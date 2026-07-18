from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import stat
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, TypeVar, cast
from uuid import UUID

from wto_desktop_agent.domain.artifact_paths import (
    ARTIFACT_PRUNE_QUARANTINE_PREFIX,
    is_artifact_prune_quarantine_path,
)
from wto_desktop_agent.domain.errors import PluginUnavailableError
from wto_desktop_agent.infrastructure.contracts import validate_contract
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.platforms.linux.secure_fs import (
    FileIdentity,
    QuarantinePlan,
    SecureFilesystemUnavailableError,
    capture_file_identity,
    logical_quarantine,
    plan_quarantine_name,
    rename_noreplace,
)
from wto_desktop_agent.ports.plugins import CancellationToken

_FCHMOD = cast(Callable[[int, int], None] | None, getattr(os, "fchmod", None))
_T = TypeVar("_T")


class DisabledArtifactUploader:
    async def upload(self, artifact_id: str, relative_path: Path) -> None:
        raise RuntimeError("artifact upload is deferred until its public server API is published")


class DisabledUpdater:
    async def check(self) -> str:
        return "disabled_phase05"


@dataclass(frozen=True)
class StagedArtifact:
    path: Path
    manifest: dict[str, object]


@dataclass(frozen=True)
class ArtifactPruneReport:
    selected: int
    files_deleted: int
    rows_deleted: int
    bytes_deleted: int
    issues: tuple[str, ...]


class ArtifactReconciliationError(RuntimeError):
    pass


class _StagingCancelled(RuntimeError):
    pass


class _ReconciliationCancelled(RuntimeError):
    pass


class _ReconciliationLimitExceeded(RuntimeError):
    pass


class _PruneEventIdentityError(RuntimeError):
    pass


@dataclass
class _ReconciliationControl:
    stop: threading.Event
    deadline: float
    maximum_entries: int
    maximum_bytes: int
    entries: int = 0
    bytes_inspected: int = 0

    def check(self) -> None:
        if self.stop.is_set():
            raise _ReconciliationCancelled("artifact reconciliation was cancelled")
        if time.monotonic() >= self.deadline:
            raise TimeoutError("artifact reconciliation deadline expired")

    def inspect_entry(self) -> None:
        self.check()
        self.entries += 1
        if self.entries > self.maximum_entries:
            raise _ReconciliationLimitExceeded("artifact reconciliation entry limit exceeded")

    def inspect_bytes(self, size: int) -> None:
        self.check()
        self.bytes_inspected += size
        if self.bytes_inspected > self.maximum_bytes:
            raise _ReconciliationLimitExceeded("artifact reconciliation byte limit exceeded")


class _StagingState(str, Enum):
    COPYING = "COPYING"
    READY_TO_COMMIT = "READY_TO_COMMIT"
    COMMITTING = "COMMITTING"
    COMMITTED = "COMMITTED"
    ABORTED = "ABORTED"


@dataclass
class _StagingTransaction:
    deadline: float
    stop: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)
    state: _StagingState = _StagingState.COPYING

    def request_cancel(self) -> bool:
        with self.lock:
            if self.state in {_StagingState.COPYING, _StagingState.READY_TO_COMMIT}:
                self.state = _StagingState.ABORTED
                self.stop.set()
                return False
            return self.state in {_StagingState.COMMITTING, _StagingState.COMMITTED}

    def check(self, cancellation: CancellationToken) -> None:
        with self.lock:
            cancelled = self.state == _StagingState.ABORTED
        if cancelled or cancellation.cancelled or self.stop.is_set():
            self.request_cancel()
            raise _StagingCancelled("artifact staging was cancelled")
        if time.monotonic() >= self.deadline:
            self.request_cancel()
            raise TimeoutError("artifact staging deadline expired")

    def ready(self, cancellation: CancellationToken) -> None:
        with self.lock:
            if self.state != _StagingState.COPYING or cancellation.cancelled or self.stop.is_set():
                self.state = _StagingState.ABORTED
                self.stop.set()
                raise _StagingCancelled("artifact staging was cancelled")
            if time.monotonic() >= self.deadline:
                self.state = _StagingState.ABORTED
                self.stop.set()
                raise TimeoutError("artifact staging deadline expired")
            self.state = _StagingState.READY_TO_COMMIT

    def begin_commit(self, cancellation: CancellationToken) -> None:
        with self.lock:
            if (
                self.state != _StagingState.READY_TO_COMMIT
                or cancellation.cancelled
                or self.stop.is_set()
            ):
                self.state = _StagingState.ABORTED
                self.stop.set()
                raise _StagingCancelled("artifact staging was cancelled")
            if time.monotonic() >= self.deadline:
                self.state = _StagingState.ABORTED
                self.stop.set()
                raise TimeoutError("artifact staging deadline expired")
            self.state = _StagingState.COMMITTING

    def committed(self) -> None:
        with self.lock:
            if self.state != _StagingState.COMMITTING:
                raise RuntimeError("artifact staging commit state is invalid")
            self.state = _StagingState.COMMITTED

    @property
    def commit_started(self) -> bool:
        with self.lock:
            return self.state in {_StagingState.COMMITTING, _StagingState.COMMITTED}

    @property
    def is_committed(self) -> bool:
        with self.lock:
            return self.state == _StagingState.COMMITTED


@dataclass(frozen=True)
class _ArtifactIntent:
    name: str
    temporary_name: str
    final_name: str
    task_id: str
    manifest: dict[str, object]
    identity: FileIdentity
    capture_authority: dict[str, object] | None = None

    @property
    def artifact_id(self) -> str:
        return str(self.manifest["artifact_id"])

    @property
    def relative_path(self) -> str:
        return f"outbox/{self.final_name}"


class _PruneStage(str, Enum):
    PREPARED = "PREPARED"
    QUARANTINED = "QUARANTINED"
    SQLITE_UPDATED = "SQLITE_UPDATED"
    MANUAL_RECOVERY_REQUIRED = "MANUAL_RECOVERY_REQUIRED"


@dataclass(frozen=True)
class _PruneOperation:
    operation_id: str
    upload_id: str
    artifact_id: str
    execution_id: str | None
    original_relative_path: str
    quarantine_relative_path: str
    directory_dev: int
    directory_ino: int
    st_dev: int
    st_ino: int
    st_uid: int
    file_type: int
    mode: int
    st_nlink: int
    size_bytes: int
    sha256: str

    @property
    def original_name(self) -> str:
        return Path(self.original_relative_path).name

    @property
    def quarantine_name(self) -> str:
        return Path(self.quarantine_relative_path).name

    def identity(self, directory_descriptor: int, relative_name: str) -> FileIdentity:
        return FileIdentity(
            dir_fd=directory_descriptor,
            directory_dev=self.directory_dev,
            directory_ino=self.directory_ino,
            relative_name=relative_name,
            st_dev=self.st_dev,
            st_ino=self.st_ino,
            st_uid=self.st_uid,
            file_type=self.file_type,
            mode=self.mode,
            st_nlink=self.st_nlink,
            st_size=self.size_bytes,
        )


@dataclass(frozen=True)
class _PruneEventCandidate:
    name: str
    operation_id: str
    stage: _PruneStage
    st_dev: int
    st_ino: int
    st_uid: int
    file_type: int
    mode: int
    st_nlink: int
    st_size: int

    def matches(self, metadata: os.stat_result) -> bool:
        return (
            self.st_dev,
            self.st_ino,
            self.st_uid,
            self.file_type,
            self.mode,
            self.st_nlink,
            self.st_size,
        ) == (
            int(metadata.st_dev),
            int(metadata.st_ino),
            int(metadata.st_uid),
            stat.S_IFMT(metadata.st_mode),
            stat.S_IMODE(metadata.st_mode),
            int(metadata.st_nlink),
            int(metadata.st_size),
        )


@dataclass(frozen=True)
class _PruneActiveCandidate:
    name: str
    operation_id: str
    st_dev: int
    st_ino: int
    st_uid: int
    file_type: int
    mode: int
    st_nlink: int
    st_size: int

    def matches(self, metadata: os.stat_result) -> bool:
        return (
            self.st_dev,
            self.st_ino,
            self.st_uid,
            self.file_type,
            self.mode,
            self.st_nlink,
            self.st_size,
        ) == (
            int(metadata.st_dev),
            int(metadata.st_ino),
            int(metadata.st_uid),
            stat.S_IFMT(metadata.st_mode),
            stat.S_IMODE(metadata.st_mode),
            int(metadata.st_nlink),
            int(metadata.st_size),
        )


@dataclass
class _OpenPruneEvent:
    candidate: _PruneEventCandidate
    descriptor: int
    identity: FileIdentity
    operation: _PruneOperation
    stage: _PruneStage
    closed: bool = False


@dataclass
class _OpenPruneActive:
    candidate: _PruneActiveCandidate
    descriptor: int
    identity: FileIdentity
    operation: _PruneOperation
    event_names: dict[_PruneStage, str]
    closed: bool = False


@dataclass(frozen=True)
class _PruneReconciliationResult:
    processed_operations: int
    has_more: bool


class SQLiteArtifactStager:
    """Stages immutable local objects and reconciles filesystem/SQLite commits.

    Cancellation before ``COMMITTING`` aborts and moves each active private
    temporary name to logical quarantine. Once ``COMMITTING`` is claimed, the
    durable intent wins the race: publication and SQLite insertion complete
    (or remain recoverable),
    and the caller receives a confirmed result instead of an ambiguous cancel.
    """

    _chunk_size = 1_048_576
    _maximum_intent_bytes = 1_048_576
    _maximum_prune_event_bytes = 65_536
    _maximum_prune_active_bytes = 65_536
    _directory_mode = 0o700
    _temporary_mode = 0o600
    _final_mode = 0o400
    _reparse_point = 0x400
    _stable_identity_fields = (
        "schema_version",
        "artifact_id",
        "execution_id",
        "artifact_type",
        "media_type",
        "idempotency_key",
    )
    _prune_operation_fields = frozenset(
        {
            "operation_id",
            "upload_id",
            "artifact_id",
            "execution_id",
            "original_relative_path",
            "quarantine_relative_path",
            "directory_dev",
            "directory_ino",
            "st_dev",
            "st_ino",
            "st_uid",
            "file_type",
            "mode",
            "st_nlink",
            "size_bytes",
            "sha256",
        }
    )
    _outbox_quarantine_prefixes = (
        ".artifact-cleanup-quarantine-",
        ".artifact-orphan-quarantine-",
        ".artifact-reconcile-quarantine-",
    )
    _intent_quarantine_prefixes = (".artifact-intent-quarantine-",)
    _prune_event_pattern = re.compile(
        r"^prune-(?P<operation>[0-9a-f]{32})-"
        r"(?P<stage>prepared|quarantined|sqlite_updated|manual_recovery_required)-"
        r"(?P<nonce>[0-9a-f]{32})\.json$"
    )
    _prune_active_pattern = re.compile(r"^active-(?P<operation>[0-9a-f]{32})\.json$")
    _prune_retired_pattern = re.compile(r"^retired-(?P<operation>[0-9a-f]{32})\.json$")
    _prune_conflict_pattern = re.compile(
        r"^conflict-(?P<operation>[0-9a-f]{32})-(?P<nonce>[0-9a-f]{64})\.json$"
    )

    def __init__(
        self,
        store: SQLiteStore,
        artifact_root: Path,
        *,
        trusted_root: Path | None = None,
        staging_timeout_seconds: float = 300.0,
        reconciliation_timeout_seconds: float = 30.0,
        reconciliation_cleanup_timeout_seconds: float = 5.0,
        reconciliation_maximum_entries: int = 10_000,
        reconciliation_maximum_bytes: int = 4 * 1024 * 1024 * 1024,
    ) -> None:
        if staging_timeout_seconds <= 0:
            raise ValueError("artifact staging timeout must be positive")
        if reconciliation_timeout_seconds <= 0 or reconciliation_cleanup_timeout_seconds <= 0:
            raise ValueError("artifact reconciliation timeouts must be positive")
        if reconciliation_maximum_entries <= 0 or reconciliation_maximum_bytes <= 0:
            raise ValueError("artifact reconciliation limits must be positive")
        if os.name != "posix":
            raise RuntimeError("descriptor-anchored artifact staging requires POSIX")
        if _FCHMOD is None:
            raise RuntimeError("descriptor-anchored mode changes are unavailable")
        if not artifact_root.is_absolute() or (
            trusted_root is not None and not trusted_root.is_absolute()
        ):
            raise ValueError("artifact roots must be absolute")
        artifact_root = artifact_root.absolute()
        trusted_root = (trusted_root or artifact_root.parent).absolute()
        try:
            relative = artifact_root.relative_to(trusted_root)
        except ValueError as error:
            raise ValueError("artifact root must be below the trusted artifact root") from error
        if any(part in {"", ".", ".."} for part in relative.parts):
            raise ValueError("artifact root contains an unsafe component")

        self.store = store
        self.trusted_root = trusted_root
        self.artifact_root = artifact_root
        self.outbox_root = artifact_root / "outbox"
        self.intent_root = self.outbox_root / "intents"
        self.prune_intent_root = self.outbox_root / "prune-intents"
        self.prune_active_root = self.outbox_root / "prune-active"
        self.prune_retired_root = self.outbox_root / "prune-retired"
        self.prune_conflicts_root = self.outbox_root / "prune-conflicts"
        self.staging_timeout_seconds = staging_timeout_seconds
        self.reconciliation_timeout_seconds = reconciliation_timeout_seconds
        self.reconciliation_cleanup_timeout_seconds = reconciliation_cleanup_timeout_seconds
        self.reconciliation_maximum_entries = reconciliation_maximum_entries
        self.reconciliation_maximum_bytes = reconciliation_maximum_bytes
        self._stage_lock = asyncio.Lock()
        self._unfinished_workers: set[asyncio.Task[Any]] = set()
        self._poison_reason: str | None = None
        self._maintenance_issues: list[str] = []
        self._managed_components: tuple[tuple[str, tuple[int, int]], ...]

        trusted_descriptor = self._open_trusted_root(trusted_root)
        trusted_error: BaseException | None = None
        try:
            self._trusted_root_identity = self._identity(os.fstat(trusted_descriptor))
            artifact_descriptor, components = self._ensure_managed_path(
                trusted_descriptor,
                relative.parts,
            )
            artifact_error: BaseException | None = None
            try:
                outbox_descriptor = self._ensure_private_child(artifact_descriptor, "outbox")
                outbox_error: BaseException | None = None
                try:
                    intent_descriptor = self._ensure_private_child(outbox_descriptor, "intents")
                    intent_error: BaseException | None = None
                    try:
                        self._intent_root_identity = self._identity(os.fstat(intent_descriptor))
                    except BaseException as error:
                        intent_error = error
                        raise
                    finally:
                        self._close_descriptors((intent_descriptor,), primary_error=intent_error)
                    self._outbox_root_identity = self._identity(os.fstat(outbox_descriptor))
                except BaseException as error:
                    outbox_error = error
                    raise
                finally:
                    self._close_descriptors((outbox_descriptor,), primary_error=outbox_error)
                self._artifact_root_identity = self._identity(os.fstat(artifact_descriptor))
            except BaseException as error:
                artifact_error = error
                raise
            finally:
                self._close_descriptors((artifact_descriptor,), primary_error=artifact_error)
            self._managed_components = tuple(components)
        except BaseException as error:
            trusted_error = error
            raise
        finally:
            self._close_descriptors((trusted_descriptor,), primary_error=trusted_error)
        descriptors = self._open_managed_tree()
        prune_descriptor: int | None = None
        active_descriptor: int | None = None
        retired_descriptor: int | None = None
        conflicts_descriptor: int | None = None
        prune_error: BaseException | None = None
        try:
            prune_descriptor = self._ensure_private_child(
                descriptors[2],
                "prune-intents",
            )
            self._prune_intent_root_identity = self._identity(os.fstat(prune_descriptor))
            active_descriptor = self._ensure_private_child(
                descriptors[2],
                "prune-active",
            )
            self._prune_active_root_identity = self._identity(os.fstat(active_descriptor))
            retired_descriptor = self._ensure_private_child(
                descriptors[2],
                "prune-retired",
            )
            self._prune_retired_root_identity = self._identity(os.fstat(retired_descriptor))
            conflicts_descriptor = self._ensure_private_child(
                descriptors[2],
                "prune-conflicts",
            )
            self._prune_conflicts_root_identity = self._identity(os.fstat(conflicts_descriptor))
            prune_devices = {
                int(os.fstat(descriptor).st_dev)
                for descriptor in (active_descriptor, retired_descriptor, conflicts_descriptor)
            }
            if len(prune_devices) != 1:
                raise RuntimeError("artifact prune directories must share a filesystem")
            os.fsync(descriptors[2])
        except BaseException as error:
            prune_error = error
            raise
        finally:
            self._close_descriptors(
                (
                    prune_descriptor,
                    active_descriptor,
                    retired_descriptor,
                    conflicts_descriptor,
                    *reversed(descriptors),
                ),
                primary_error=prune_error,
            )
        self._reconcile_startup_sync(self._new_reconciliation_control())

    async def find_existing(
        self,
        identity: dict[str, object],
        task_id: UUID,
        *,
        cancellation: CancellationToken,
    ) -> StagedArtifact | None:
        async with self._stage_lock:
            self._ensure_available()
            deadline = time.monotonic() + self.reconciliation_timeout_seconds
            return await self._preflight_existing(
                dict(identity), str(task_id), cancellation, deadline
            )

    async def stage(
        self,
        manifest: dict[str, object],
        path: Path,
        task_id: UUID,
        *,
        maximum_size_bytes: int,
        cancellation: CancellationToken,
    ) -> StagedArtifact:
        if maximum_size_bytes <= 0:
            raise ValueError("artifact size limit must be positive")
        async with self._stage_lock:
            self._ensure_available()
            return await self._stage_exclusive(
                manifest,
                path,
                task_id,
                source_descriptor=None,
                expected_source_identity=None,
                maximum_size_bytes=maximum_size_bytes,
                cancellation=cancellation,
            )

    async def stage_from_descriptor(
        self,
        manifest: dict[str, object],
        descriptor: int,
        expected_identity: FileIdentity,
        task_id: UUID,
        *,
        maximum_size_bytes: int,
        cancellation: CancellationToken,
        capture_authority: dict[str, object] | None = None,
        intent_durable_callback: Callable[[dict[str, object]], None] | None = None,
    ) -> StagedArtifact:
        """Stage bytes from a stable caller-owned inode without reopening a path."""

        if maximum_size_bytes <= 0:
            raise ValueError("artifact size limit must be positive")
        duplicate = os.dup(descriptor)
        handed_off = False
        try:
            async with self._stage_lock:
                self._ensure_available()
                handed_off = True
                return await self._stage_exclusive(
                    manifest,
                    None,
                    task_id,
                    source_descriptor=duplicate,
                    expected_source_identity=expected_identity,
                    maximum_size_bytes=maximum_size_bytes,
                    cancellation=cancellation,
                    capture_authority=capture_authority,
                    intent_durable_callback=intent_durable_callback,
                )
        finally:
            if not handed_off:
                self._close_descriptors((duplicate,))

    async def _stage_exclusive(
        self,
        manifest: dict[str, object],
        path: Path | None,
        task_id: UUID,
        *,
        source_descriptor: int | None,
        expected_source_identity: FileIdentity | None,
        maximum_size_bytes: int,
        cancellation: CancellationToken,
        capture_authority: dict[str, object] | None = None,
        intent_durable_callback: Callable[[dict[str, object]], None] | None = None,
    ) -> StagedArtifact:
        supplied_manifest = dict(manifest)
        operation_deadline = time.monotonic() + self.staging_timeout_seconds
        reconciliation_deadline = min(
            operation_deadline,
            time.monotonic() + self.reconciliation_timeout_seconds,
        )
        try:
            existing = await self._preflight_existing(
                supplied_manifest,
                str(task_id),
                cancellation,
                reconciliation_deadline,
            )
        except BaseException as error:
            if source_descriptor is not None:
                self._close_descriptors((source_descriptor,), primary_error=error)
            raise
        if existing is not None:
            if source_descriptor is not None:
                self._close_descriptors((source_descriptor,))
            return existing
        transaction = _StagingTransaction(deadline=operation_deadline)
        try:
            worker = self._track_worker(
                asyncio.create_task(
                    asyncio.to_thread(
                        self._stage_sync,
                        supplied_manifest,
                        path,
                        task_id,
                        maximum_size_bytes,
                        cancellation,
                        transaction,
                        source_descriptor,
                        expected_source_identity,
                        capture_authority,
                        intent_durable_callback,
                    )
                )
            )
        except BaseException as error:
            if source_descriptor is not None:
                self._close_descriptors((source_descriptor,), primary_error=error)
            raise
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError as cancelled:
            commit_started = transaction.request_cancel()
            try:
                result = await self._wait_worker_after_cancel(worker)
            except _StagingCancelled:
                raise cancelled from None
            except BaseException as error:
                if commit_started and worker.done():
                    recovery_stop = threading.Event()
                    recovery = self._track_worker(
                        asyncio.create_task(
                            asyncio.to_thread(
                                self._reconcile_and_find_existing,
                                supplied_manifest,
                                str(task_id),
                                recovery_stop,
                                time.monotonic() + self.reconciliation_timeout_seconds,
                            )
                        )
                    )
                    try:
                        recovered = await self._wait_worker_after_cancel(recovery)
                    except BaseException as recovery_error:
                        error.add_note(
                            "artifact commit reconciliation also failed: " f"{recovery_error!r}"
                        )
                    else:
                        if recovered is not None:
                            if not transaction.is_committed:
                                transaction.committed()
                            return recovered
                cancelled.add_note(f"artifact staging cleanup incomplete: {error!r}")
                raise cancelled from error
            if commit_started and transaction.is_committed:
                return result
            raise cancelled
        except _StagingCancelled:
            raise asyncio.CancelledError from None

    async def _preflight_existing(
        self,
        supplied_manifest: dict[str, object],
        task_id: str,
        cancellation: CancellationToken,
        deadline: float,
    ) -> StagedArtifact | None:
        if cancellation.cancelled:
            raise asyncio.CancelledError
        reconciliation_stop = threading.Event()
        preflight = self._track_worker(
            asyncio.create_task(
                asyncio.to_thread(
                    self._reconcile_and_find_existing,
                    supplied_manifest,
                    task_id,
                    reconciliation_stop,
                    deadline,
                )
            )
        )
        cancellation_wait = asyncio.create_task(cancellation.wait())
        cancellation_wait.add_done_callback(self._consume_future_result)
        try:
            remaining = max(0.0, deadline - time.monotonic())
            done, _ = await asyncio.wait(
                {preflight, cancellation_wait},
                timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                reconciliation_stop.set()
                try:
                    await self._wait_worker_after_cancel(preflight)
                except _ReconciliationCancelled:
                    pass
                except TimeoutError as cleanup_error:
                    self._poison(
                        "artifact reconciliation worker did not stop within its grace period"
                    )
                    timeout = ArtifactReconciliationError(
                        "artifact reconciliation timed out and the stager is unavailable"
                    )
                    timeout.add_note(f"worker grace timeout: {cleanup_error!r}")
                    raise timeout from cleanup_error
                except BaseException as cleanup_error:
                    timeout = ArtifactReconciliationError(
                        "artifact reconciliation external timeout"
                    )
                    timeout.add_note(f"worker cleanup failed: {cleanup_error!r}")
                    raise timeout from cleanup_error
                deadline_error = TimeoutError("artifact reconciliation deadline expired")
                raise ArtifactReconciliationError(
                    "artifact reconciliation external timeout"
                ) from deadline_error
            if cancellation_wait in done:
                reconciliation_stop.set()
                try:
                    await self._wait_worker_after_cancel(preflight)
                except _ReconciliationCancelled:
                    pass
                except BaseException as cleanup_error:
                    if isinstance(cleanup_error, TimeoutError):
                        self._poison(
                            "artifact reconciliation worker did not stop within its grace period"
                        )
                    cancelled = asyncio.CancelledError()
                    cancelled.add_note(
                        "artifact reconciliation cleanup incomplete: " f"{cleanup_error!r}"
                    )
                    raise cancelled from cleanup_error
                raise asyncio.CancelledError
            try:
                existing = preflight.result()
            except TimeoutError as deadline_error:
                raise ArtifactReconciliationError(
                    "artifact reconciliation deadline expired"
                ) from deadline_error
        except asyncio.CancelledError as cancelled:
            reconciliation_stop.set()
            if not preflight.done() and self._poison_reason is None:
                try:
                    await self._wait_worker_after_cancel(preflight)
                except _ReconciliationCancelled:
                    pass
                except BaseException as cleanup_error:
                    if isinstance(cleanup_error, TimeoutError):
                        self._poison(
                            "artifact reconciliation worker did not stop within its grace period"
                        )
                    cancelled.add_note(
                        f"artifact reconciliation cleanup incomplete: {cleanup_error!r}"
                    )
            raise cancelled
        finally:
            if not cancellation_wait.done():
                cancellation_wait.cancel()
        return existing

    def _ensure_available(self) -> None:
        if self._poison_reason is not None:
            raise ArtifactReconciliationError(self._poison_reason)
        if any(not worker.done() for worker in self._unfinished_workers):
            raise ArtifactReconciliationError(
                "artifact staging is blocked by incomplete background cleanup"
            )

    def _poison(self, reason: str) -> None:
        self._poison_reason = reason

    @property
    def maintenance_issues(self) -> tuple[str, ...]:
        return tuple(self._maintenance_issues)

    def _record_quarantine(self, name: str, context: str) -> None:
        issue = f"{context}:physical_delete_pending:{name}"
        if issue not in self._maintenance_issues:
            self._maintenance_issues.append(issue)

    def _record_maintenance_issue(self, issue: str) -> None:
        if issue not in self._maintenance_issues:
            self._maintenance_issues.append(issue)

    @staticmethod
    def _has_prefix(name: str, prefixes: tuple[str, ...]) -> bool:
        return any(name.startswith(prefix) for prefix in prefixes)

    @staticmethod
    def _is_safe_outbox_relative(value: str) -> bool:
        if "\x00" in value:
            return False
        relative = Path(value)
        return (
            not relative.is_absolute()
            and len(relative.parts) == 2
            and relative.parts[0] == "outbox"
            and relative.parts[1] not in {"", ".", ".."}
            and relative.as_posix() == value
        )

    @staticmethod
    def _prune_operation_payload(operation: _PruneOperation) -> dict[str, object]:
        return {
            "operation_id": operation.operation_id,
            "upload_id": operation.upload_id,
            "artifact_id": operation.artifact_id,
            "execution_id": operation.execution_id,
            "original_relative_path": operation.original_relative_path,
            "quarantine_relative_path": operation.quarantine_relative_path,
            "directory_dev": operation.directory_dev,
            "directory_ino": operation.directory_ino,
            "st_dev": operation.st_dev,
            "st_ino": operation.st_ino,
            "st_uid": operation.st_uid,
            "file_type": operation.file_type,
            "mode": operation.mode,
            "st_nlink": operation.st_nlink,
            "size_bytes": operation.size_bytes,
            "sha256": operation.sha256,
        }

    @classmethod
    def _prune_event_payload(
        cls,
        operation: _PruneOperation,
        stage: _PruneStage,
    ) -> dict[str, object]:
        return {
            "version": 1,
            **cls._prune_operation_payload(operation),
            "stage": stage.value,
            "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }

    @classmethod
    def _planned_prune_event_names(
        cls,
        operation: _PruneOperation,
    ) -> dict[_PruneStage, str]:
        return {
            stage: (
                f"prune-{operation.operation_id}-{stage.value.lower()}-"
                f"{secrets.token_hex(16)}.json"
            )
            for stage in _PruneStage
        }

    @classmethod
    def _prune_active_payload(
        cls,
        operation: _PruneOperation,
        event_names: dict[_PruneStage, str],
    ) -> dict[str, object]:
        return {
            "version": 1,
            **cls._prune_operation_payload(operation),
            "event_names": {stage.value: event_names[stage] for stage in _PruneStage},
            "state": "ACTIVE",
            "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }

    @staticmethod
    def _prune_operation_from_payload(payload: dict[str, object]) -> _PruneOperation:
        def integer(field_name: str) -> int:
            value = payload[field_name]
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"artifact prune {field_name} must be an integer")
            return value

        return _PruneOperation(
            operation_id=str(payload["operation_id"]),
            upload_id=str(payload["upload_id"]),
            artifact_id=str(payload["artifact_id"]),
            execution_id=(
                None if payload["execution_id"] is None else str(payload["execution_id"])
            ),
            original_relative_path=str(payload["original_relative_path"]),
            quarantine_relative_path=str(payload["quarantine_relative_path"]),
            directory_dev=integer("directory_dev"),
            directory_ino=integer("directory_ino"),
            st_dev=integer("st_dev"),
            st_ino=integer("st_ino"),
            st_uid=integer("st_uid"),
            file_type=integer("file_type"),
            mode=integer("mode"),
            st_nlink=integer("st_nlink"),
            size_bytes=integer("size_bytes"),
            sha256=str(payload["sha256"]),
        )

    def _create_prune_active(
        self,
        active_descriptor: int,
        operation: _PruneOperation,
        *,
        control: _ReconciliationControl | None = None,
    ) -> _OpenPruneActive:
        if control is not None:
            control.check()
        name = f"active-{operation.operation_id}.json"
        event_names = self._planned_prune_event_names(operation)
        payload = self._prune_active_payload(operation, event_names)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > self._maximum_prune_active_bytes:
            raise RuntimeError("artifact prune active record is too large")
        descriptor = os.open(
            name,
            (self._write_flags() & ~os.O_WRONLY) | os.O_RDWR,
            self._temporary_mode,
            dir_fd=active_descriptor,
        )
        primary_error: BaseException | None = None
        try:
            self._write_all(descriptor, encoded)
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            self._validate_private_file(metadata, self._temporary_mode)
            if int(metadata.st_size) != len(encoded):
                raise RuntimeError("artifact prune active record size changed")
            identity = capture_file_identity(
                active_descriptor,
                name,
                descriptor,
                expected_uid=self._effective_uid(metadata),
                expected_mode=self._temporary_mode,
            )
            os.lseek(descriptor, 0, os.SEEK_SET)
            readback = self._read_exact_file(descriptor, len(encoded))
            if not secrets.compare_digest(readback, encoded) or os.read(descriptor, 1):
                raise RuntimeError("artifact prune active record readback did not match")
            os.fsync(active_descriptor)
            candidate = _PruneActiveCandidate(
                name=name,
                operation_id=operation.operation_id,
                st_dev=int(metadata.st_dev),
                st_ino=int(metadata.st_ino),
                st_uid=int(metadata.st_uid),
                file_type=stat.S_IFMT(metadata.st_mode),
                mode=stat.S_IMODE(metadata.st_mode),
                st_nlink=int(metadata.st_nlink),
                st_size=int(metadata.st_size),
            )
            opened = _OpenPruneActive(
                candidate,
                descriptor,
                identity,
                operation,
                event_names,
            )
            self._validate_open_prune_active(opened)
            return opened
        except BaseException as error:
            primary_error = error
            self._close_descriptors((descriptor,), primary_error=primary_error)
            raise

    def _validate_open_prune_active(self, active: _OpenPruneActive) -> None:
        if active.closed:
            raise _PruneEventIdentityError("artifact prune active descriptor is closed")
        try:
            metadata = os.fstat(active.descriptor)
            self._validate_private_file(metadata, self._temporary_mode)
        except BaseException as error:
            raise _PruneEventIdentityError(
                "artifact prune active descriptor validation failed"
            ) from error
        if not active.candidate.matches(metadata) or not active.identity.matches_with_size(
            metadata
        ):
            raise _PruneEventIdentityError("artifact prune active descriptor identity changed")
        try:
            current = capture_file_identity(
                active.identity.dir_fd,
                active.candidate.name,
                active.descriptor,
                expected_uid=active.identity.st_uid,
                expected_mode=active.identity.mode,
            )
        except BaseException as error:
            raise _PruneEventIdentityError(
                "artifact prune active name validation failed"
            ) from error
        if current != active.identity:
            raise _PruneEventIdentityError(
                "artifact prune active name no longer matches its descriptor"
            )

    def _close_prune_active(
        self,
        active: _OpenPruneActive | None,
        *,
        primary_error: BaseException | None = None,
    ) -> None:
        if active is None or active.closed:
            return
        active.closed = True
        self._close_descriptors((active.descriptor,), primary_error=primary_error)

    @staticmethod
    def _mark_retirement_durability_indeterminate(error: BaseException) -> BaseException:
        error.add_note("retirement_durability_indeterminate")
        return error

    @staticmethod
    def _is_retirement_durability_indeterminate(error: BaseException) -> bool:
        return "retirement_durability_indeterminate" in getattr(error, "__notes__", ())

    def _move_prune_active_record(
        self,
        active: _OpenPruneActive,
        source_descriptor: int,
        destination_descriptor: int,
        destination_name: str,
        *,
        event_guard: Callable[[], None],
    ) -> None:
        event_guard()
        if active.identity.dir_fd != source_descriptor:
            raise _PruneEventIdentityError("artifact prune active directory changed")
        source_metadata = os.fstat(source_descriptor)
        destination_metadata = os.fstat(destination_descriptor)
        self._validate_directory_metadata(source_metadata)
        self._validate_directory_metadata(destination_metadata)
        if int(source_metadata.st_dev) != int(destination_metadata.st_dev):
            raise RuntimeError("artifact prune terminalization requires one filesystem")

        renamed = False
        opened_destination = -1
        primary_error: BaseException | None = None
        try:
            rename_noreplace(
                source_descriptor,
                active.candidate.name,
                destination_descriptor,
                destination_name,
            )
            renamed = True
            try:
                if self._entry_exists(source_descriptor, active.candidate.name):
                    raise _PruneEventIdentityError(
                        "artifact prune active name remained after terminalization"
                    )
                opened_destination = os.open(
                    destination_name,
                    self._read_flags(),
                    dir_fd=destination_descriptor,
                )
                destination_file_metadata = os.fstat(opened_destination)
                self._validate_private_file(destination_file_metadata, self._temporary_mode)
                destination_identity = capture_file_identity(
                    destination_descriptor,
                    destination_name,
                    opened_destination,
                    expected_uid=active.identity.st_uid,
                    expected_mode=self._temporary_mode,
                )
                if (
                    destination_identity.st_dev,
                    destination_identity.st_ino,
                    destination_identity.st_uid,
                    destination_identity.file_type,
                    destination_identity.mode,
                    destination_identity.st_nlink,
                    destination_identity.st_size,
                ) != (
                    active.identity.st_dev,
                    active.identity.st_ino,
                    active.identity.st_uid,
                    active.identity.file_type,
                    active.identity.mode,
                    active.identity.st_nlink,
                    active.identity.st_size,
                ):
                    raise _PruneEventIdentityError(
                        "artifact prune terminal identity does not match active record"
                    )
                retained_metadata = os.fstat(active.descriptor)
                if not active.identity.matches_with_size(retained_metadata):
                    raise _PruneEventIdentityError(
                        "artifact prune retained descriptor identity changed"
                    )
            except BaseException as error:
                primary_error = error
        finally:
            if renamed:
                for label, descriptor in (
                    ("source", source_descriptor),
                    ("destination", destination_descriptor),
                ):
                    try:
                        os.fsync(descriptor)
                    except BaseException as sync_error:
                        if primary_error is None:
                            primary_error = sync_error
                        else:
                            primary_error.add_note(
                                f"artifact prune {label} directory fsync also failed: "
                                f"{sync_error!r}"
                            )
                if opened_destination >= 0:
                    try:
                        self._close_descriptor(opened_destination)
                    except BaseException as close_error:
                        if primary_error is None:
                            primary_error = close_error
                        else:
                            primary_error.add_note(
                                "artifact prune destination descriptor close also failed: "
                                f"{close_error!r}"
                            )
            elif opened_destination >= 0:
                self._close_descriptors((opened_destination,), primary_error=primary_error)
        if primary_error is not None:
            raise self._mark_retirement_durability_indeterminate(primary_error)

    def _retire_prune_active(
        self,
        active: _OpenPruneActive,
        active_descriptor: int,
        retired_descriptor: int,
        *,
        event_guard: Callable[[], None],
    ) -> None:
        retired_name = f"retired-{active.operation.operation_id}.json"
        match = self._prune_retired_pattern.fullmatch(retired_name)
        if match is None or match.group("operation") != active.operation.operation_id:
            raise RuntimeError("artifact prune retired name is invalid")
        self._move_prune_active_record(
            active,
            active_descriptor,
            retired_descriptor,
            retired_name,
            event_guard=event_guard,
        )
        self._record_quarantine(retired_name, "prune_active")

    def _move_prune_active_to_conflict(
        self,
        active: _OpenPruneActive,
        active_descriptor: int,
        conflicts_descriptor: int,
        *,
        event_guard: Callable[[], None],
    ) -> str:
        for _attempt in range(32):
            conflict_name = f"conflict-{active.operation.operation_id}-{secrets.token_hex(32)}.json"
            match = self._prune_conflict_pattern.fullmatch(conflict_name)
            if match is None or match.group("operation") != active.operation.operation_id:
                raise RuntimeError("artifact prune conflict name is invalid")
            try:
                self._move_prune_active_record(
                    active,
                    active_descriptor,
                    conflicts_descriptor,
                    conflict_name,
                    event_guard=event_guard,
                )
            except FileExistsError:
                continue
            self._record_quarantine(conflict_name, "prune_active_conflict")
            return conflict_name
        raise RuntimeError("artifact prune conflict name allocation was exhausted")

    def _write_prune_event(
        self,
        prune_descriptor: int,
        operation: _PruneOperation,
        stage: _PruneStage,
        *,
        name: str | None = None,
        control: _ReconciliationControl | None = None,
    ) -> str:
        if control is not None:
            control.check()
        name = name or (
            f"prune-{operation.operation_id}-{stage.value.lower()}-" f"{secrets.token_hex(16)}.json"
        )
        match = self._prune_event_pattern.fullmatch(name)
        if (
            match is None
            or match.group("operation") != operation.operation_id
            or match.group("stage") != stage.value.lower()
        ):
            raise ValueError("artifact prune event name does not match its operation")
        payload = self._prune_event_payload(operation, stage)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > self._maximum_prune_event_bytes:
            raise RuntimeError("artifact prune event is too large")
        descriptor = os.open(
            name,
            self._write_flags(),
            self._temporary_mode,
            dir_fd=prune_descriptor,
        )
        primary_error: BaseException | None = None
        try:
            self._write_all(descriptor, encoded)
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            self._validate_private_file(metadata, self._temporary_mode)
            if int(metadata.st_size) != len(encoded):
                raise RuntimeError("artifact prune event size changed")
            capture_file_identity(
                prune_descriptor,
                name,
                descriptor,
                expected_uid=self._effective_uid(metadata),
                expected_mode=self._temporary_mode,
            )
        except BaseException as error:
            primary_error = error
            raise
        finally:
            self._close_descriptors((descriptor,), primary_error=primary_error)
        os.fsync(prune_descriptor)
        self._record_maintenance_issue(f"prune_journal:append_only:{name}")
        return name

    def _read_prune_event(
        self,
        prune_descriptor: int,
        candidate: _PruneEventCandidate,
        control: _ReconciliationControl,
    ) -> _OpenPruneEvent:
        match = self._prune_event_pattern.fullmatch(candidate.name)
        if match is None:
            raise ValueError("artifact prune event name is invalid")
        self._before_prune_event_open(candidate)
        descriptor = os.open(candidate.name, self._read_flags(), dir_fd=prune_descriptor)
        primary_error: BaseException | None = None
        try:
            metadata = os.fstat(descriptor)
            self._validate_private_file(metadata, self._temporary_mode)
            if not candidate.matches(metadata):
                raise RuntimeError("artifact prune event changed between discovery and open")
            identity = capture_file_identity(
                prune_descriptor,
                candidate.name,
                descriptor,
                expected_uid=self._effective_uid(metadata),
                expected_mode=self._temporary_mode,
            )
            if not identity.matches_with_size(metadata):
                raise RuntimeError("artifact prune event identity changed during open")
            self._after_prune_event_open(candidate, descriptor)
            if metadata.st_size <= 0 or metadata.st_size > self._maximum_prune_event_bytes:
                raise ValueError("artifact prune event size is invalid")
            control.inspect_bytes(int(metadata.st_size))
            encoded = self._read_exact_file(descriptor, int(metadata.st_size))
            if os.read(descriptor, 1):
                raise ValueError("artifact prune event grew during validation")
            payload = json.loads(encoded.decode("utf-8"))
            expected_fields = {
                "version",
                "operation_id",
                "upload_id",
                "artifact_id",
                "execution_id",
                "original_relative_path",
                "quarantine_relative_path",
                "directory_dev",
                "directory_ino",
                "st_dev",
                "st_ino",
                "st_uid",
                "file_type",
                "mode",
                "st_nlink",
                "size_bytes",
                "sha256",
                "stage",
                "recorded_at",
            }
            if not isinstance(payload, dict) or set(payload) != expected_fields:
                raise ValueError("artifact prune event fields are invalid")
            recorded_at = payload["recorded_at"]
            if not isinstance(recorded_at, str) or not recorded_at.endswith("Z"):
                raise ValueError("artifact prune event timestamp is invalid")
            try:
                datetime.fromisoformat(recorded_at.removesuffix("Z") + "+00:00")
            except ValueError as error:
                raise ValueError("artifact prune event timestamp is invalid") from error
            stage = _PruneStage(str(payload["stage"]))
            if (
                payload["version"] != 1
                or payload["operation_id"] != match.group("operation")
                or stage.value.lower() != match.group("stage")
                or candidate.operation_id != match.group("operation")
                or candidate.stage is not stage
            ):
                raise ValueError("artifact prune event identity is inconsistent")
            operation = self._prune_operation_from_payload(payload)
            self._validate_prune_operation(operation)
            return _OpenPruneEvent(candidate, descriptor, identity, operation, stage)
        except BaseException as error:
            primary_error = error
            self._close_descriptors((descriptor,), primary_error=primary_error)
            raise

    def _read_prune_active(
        self,
        active_descriptor: int,
        candidate: _PruneActiveCandidate,
        control: _ReconciliationControl,
    ) -> _OpenPruneActive:
        match = self._prune_active_pattern.fullmatch(candidate.name)
        if match is None or match.group("operation") != candidate.operation_id:
            raise ValueError("artifact prune active name is invalid")
        self._before_prune_active_open(candidate)
        descriptor = os.open(candidate.name, self._read_flags(), dir_fd=active_descriptor)
        primary_error: BaseException | None = None
        try:
            metadata = os.fstat(descriptor)
            self._validate_private_file(metadata, self._temporary_mode)
            if not candidate.matches(metadata):
                raise RuntimeError("artifact prune active changed between discovery and open")
            identity = capture_file_identity(
                active_descriptor,
                candidate.name,
                descriptor,
                expected_uid=self._effective_uid(metadata),
                expected_mode=self._temporary_mode,
            )
            if not identity.matches_with_size(metadata):
                raise RuntimeError("artifact prune active identity changed during open")
            self._after_prune_active_open(candidate, descriptor)
            if metadata.st_size <= 0 or metadata.st_size > self._maximum_prune_active_bytes:
                raise ValueError("artifact prune active size is invalid")
            control.inspect_bytes(int(metadata.st_size))
            encoded = self._read_exact_file(descriptor, int(metadata.st_size))
            if os.read(descriptor, 1):
                raise ValueError("artifact prune active grew during validation")
            payload = json.loads(encoded.decode("utf-8"))
            expected_fields = self._prune_operation_fields | {
                "version",
                "event_names",
                "state",
                "recorded_at",
            }
            if not isinstance(payload, dict) or set(payload) != expected_fields:
                raise ValueError("artifact prune active fields are invalid")
            recorded_at = payload["recorded_at"]
            if not isinstance(recorded_at, str) or not recorded_at.endswith("Z"):
                raise ValueError("artifact prune active timestamp is invalid")
            datetime.fromisoformat(recorded_at.removesuffix("Z") + "+00:00")
            if payload["version"] != 1 or payload["state"] != "ACTIVE":
                raise ValueError("artifact prune active state is invalid")
            operation = self._prune_operation_from_payload(payload)
            self._validate_prune_operation(operation)
            if operation.operation_id != candidate.operation_id:
                raise ValueError("artifact prune active operation is inconsistent")
            raw_event_names = payload["event_names"]
            if not isinstance(raw_event_names, dict) or set(raw_event_names) != {
                stage.value for stage in _PruneStage
            }:
                raise ValueError("artifact prune active event names are invalid")
            event_names: dict[_PruneStage, str] = {}
            for stage in _PruneStage:
                event_name = raw_event_names[stage.value]
                if not isinstance(event_name, str):
                    raise ValueError("artifact prune active event name is invalid")
                event_match = self._prune_event_pattern.fullmatch(event_name)
                if (
                    event_match is None
                    or event_match.group("operation") != operation.operation_id
                    or event_match.group("stage") != stage.value.lower()
                ):
                    raise ValueError("artifact prune active event name is inconsistent")
                event_names[stage] = event_name
            if len(set(event_names.values())) != len(event_names):
                raise ValueError("artifact prune active event names are ambiguous")
            opened = _OpenPruneActive(
                candidate,
                descriptor,
                identity,
                operation,
                event_names,
            )
            self._after_prune_active_parsed(opened)
            self._validate_open_prune_active(opened)
            return opened
        except BaseException as error:
            primary_error = error
            self._close_descriptors((descriptor,), primary_error=primary_error)
            raise

    def _prune_event_candidate(
        self,
        prune_descriptor: int,
        *,
        name: str,
        operation_id: str,
        stage: _PruneStage,
    ) -> _PruneEventCandidate | None:
        match = self._prune_event_pattern.fullmatch(name)
        if (
            match is None
            or match.group("operation") != operation_id
            or match.group("stage") != stage.value.lower()
        ):
            raise ValueError("artifact prune planned event name is invalid")
        try:
            metadata = os.stat(name, dir_fd=prune_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return None
        return _PruneEventCandidate(
            name=name,
            operation_id=operation_id,
            stage=stage,
            st_dev=int(metadata.st_dev),
            st_ino=int(metadata.st_ino),
            st_uid=int(metadata.st_uid),
            file_type=stat.S_IFMT(metadata.st_mode),
            mode=stat.S_IMODE(metadata.st_mode),
            st_nlink=int(metadata.st_nlink),
            st_size=int(metadata.st_size),
        )

    def _open_planned_prune_event(
        self,
        control: _ReconciliationControl,
        prune_descriptor: int,
        active: _OpenPruneActive,
        stage: _PruneStage,
    ) -> _OpenPruneEvent | None:
        candidate = self._prune_event_candidate(
            prune_descriptor,
            name=active.event_names[stage],
            operation_id=active.operation.operation_id,
            stage=stage,
        )
        if candidate is None:
            return None
        opened = self._read_prune_event(prune_descriptor, candidate, control)
        if opened.operation != active.operation:
            self._close_prune_events([opened])
            raise ValueError("artifact prune active and event operations differ")
        return opened

    def _append_planned_prune_event(
        self,
        control: _ReconciliationControl,
        prune_descriptor: int,
        active: _OpenPruneActive,
        stage: _PruneStage,
        events: list[_OpenPruneEvent],
    ) -> _OpenPruneEvent:
        self._validate_open_prune_active(active)
        self._write_prune_event(
            prune_descriptor,
            active.operation,
            stage,
            name=active.event_names[stage],
            control=control,
        )
        opened = self._open_planned_prune_event(
            control,
            prune_descriptor,
            active,
            stage,
        )
        if opened is None:
            raise RuntimeError("artifact prune event disappeared after durable append")
        events.append(opened)
        return opened

    def _validate_open_prune_event(self, event: _OpenPruneEvent) -> None:
        if event.closed:
            raise _PruneEventIdentityError("artifact prune event descriptor is closed")
        try:
            metadata = os.fstat(event.descriptor)
            self._validate_private_file(metadata, self._temporary_mode)
        except BaseException as error:
            raise _PruneEventIdentityError(
                "artifact prune event descriptor validation failed"
            ) from error
        if not event.candidate.matches(metadata) or not event.identity.matches_with_size(metadata):
            raise _PruneEventIdentityError("artifact prune event descriptor identity changed")
        try:
            current = capture_file_identity(
                event.identity.dir_fd,
                event.candidate.name,
                event.descriptor,
                expected_uid=event.identity.st_uid,
                expected_mode=event.identity.mode,
            )
        except BaseException as error:
            raise _PruneEventIdentityError("artifact prune event name validation failed") from error
        if current != event.identity:
            raise _PruneEventIdentityError(
                "artifact prune event name no longer matches its descriptor"
            )

    def _close_prune_events(
        self,
        events: list[_OpenPruneEvent],
        *,
        primary_error: BaseException | None = None,
    ) -> None:
        descriptors: list[int | None] = []
        for event in events:
            if event.closed:
                continue
            event.closed = True
            descriptors.append(event.descriptor)
        self._close_descriptors(descriptors, primary_error=primary_error)

    @staticmethod
    def _validate_prune_operation(operation: _PruneOperation) -> None:
        if len(operation.operation_id) != 32 or any(
            character not in "0123456789abcdef" for character in operation.operation_id
        ):
            raise ValueError("artifact prune operation id is invalid")
        try:
            UUID(operation.upload_id)
            UUID(operation.artifact_id)
            if operation.execution_id is not None:
                UUID(operation.execution_id)
        except ValueError as error:
            raise ValueError("artifact prune operation UUID is invalid") from error
        original = Path(operation.original_relative_path)
        quarantine = Path(operation.quarantine_relative_path)
        if (
            original.is_absolute()
            or len(original.parts) != 2
            or original.parts[0] != "outbox"
            or original.name in {"", ".", ".."}
            or original.as_posix() != operation.original_relative_path
            or is_artifact_prune_quarantine_path(operation.original_relative_path)
            or quarantine.is_absolute()
            or len(quarantine.parts) != 2
            or quarantine.parts[0] != "outbox"
            or quarantine.as_posix() != operation.quarantine_relative_path
            or not is_artifact_prune_quarantine_path(operation.quarantine_relative_path)
        ):
            raise ValueError("artifact prune operation path is invalid")
        if (
            operation.directory_dev < 0
            or operation.directory_ino <= 0
            or operation.st_dev < 0
            or operation.st_ino <= 0
            or operation.st_uid < 0
            or operation.file_type != stat.S_IFREG
            or operation.mode != SQLiteArtifactStager._final_mode
            or operation.st_nlink != 1
            or operation.size_bytes <= 0
            or len(operation.sha256) != 64
            or any(character not in "0123456789abcdef" for character in operation.sha256)
        ):
            raise ValueError("artifact prune operation identity is invalid")

    async def validate_for_upload(self, artifact_id: str) -> Path:
        """Fail closed unless the queued read-only object currently matches SQLite.

        Mode 0400 prevents accidental writes, not a hostile process running as
        the same UID (which can chmod the file). This path-returning check is
        not an end-to-end upload guarantee. A future uploader must open with
        O_NOFOLLOW and validate and transmit through that same descriptor,
        including a fresh size and SHA-256 calculation.
        """

        row = await asyncio.to_thread(self.store.artifact_upload, artifact_id)
        if row is None:
            raise FileNotFoundError("queued artifact is unavailable")
        return await asyncio.to_thread(self._validate_upload_row, row)

    async def prune_confirmed(
        self,
        *,
        maximum_age_seconds: int | None,
        retain_count: int | None,
        retain_bytes: int | None,
        batch_limit: int = 100,
    ) -> ArtifactPruneReport:
        if maximum_age_seconds is not None and maximum_age_seconds < 0:
            raise ValueError("artifact retention age cannot be negative")
        if retain_count is not None and retain_count < 0:
            raise ValueError("artifact retention count cannot be negative")
        if retain_bytes is not None and retain_bytes < 0:
            raise ValueError("artifact retention bytes cannot be negative")
        if maximum_age_seconds is None and retain_count is None and retain_bytes is None:
            raise ValueError("at least one artifact retention limit is required")
        if batch_limit <= 0 or batch_limit > 10_000:
            raise ValueError("artifact pruning batch must be between 1 and 10000")
        async with self._stage_lock:
            self._ensure_available()
            return await asyncio.to_thread(
                self._prune_confirmed_sync,
                maximum_age_seconds,
                retain_count,
                retain_bytes,
                batch_limit,
            )

    def _new_prune_operation(
        self,
        row: dict[str, Any],
        identity: FileIdentity,
        manifest: dict[str, object],
    ) -> tuple[_PruneOperation, QuarantinePlan]:
        if str(manifest.get("artifact_id")) != str(row["artifact_id"]):
            raise RuntimeError("artifact prune manifest identity is inconsistent")
        plan = plan_quarantine_name(ARTIFACT_PRUNE_QUARANTINE_PREFIX)
        operation = _PruneOperation(
            operation_id=secrets.token_hex(16),
            upload_id=str(row["upload_id"]),
            artifact_id=str(row["artifact_id"]),
            execution_id=(
                str(manifest["execution_id"])
                if isinstance(manifest.get("execution_id"), str)
                else None
            ),
            original_relative_path=str(row["relative_path"]),
            quarantine_relative_path=f"outbox/{plan.relative_name}",
            directory_dev=identity.directory_dev,
            directory_ino=identity.directory_ino,
            st_dev=identity.st_dev,
            st_ino=identity.st_ino,
            st_uid=identity.st_uid,
            file_type=identity.file_type,
            mode=identity.mode,
            st_nlink=identity.st_nlink,
            size_bytes=int(row["size_bytes"]),
            sha256=str(row["sha256"]),
        )
        self._validate_prune_operation(operation)
        return operation, plan

    @staticmethod
    def _prune_identity_matches(
        operation: _PruneOperation,
        identity: FileIdentity,
    ) -> bool:
        return (
            identity.directory_dev,
            identity.directory_ino,
            identity.st_dev,
            identity.st_ino,
            identity.st_uid,
            identity.file_type,
            identity.mode,
            identity.st_nlink,
            identity.st_size,
        ) == (
            operation.directory_dev,
            operation.directory_ino,
            operation.st_dev,
            operation.st_ino,
            operation.st_uid,
            operation.file_type,
            operation.mode,
            operation.st_nlink,
            operation.size_bytes,
        )

    def _write_prune_manual_recovery(
        self,
        prune_descriptor: int,
        active: _OpenPruneActive,
        events: list[_OpenPruneEvent],
        *,
        reason: str,
        primary_error: BaseException | None = None,
        control: _ReconciliationControl | None = None,
        event_guard: Callable[[], None] | None = None,
    ) -> None:
        operation = active.operation
        self._record_maintenance_issue(
            f"prune_operation:{operation.operation_id}:manual_recovery_required:{reason}"
        )
        try:
            if event_guard is not None:
                event_guard()
            if any(event.stage is _PruneStage.MANUAL_RECOVERY_REQUIRED for event in events):
                return
            self._append_planned_prune_event(
                control or self._new_reconciliation_control(),
                prune_descriptor,
                active,
                _PruneStage.MANUAL_RECOVERY_REQUIRED,
                events,
            )
        except BaseException as event_error:
            if primary_error is not None:
                primary_error.add_note(
                    f"artifact prune manual recovery event also failed: {event_error!r}"
                )
                return
            raise

    def _validate_prune_object(
        self,
        control: _ReconciliationControl,
        outbox_descriptor: int,
        operation: _PruneOperation,
        name: str,
    ) -> FileIdentity:
        identity = self._validate_named_artifact(
            outbox_descriptor,
            name,
            expected_size=operation.size_bytes,
            expected_sha256=operation.sha256,
            control=control,
        )
        if not self._prune_identity_matches(operation, identity):
            raise RuntimeError("artifact prune object identity changed")
        return identity

    def _finish_prune_sqlite_association(
        self,
        control: _ReconciliationControl,
        prune_descriptor: int,
        active: _OpenPruneActive,
        events: list[_OpenPruneEvent],
        *,
        event_guard: Callable[[], None] | None = None,
    ) -> bool:
        operation = active.operation
        control.check()
        if event_guard is not None:
            event_guard()
        updated = self.store.update_confirmed_artifact_path(
            operation.upload_id,
            expected_relative_path=operation.original_relative_path,
            quarantine_relative_path=operation.quarantine_relative_path,
        )
        if not updated:
            current = self.store.artifact_upload(operation.artifact_id)
            updated = bool(
                current is not None
                and str(current["upload_id"]) == operation.upload_id
                and str(current["state"]) == "confirmed"
                and str(current["relative_path"]) == operation.quarantine_relative_path
            )
        if not updated:
            return False
        self._after_prune_sqlite_update(operation)
        self._append_planned_prune_event(
            control,
            prune_descriptor,
            active,
            _PruneStage.SQLITE_UPDATED,
            events,
        )
        if event_guard is not None:
            event_guard()
        self._record_quarantine(operation.quarantine_name, "confirmed_artifact")
        return True

    def _recover_prune_operation(
        self,
        control: _ReconciliationControl,
        outbox_descriptor: int,
        prune_descriptor: int,
        active: _OpenPruneActive,
        events: list[_OpenPruneEvent],
        stages: set[_PruneStage],
        *,
        event_guard: Callable[[], None],
    ) -> bool:
        operation = active.operation
        event_guard()
        if _PruneStage.SQLITE_UPDATED in stages:
            self._record_quarantine(operation.quarantine_name, "confirmed_artifact")
            return True
        if _PruneStage.MANUAL_RECOVERY_REQUIRED in stages:
            self._record_maintenance_issue(
                f"prune_operation:{operation.operation_id}:manual_recovery_required"
            )
            return False

        row = self.store.artifact_upload(operation.artifact_id)
        if (
            row is None
            or str(row["upload_id"]) != operation.upload_id
            or str(row["state"]) != "confirmed"
            or int(row["size_bytes"]) != operation.size_bytes
            or str(row["sha256"]) != operation.sha256
        ):
            self._write_prune_manual_recovery(
                prune_descriptor,
                active,
                events,
                reason="confirmed_row_identity_changed",
                control=control,
                event_guard=event_guard,
            )
            return False

        current_path = str(row["relative_path"])
        original_exists = self._entry_exists(outbox_descriptor, operation.original_name)
        quarantine_exists = self._entry_exists(outbox_descriptor, operation.quarantine_name)
        if original_exists and quarantine_exists:
            self._write_prune_manual_recovery(
                prune_descriptor,
                active,
                events,
                reason="original_and_quarantine_both_present",
                control=control,
                event_guard=event_guard,
            )
            return False
        if not original_exists and not quarantine_exists:
            self._write_prune_manual_recovery(
                prune_descriptor,
                active,
                events,
                reason="artifact_location_missing",
                control=control,
                event_guard=event_guard,
            )
            return False

        try:
            if quarantine_exists:
                try:
                    self._validate_prune_object(
                        control,
                        outbox_descriptor,
                        operation,
                        operation.quarantine_name,
                    )
                except BaseException as error:
                    self._raise_if_reconciliation_stopped(error)
                    self._write_prune_manual_recovery(
                        prune_descriptor,
                        active,
                        events,
                        reason="quarantine_identity_invalid",
                        primary_error=error,
                        control=control,
                        event_guard=event_guard,
                    )
                    return False
                if _PruneStage.QUARANTINED not in stages:
                    event_guard()
                    self._append_planned_prune_event(
                        control,
                        prune_descriptor,
                        active,
                        _PruneStage.QUARANTINED,
                        events,
                    )
            else:
                if current_path != operation.original_relative_path:
                    self._write_prune_manual_recovery(
                        prune_descriptor,
                        active,
                        events,
                        reason="confirmed_row_path_changed",
                        control=control,
                        event_guard=event_guard,
                    )
                    return False
                try:
                    original_identity = self._validate_prune_object(
                        control,
                        outbox_descriptor,
                        operation,
                        operation.original_name,
                    )
                except BaseException as error:
                    self._raise_if_reconciliation_stopped(error)
                    self._write_prune_manual_recovery(
                        prune_descriptor,
                        active,
                        events,
                        reason="original_identity_invalid",
                        primary_error=error,
                        control=control,
                        event_guard=event_guard,
                    )
                    return False
                plan = QuarantinePlan(
                    prefix=ARTIFACT_PRUNE_QUARANTINE_PREFIX,
                    relative_name=operation.quarantine_name,
                )
                event_guard()
                result = logical_quarantine(
                    original_identity,
                    quarantine_prefix=ARTIFACT_PRUNE_QUARANTINE_PREFIX,
                    plan=plan,
                )
                if (
                    not result.logical_deletion_confirmed
                    or result.quarantine_name != operation.quarantine_name
                ):
                    raise RuntimeError("artifact prune recovery quarantine was not durable")
                self._after_prune_quarantine(operation)
                self._validate_prune_object(
                    control,
                    outbox_descriptor,
                    operation,
                    operation.quarantine_name,
                )
                event_guard()
                self._append_planned_prune_event(
                    control,
                    prune_descriptor,
                    active,
                    _PruneStage.QUARANTINED,
                    events,
                )

            if current_path not in {
                operation.original_relative_path,
                operation.quarantine_relative_path,
            }:
                self._write_prune_manual_recovery(
                    prune_descriptor,
                    active,
                    events,
                    reason="confirmed_row_path_changed",
                    control=control,
                    event_guard=event_guard,
                )
                return False
            if not self._finish_prune_sqlite_association(
                control,
                prune_descriptor,
                active,
                events,
                event_guard=event_guard,
            ):
                self._write_prune_manual_recovery(
                    prune_descriptor,
                    active,
                    events,
                    reason="confirmed_row_update_failed",
                    control=control,
                    event_guard=event_guard,
                )
                return False
            return True
        except BaseException as error:
            self._raise_if_reconciliation_stopped(error)
            if isinstance(error, _PruneEventIdentityError):
                raise
            self._record_maintenance_issue(
                f"prune_operation:{operation.operation_id}:reconciliation_deferred:"
                f"{type(error).__name__}"
            )
            return False

    def _reconcile_prune_intents(
        self,
        control: _ReconciliationControl,
        outbox_descriptor: int,
        prune_descriptor: int,
        active_descriptor: int,
        retired_descriptor: int,
        conflicts_descriptor: int,
    ) -> _PruneReconciliationResult:
        active_names: list[str] = []
        invalid_active_names = 0
        with os.scandir(active_descriptor) as entries:
            for entry in entries:
                control.check()
                match = self._prune_active_pattern.fullmatch(entry.name)
                if match is None:
                    invalid_active_names += 1
                    self._record_maintenance_issue(
                        f"prune_active:{entry.name}:manual_recovery_required:invalid_name"
                    )
                    continue
                active_names.append(entry.name)

        processed = 0
        remaining_active = len(active_names) + invalid_active_names
        for index, name in enumerate(sorted(active_names)):
            match = self._prune_active_pattern.fullmatch(name)
            assert match is not None
            operation_id = match.group("operation")
            active: _OpenPruneActive | None = None
            events: list[_OpenPruneEvent] = []
            primary_error: BaseException | None = None
            operation_counted = False
            try:
                metadata = os.stat(name, dir_fd=active_descriptor, follow_symlinks=False)
                candidate = _PruneActiveCandidate(
                    name=name,
                    operation_id=operation_id,
                    st_dev=int(metadata.st_dev),
                    st_ino=int(metadata.st_ino),
                    st_uid=int(metadata.st_uid),
                    file_type=stat.S_IFMT(metadata.st_mode),
                    mode=stat.S_IMODE(metadata.st_mode),
                    st_nlink=int(metadata.st_nlink),
                    st_size=int(metadata.st_size),
                )
                active = self._read_prune_active(active_descriptor, candidate, control)
                for stage in _PruneStage:
                    event = self._open_planned_prune_event(
                        control,
                        prune_descriptor,
                        active,
                        stage,
                    )
                    if event is not None:
                        events.append(event)
                self._after_prune_events_parsed(tuple(events))

                guarded_active = active

                def event_guard(
                    active_record: _OpenPruneActive = guarded_active,
                    event_records: list[_OpenPruneEvent] = events,
                ) -> None:
                    control.check()
                    self._validate_open_prune_active(active_record)
                    for event in event_records:
                        self._validate_open_prune_event(event)

                event_guard()
                stages = {event.stage for event in events}
                if _PruneStage.PREPARED not in stages:
                    self._write_prune_manual_recovery(
                        prune_descriptor,
                        active,
                        events,
                        reason="active_without_prepared",
                        control=control,
                        event_guard=event_guard,
                    )
                    self._move_prune_active_to_conflict(
                        active,
                        active_descriptor,
                        conflicts_descriptor,
                        event_guard=event_guard,
                    )
                    remaining_active -= 1
                    continue
                impossible = (
                    _PruneStage.SQLITE_UPDATED in stages and _PruneStage.QUARANTINED not in stages
                )
                if impossible:
                    self._write_prune_manual_recovery(
                        prune_descriptor,
                        active,
                        events,
                        reason="invalid_event_transition",
                        control=control,
                        event_guard=event_guard,
                    )
                    self._move_prune_active_to_conflict(
                        active,
                        active_descriptor,
                        conflicts_descriptor,
                        event_guard=event_guard,
                    )
                    remaining_active -= 1
                    continue
                if _PruneStage.MANUAL_RECOVERY_REQUIRED in stages:
                    self._record_maintenance_issue(
                        f"prune_operation:{operation_id}:manual_recovery_required"
                    )
                    self._move_prune_active_to_conflict(
                        active,
                        active_descriptor,
                        conflicts_descriptor,
                        event_guard=event_guard,
                    )
                    remaining_active -= 1
                    continue
                retired_name = f"retired-{operation_id}.json"
                if self._entry_exists(retired_descriptor, retired_name):
                    self._write_prune_manual_recovery(
                        prune_descriptor,
                        active,
                        events,
                        reason="retired_destination_conflict",
                        control=control,
                        event_guard=event_guard,
                    )
                    self._move_prune_active_to_conflict(
                        active,
                        active_descriptor,
                        conflicts_descriptor,
                        event_guard=event_guard,
                    )
                    remaining_active -= 1
                    continue
                try:
                    control.inspect_entry()
                except _ReconciliationLimitExceeded:
                    return _PruneReconciliationResult(
                        processed_operations=processed,
                        has_more=True,
                    )
                operation_counted = True
                completed = self._recover_prune_operation(
                    control,
                    outbox_descriptor,
                    prune_descriptor,
                    active,
                    events,
                    stages,
                    event_guard=event_guard,
                )
                if completed:
                    try:
                        self._retire_prune_active(
                            active,
                            active_descriptor,
                            retired_descriptor,
                            event_guard=event_guard,
                        )
                    except FileExistsError:
                        self._write_prune_manual_recovery(
                            prune_descriptor,
                            active,
                            events,
                            reason="retired_destination_conflict",
                            control=control,
                            event_guard=event_guard,
                        )
                        self._move_prune_active_to_conflict(
                            active,
                            active_descriptor,
                            conflicts_descriptor,
                            event_guard=event_guard,
                        )
                    remaining_active -= 1
                elif any(event.stage is _PruneStage.MANUAL_RECOVERY_REQUIRED for event in events):
                    self._move_prune_active_to_conflict(
                        active,
                        active_descriptor,
                        conflicts_descriptor,
                        event_guard=event_guard,
                    )
                    remaining_active -= 1
                self._after_prune_operation_reconciled(operation_id)
            except BaseException as error:
                primary_error = error
                self._raise_if_reconciliation_stopped(error)
                self._record_maintenance_issue(
                    f"prune_operation:{operation_id}:manual_recovery_required:"
                    + (
                        "retirement_durability_indeterminate"
                        if self._is_retirement_durability_indeterminate(error)
                        else f"invalid_or_replaced_event:{type(error).__name__}"
                    )
                )
            finally:
                self._close_prune_events(events, primary_error=primary_error)
                self._close_prune_active(active, primary_error=primary_error)
            if operation_counted:
                processed += 1
            if index + 1 < len(active_names):
                control.check()
        return _PruneReconciliationResult(
            processed_operations=processed,
            has_more=remaining_active > 0,
        )

    def _prune_confirmed_sync(
        self,
        maximum_age_seconds: int | None,
        retain_count: int | None,
        retain_bytes: int | None,
        batch_limit: int,
    ) -> ArtifactPruneReport:
        cutoff = None
        if maximum_age_seconds is not None:
            cutoff = (datetime.now(UTC) - timedelta(seconds=maximum_age_seconds)).isoformat()
        rows = self.store.confirmed_artifacts_for_pruning(
            confirmed_before=cutoff,
            retain_count=retain_count,
            retain_bytes=retain_bytes,
            limit=batch_limit,
        )
        descriptors = self._open_managed_tree()
        outbox_descriptor = descriptors[2]
        prune_descriptor = self._open_prune_intent_directory(outbox_descriptor)
        active_descriptor = self._open_prune_active_directory(outbox_descriptor)
        retired_descriptor = self._open_prune_retired_directory(outbox_descriptor)
        conflicts_descriptor = self._open_prune_conflicts_directory(outbox_descriptor)
        control = self._new_reconciliation_control()
        files_deleted = 0
        rows_deleted = 0
        bytes_deleted = 0
        issues: list[str] = []
        primary_error: BaseException | None = None
        try:
            for row in rows:
                control.inspect_entry()
                upload_id = str(row["upload_id"])
                active: _OpenPruneActive | None = None
                events: list[_OpenPruneEvent] = []
                row_error: BaseException | None = None
                event_guard: Callable[[], None] | None = None
                relative_value = str(row["relative_path"])
                relative = Path(relative_value)
                if not self._is_safe_outbox_relative(relative_value):
                    issues.append(f"{upload_id}:unsafe_sqlite_path")
                    continue
                if not self._entry_exists(outbox_descriptor, relative.name):
                    issues.append(f"{upload_id}:confirmed_file_missing")
                    continue
                try:
                    identity = self._validate_named_artifact(
                        outbox_descriptor,
                        relative.name,
                        expected_size=int(row["size_bytes"]),
                        expected_sha256=str(row["sha256"]),
                        control=control,
                    )
                    manifest = self._validate_row_payload(row)
                    if is_artifact_prune_quarantine_path(relative_value):
                        issues.append(f"{upload_id}:physical_delete_pending:{relative.name}")
                        continue
                    control.check()
                    operation, plan = self._new_prune_operation(row, identity, manifest)
                    active = self._create_prune_active(
                        active_descriptor,
                        operation,
                        control=control,
                    )
                    self._append_planned_prune_event(
                        control,
                        prune_descriptor,
                        active,
                        _PruneStage.PREPARED,
                        events,
                    )

                    guarded_active = active

                    def guard_events(
                        active_record: _OpenPruneActive = guarded_active,
                        event_records: list[_OpenPruneEvent] = events,
                    ) -> None:
                        control.check()
                        self._validate_open_prune_active(active_record)
                        for event in event_records:
                            self._validate_open_prune_event(event)

                    event_guard = guard_events
                    event_guard()
                    self._after_prune_prepared(operation)
                    event_guard()
                    quarantine = logical_quarantine(
                        identity,
                        quarantine_prefix=ARTIFACT_PRUNE_QUARANTINE_PREFIX,
                        plan=plan,
                    )
                    if not quarantine.logical_deletion_confirmed:
                        raise RuntimeError("artifact prune quarantine was not durable")
                    if quarantine.quarantine_name is None:
                        raise RuntimeError("artifact quarantine path is unavailable")
                    if quarantine.quarantine_name != operation.quarantine_name:
                        raise RuntimeError("artifact prune used an unexpected quarantine name")
                    self._after_prune_quarantine(operation)
                    quarantine_identity = self._validate_named_artifact(
                        outbox_descriptor,
                        operation.quarantine_name,
                        expected_size=operation.size_bytes,
                        expected_sha256=operation.sha256,
                        control=control,
                    )
                    if not self._prune_identity_matches(operation, quarantine_identity):
                        error = RuntimeError("artifact prune quarantine identity changed")
                        self._write_prune_manual_recovery(
                            prune_descriptor,
                            active,
                            events,
                            reason="quarantine_identity_mismatch",
                            primary_error=error,
                            control=control,
                            event_guard=event_guard,
                        )
                        raise error
                    self._append_planned_prune_event(
                        control,
                        prune_descriptor,
                        active,
                        _PruneStage.QUARANTINED,
                        events,
                    )
                    event_guard()
                    if self._finish_prune_sqlite_association(
                        control,
                        prune_descriptor,
                        active,
                        events,
                        event_guard=event_guard,
                    ):
                        try:
                            self._retire_prune_active(
                                active,
                                active_descriptor,
                                retired_descriptor,
                                event_guard=event_guard,
                            )
                        except FileExistsError:
                            self._write_prune_manual_recovery(
                                prune_descriptor,
                                active,
                                events,
                                reason="retired_destination_conflict",
                                control=control,
                                event_guard=event_guard,
                            )
                            self._move_prune_active_to_conflict(
                                active,
                                active_descriptor,
                                conflicts_descriptor,
                                event_guard=event_guard,
                            )
                        issues.append(
                            f"{upload_id}:physical_delete_pending:{quarantine.quarantine_name}"
                        )
                    else:
                        self._write_prune_manual_recovery(
                            prune_descriptor,
                            active,
                            events,
                            reason="confirmed_row_changed",
                            control=control,
                            event_guard=event_guard,
                        )
                        self._move_prune_active_to_conflict(
                            active,
                            active_descriptor,
                            conflicts_descriptor,
                            event_guard=event_guard,
                        )
                        self._record_quarantine(
                            quarantine.quarantine_name,
                            "confirmed_artifact_row_changed",
                        )
                        issues.append(f"{upload_id}:confirmed_row_changed")
                except BaseException as error:
                    row_error = error
                    self._raise_if_reconciliation_stopped(error)
                    issues.append(
                        f"{upload_id}:"
                        + (
                            "retirement_durability_indeterminate"
                            if self._is_retirement_durability_indeterminate(error)
                            else type(error).__name__
                        )
                    )
                finally:
                    if (
                        active is not None
                        and event_guard is not None
                        and self._entry_exists(active_descriptor, active.candidate.name)
                        and any(
                            event.stage is _PruneStage.MANUAL_RECOVERY_REQUIRED for event in events
                        )
                    ):
                        try:
                            self._move_prune_active_to_conflict(
                                active,
                                active_descriptor,
                                conflicts_descriptor,
                                event_guard=event_guard,
                            )
                        except BaseException as terminal_error:
                            issues.append(
                                f"{upload_id}:manual_recovery_terminalization_failed:"
                                + (
                                    "retirement_durability_indeterminate"
                                    if self._is_retirement_durability_indeterminate(terminal_error)
                                    else type(terminal_error).__name__
                                )
                            )
                            if row_error is not None:
                                row_error.add_note(
                                    "artifact prune conflict terminalization also failed: "
                                    f"{terminal_error!r}"
                                )
                    self._close_prune_events(events, primary_error=row_error)
                    self._close_prune_active(active, primary_error=row_error)
            return ArtifactPruneReport(
                selected=len(rows),
                files_deleted=files_deleted,
                rows_deleted=rows_deleted,
                bytes_deleted=bytes_deleted,
                issues=tuple(issues),
            )
        except BaseException as error:
            primary_error = error
            raise
        finally:
            self._close_descriptors(
                (
                    conflicts_descriptor,
                    retired_descriptor,
                    active_descriptor,
                    prune_descriptor,
                    *descriptors,
                ),
                primary_error=primary_error,
            )

    async def _wait_worker_after_cancel(self, worker: asyncio.Task[_T]) -> _T:
        deadline = asyncio.get_running_loop().time() + self.reconciliation_cleanup_timeout_seconds
        while not worker.done():
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("artifact background worker did not stop after cancellation")
            try:
                done, _ = await asyncio.wait({worker}, timeout=remaining)
            except asyncio.CancelledError:
                continue
            if not done:
                raise TimeoutError("artifact background worker did not stop after cancellation")
        return worker.result()

    def _track_worker(self, worker: asyncio.Task[_T]) -> asyncio.Task[_T]:
        self._unfinished_workers.add(worker)

        def finished(task: asyncio.Task[Any]) -> None:
            self._unfinished_workers.discard(task)
            self._consume_future_result(task)

        worker.add_done_callback(finished)
        return worker

    @staticmethod
    def _consume_future_result(worker: asyncio.Future[Any]) -> None:
        if worker.cancelled():
            return
        try:
            worker.exception()
        except BaseException:
            return

    def _reconcile_and_find_existing(
        self,
        supplied_manifest: dict[str, object],
        task_id: str,
        stop: threading.Event,
        deadline: float,
    ) -> StagedArtifact | None:
        control = self._new_reconciliation_control(stop=stop, deadline=deadline)
        artifact_id = supplied_manifest.get("artifact_id")
        execution_id = supplied_manifest.get("execution_id")
        self._reconcile_relevant_sync(
            control,
            artifact_id=artifact_id if isinstance(artifact_id, str) else None,
            execution_id=execution_id if isinstance(execution_id, str) else None,
        )
        control.check()
        return self._existing_staged(supplied_manifest, task_id, control=control)

    def _new_reconciliation_control(
        self,
        *,
        stop: threading.Event | None = None,
        deadline: float | None = None,
    ) -> _ReconciliationControl:
        return _ReconciliationControl(
            stop=stop or threading.Event(),
            deadline=(
                time.monotonic() + self.reconciliation_timeout_seconds
                if deadline is None
                else deadline
            ),
            maximum_entries=self.reconciliation_maximum_entries,
            maximum_bytes=self.reconciliation_maximum_bytes,
        )

    def _prune_reconciliation_control(
        self,
        parent: _ReconciliationControl,
    ) -> _ReconciliationControl:
        """Keep append-only maintenance history from starving active recovery."""

        return _ReconciliationControl(
            stop=parent.stop,
            deadline=parent.deadline,
            maximum_entries=min(4_096, self.reconciliation_maximum_entries),
            maximum_bytes=min(64 * 1024 * 1024, self.reconciliation_maximum_bytes),
        )

    def _stage_sync(
        self,
        manifest: dict[str, object],
        source: Path | None,
        task_id: UUID,
        maximum_size_bytes: int,
        cancellation: CancellationToken,
        transaction: _StagingTransaction,
        supplied_source_descriptor: int | None,
        expected_source_identity: FileIdentity | None,
        capture_authority: dict[str, object] | None,
        intent_durable_callback: Callable[[dict[str, object]], None] | None,
    ) -> StagedArtifact:
        descriptors = self._open_managed_tree()
        (
            trusted_descriptor,
            artifact_descriptor,
            outbox_descriptor,
            intent_descriptor,
        ) = descriptors
        source_descriptor: int | None = supplied_source_descriptor
        destination_descriptor: int | None = None
        temporary: str | None = None
        temporary_identity: FileIdentity | None = None
        intent: _ArtifactIntent | None = None
        published = False
        queued = False
        primary_error: BaseException | None = None
        try:
            if source_descriptor is None:
                if source is None:
                    raise ValueError("artifact source is unavailable")
                source_descriptor = self._open_source(source, artifact_descriptor)
            before = os.fstat(source_descriptor)
            self._validate_source(before, maximum_size_bytes)
            if expected_source_identity is not None and not expected_source_identity.matches(
                before
            ):
                raise RuntimeError("artifact source descriptor identity changed")
            os.lseek(source_descriptor, 0, os.SEEK_SET)
            suffix = ".pcapng" if str(manifest.get("artifact_type")) == "pcapng" else ".pcap"
            temporary = f".staging-{secrets.token_hex(24)}"
            final_name = f"artifact-{secrets.token_hex(24)}{suffix}"
            destination_descriptor = os.open(
                temporary,
                self._write_flags(),
                self._temporary_mode,
                dir_fd=outbox_descriptor,
            )
            temporary_identity = capture_file_identity(
                outbox_descriptor,
                temporary,
                destination_descriptor,
                expected_uid=self._effective_uid(os.fstat(destination_descriptor)),
                expected_mode=self._temporary_mode,
            )
            digest = hashlib.sha256()
            copied = 0
            while True:
                transaction.check(cancellation)
                chunk = os.read(source_descriptor, self._chunk_size)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > maximum_size_bytes:
                    raise RuntimeError("artifact size limit was violated during staging")
                digest.update(chunk)
                self._write_all(destination_descriptor, chunk)
                self._after_chunk(copied)
            if copied <= 0:
                raise RuntimeError("empty artifacts cannot be staged")
            after = os.fstat(source_descriptor)
            if expected_source_identity is not None and not expected_source_identity.matches(after):
                raise RuntimeError("artifact source descriptor identity changed during staging")
            if self._source_fingerprint(before) != self._source_fingerprint(after):
                raise RuntimeError("artifact source changed during staging")
            if copied != before.st_size:
                raise RuntimeError("artifact source size changed during staging")
            final_manifest = {
                **manifest,
                "size_bytes": copied,
                "sha256": digest.hexdigest(),
            }
            validate_contract("artifact-manifest.schema.json", final_manifest)
            self._set_descriptor_mode(destination_descriptor, self._final_mode)
            temporary_identity = capture_file_identity(
                outbox_descriptor,
                temporary,
                destination_descriptor,
                expected_uid=self._effective_uid(os.fstat(destination_descriptor)),
                expected_mode=self._final_mode,
            )
            os.fsync(destination_descriptor)
            completed_destination = destination_descriptor
            destination_descriptor = None
            self._close_descriptors((completed_destination,))
            intent = self._write_intent(
                intent_descriptor,
                task_id=str(task_id),
                temporary_name=temporary,
                final_name=final_name,
                manifest=final_manifest,
                capture_authority=capture_authority,
            )
            if intent_durable_callback is not None:
                intent_durable_callback(
                    {
                        "intent_name": intent.name,
                        "source_st_dev": int(before.st_dev),
                        "source_st_ino": int(before.st_ino),
                        "source_sha256": digest.hexdigest(),
                    }
                )
            transaction.ready(cancellation)
            self._before_commit(transaction)
            transaction.begin_commit(cancellation)
            self._publish_without_overwrite(temporary, final_name, outbox_descriptor)
            published = True
            temporary = None
            os.fsync(outbox_descriptor)
            self._after_publish(intent)
            self._validate_named_artifact(
                outbox_descriptor,
                final_name,
                expected_size=copied,
                expected_sha256=digest.hexdigest(),
            )
            self.store.ensure_artifact_queued(
                task_id=str(task_id),
                relative_path=intent.relative_path,
                media_type=str(final_manifest["media_type"]),
                payload=final_manifest,
            )
            queued = True
            self._after_queue(intent)
            removed_intent = logical_quarantine(
                intent.identity,
                quarantine_prefix=".artifact-intent-quarantine-",
            )
            if not removed_intent.logical_deletion_confirmed:
                raise RuntimeError("artifact intent quarantine was not durable")
            assert removed_intent.quarantine_name is not None
            self._record_quarantine(removed_intent.quarantine_name, "artifact_intent")
            transaction.committed()
            return StagedArtifact(
                path=self.artifact_root / intent.relative_path,
                manifest=final_manifest,
            )
        except BaseException as error:
            primary_error = error
            cleanup_errors: list[BaseException] = []
            if not published:
                for identity in (
                    temporary_identity,
                    intent.identity if intent is not None else None,
                ):
                    if identity is None:
                        continue
                    try:
                        outcome = logical_quarantine(
                            identity,
                            quarantine_prefix=".artifact-cleanup-quarantine-",
                        )
                        if not outcome.logical_deletion_confirmed:
                            raise RuntimeError("artifact cleanup quarantine was not durable")
                        assert outcome.quarantine_name is not None
                        self._record_quarantine(outcome.quarantine_name, "artifact_cleanup")
                    except BaseException as cleanup:
                        cleanup_errors.append(cleanup)
            elif queued:
                # A durable row and final object are authoritative. Keep an
                # intent if its removal/fsync failed so startup can finish.
                pass
            for cleanup_error in cleanup_errors:
                error.add_note(f"artifact staging cleanup incomplete: {cleanup_error!r}")
            raise
        finally:
            self._close_descriptors(
                (
                    destination_descriptor,
                    source_descriptor,
                    *reversed(descriptors),
                ),
                primary_error=primary_error,
            )

    def _existing_staged(
        self,
        supplied_manifest: dict[str, object],
        task_id: str,
        *,
        control: _ReconciliationControl | None = None,
    ) -> StagedArtifact | None:
        artifact_id = supplied_manifest.get("artifact_id")
        if not isinstance(artifact_id, str):
            return None
        row = self.store.artifact_upload(artifact_id)
        if row is None:
            return None
        if str(row["task_id"]) != task_id:
            raise RuntimeError("artifact idempotency conflict: task_id")
        payload = json.loads(str(row["payload"]))
        if not isinstance(payload, dict):
            raise RuntimeError("artifact idempotency conflict: persisted_manifest")
        for field_name in self._stable_identity_fields:
            if payload.get(field_name) != supplied_manifest.get(field_name):
                raise RuntimeError(f"artifact idempotency conflict: {field_name}")
        path = self._validate_upload_row(row, control=control)
        return StagedArtifact(path=path, manifest=dict(payload))

    def _write_intent(
        self,
        intent_descriptor: int,
        *,
        task_id: str,
        temporary_name: str,
        final_name: str,
        manifest: dict[str, object],
        capture_authority: dict[str, object] | None = None,
    ) -> _ArtifactIntent:
        name = f"intent-{secrets.token_hex(24)}.json"
        payload: dict[str, object] = {
            "version": 2 if capture_authority is not None else 1,
            "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "task_id": task_id,
            "artifact_id": manifest["artifact_id"],
            "execution_id": manifest["execution_id"],
            "temporary_name": temporary_name,
            "final_name": final_name,
            "size_bytes": manifest["size_bytes"],
            "sha256": manifest["sha256"],
            "media_type": manifest["media_type"],
            "manifest": manifest,
        }
        if capture_authority is not None:
            expected_authority_fields = {
                "task_id",
                "execution_id",
                "idempotency_key",
                "fingerprint_version",
                "fingerprint_sha256",
                "operation_token",
            }
            if set(capture_authority) != expected_authority_fields:
                raise ValueError("capture artifact intent authority is invalid")
            self._validate_capture_intent_authority(
                capture_authority,
                task_id=task_id,
                manifest=manifest,
            )
            payload["capture_authority"] = dict(capture_authority)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > self._maximum_intent_bytes:
            raise RuntimeError("artifact intent is too large")
        descriptor = os.open(
            name,
            self._write_flags(),
            self._temporary_mode,
            dir_fd=intent_descriptor,
        )
        identity: FileIdentity | None = None
        primary_error: BaseException | None = None
        try:
            identity = capture_file_identity(
                intent_descriptor,
                name,
                descriptor,
                expected_uid=self._effective_uid(os.fstat(descriptor)),
                expected_mode=self._temporary_mode,
            )
            self._write_all(descriptor, encoded)
            os.fsync(descriptor)
        except BaseException as error:
            primary_error = error
        try:
            self._close_descriptor(descriptor)
        except BaseException as close_error:
            if primary_error is None:
                primary_error = close_error
            else:
                primary_error.add_note(f"artifact descriptor close also failed: {close_error!r}")
        if primary_error is not None:
            if identity is None:
                primary_error.add_note(
                    f"manual recovery may be required for artifact intent {name}"
                )
            else:
                quarantine = logical_quarantine(
                    identity,
                    quarantine_prefix=".artifact-intent-quarantine-",
                    primary_error=primary_error,
                )
                if quarantine.logical_deletion_confirmed:
                    assert quarantine.quarantine_name is not None
                    self._record_quarantine(quarantine.quarantine_name, "artifact_intent")
            raise primary_error
        assert identity is not None
        try:
            os.fsync(intent_descriptor)
        except BaseException as error:
            quarantine = logical_quarantine(
                identity,
                quarantine_prefix=".artifact-intent-quarantine-",
                primary_error=error,
            )
            if quarantine.logical_deletion_confirmed:
                assert quarantine.quarantine_name is not None
                self._record_quarantine(quarantine.quarantine_name, "artifact_intent")
            raise
        return _ArtifactIntent(
            name,
            temporary_name,
            final_name,
            task_id,
            manifest,
            identity,
            dict(capture_authority) if capture_authority is not None else None,
        )

    def _read_intent(
        self,
        intent_descriptor: int,
        name: str,
        control: _ReconciliationControl | None = None,
    ) -> _ArtifactIntent:
        if not name.startswith("intent-") or not name.endswith(".json") or "/" in name:
            raise ValueError("artifact intent name is invalid")
        descriptor = os.open(name, self._read_flags(), dir_fd=intent_descriptor)
        primary_error: BaseException | None = None
        identity: FileIdentity | None = None
        try:
            metadata = os.fstat(descriptor)
            self._validate_private_file(metadata, self._temporary_mode)
            identity = capture_file_identity(
                intent_descriptor,
                name,
                descriptor,
                expected_uid=self._effective_uid(metadata),
                expected_mode=self._temporary_mode,
            )
            if metadata.st_size <= 0 or metadata.st_size > self._maximum_intent_bytes:
                raise RuntimeError("artifact intent size is invalid")
            if control is not None:
                control.inspect_bytes(metadata.st_size)
            encoded = self._read_exact_file(descriptor, metadata.st_size)
            payload = json.loads(encoded.decode("utf-8"))
        except BaseException as error:
            primary_error = error
            raise
        finally:
            self._close_descriptors((descriptor,), primary_error=primary_error)
        expected = {
            "version",
            "recorded_at",
            "task_id",
            "artifact_id",
            "execution_id",
            "temporary_name",
            "final_name",
            "size_bytes",
            "sha256",
            "media_type",
            "manifest",
        }
        if not isinstance(payload, dict) or payload.get("version") not in {1, 2}:
            raise ValueError("artifact intent payload is invalid")
        capture_authority: dict[str, object] | None = None
        if payload["version"] == 2:
            expected.add("capture_authority")
            authority = payload.get("capture_authority")
            authority_fields = {
                "task_id",
                "execution_id",
                "idempotency_key",
                "fingerprint_version",
                "fingerprint_sha256",
                "operation_token",
            }
            if not isinstance(authority, dict) or set(authority) != authority_fields:
                raise ValueError("artifact intent capture authority is invalid")
            capture_authority = dict(authority)
        if set(payload) != expected:
            raise ValueError("artifact intent payload is invalid")
        temporary = payload["temporary_name"]
        final = payload["final_name"]
        task_id = payload["task_id"]
        manifest = payload["manifest"]
        if (
            not isinstance(temporary, str)
            or not temporary.startswith(".staging-")
            or "/" in temporary
            or not isinstance(final, str)
            or not final.startswith("artifact-")
            or "/" in final
            or not isinstance(task_id, str)
            or not isinstance(manifest, dict)
        ):
            raise ValueError("artifact intent fields are invalid")
        manifest_value = dict(manifest)
        validate_contract("artifact-manifest.schema.json", manifest_value)
        for key in (
            "artifact_id",
            "execution_id",
            "size_bytes",
            "sha256",
            "media_type",
        ):
            if payload[key] != manifest_value[key]:
                raise ValueError("artifact intent manifest is inconsistent")
        if capture_authority is not None:
            self._validate_capture_intent_authority(
                capture_authority,
                task_id=task_id,
                manifest=manifest_value,
            )
        if identity is None:
            raise RuntimeError("artifact intent identity is unavailable")
        return _ArtifactIntent(
            name,
            temporary,
            final,
            task_id,
            manifest_value,
            identity,
            capture_authority,
        )

    @staticmethod
    def _validate_capture_intent_authority(
        authority: dict[str, object],
        *,
        task_id: str,
        manifest: dict[str, object],
    ) -> None:
        ids = {
            "task_id": task_id,
            "execution_id": manifest.get("execution_id"),
            "idempotency_key": manifest.get("idempotency_key"),
        }
        for field_name, expected in ids.items():
            observed = authority.get(field_name)
            if (
                not isinstance(observed, str)
                or not isinstance(expected, str)
                or observed != expected
            ):
                raise ValueError(f"artifact intent capture authority {field_name} is inconsistent")
            try:
                if str(UUID(observed)) != observed:
                    raise ValueError
            except ValueError as error:
                raise ValueError(
                    f"artifact intent capture authority {field_name} is invalid"
                ) from error
        if manifest.get("artifact_id") != authority.get("idempotency_key"):
            raise ValueError("artifact intent capture artifact id is inconsistent")
        fingerprint_version = authority.get("fingerprint_version")
        fingerprint_sha256 = authority.get("fingerprint_sha256")
        operation_token = authority.get("operation_token")
        if (
            not isinstance(fingerprint_version, str)
            or not fingerprint_version
            or not isinstance(fingerprint_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", fingerprint_sha256) is None
            or not isinstance(operation_token, str)
            or re.fullmatch(r"[0-9a-f]{32}", operation_token) is None
        ):
            raise ValueError("artifact intent capture fingerprint authority is invalid")

    @staticmethod
    def _raise_if_reconciliation_stopped(error: BaseException) -> None:
        if isinstance(
            error,
            _ReconciliationCancelled | _ReconciliationLimitExceeded | TimeoutError,
        ):
            raise error

    def _reconcile_intent(
        self,
        control: _ReconciliationControl,
        outbox_descriptor: int,
        intent_descriptor: int,
        intent: _ArtifactIntent,
        protected_temporaries: set[str],
    ) -> None:
        protected_temporaries.add(intent.temporary_name)
        if self._entry_exists(outbox_descriptor, intent.final_name):
            self._validate_named_artifact(
                outbox_descriptor,
                intent.final_name,
                expected_size=cast(int, intent.manifest["size_bytes"]),
                expected_sha256=str(intent.manifest["sha256"]),
                control=control,
            )
            control.check()
            self.store.ensure_artifact_queued(
                task_id=intent.task_id,
                relative_path=intent.relative_path,
                media_type=str(intent.manifest["media_type"]),
                payload=intent.manifest,
            )
            if self._entry_exists(outbox_descriptor, intent.temporary_name):
                # A link/unlink publication remnant has st_nlink > 1 and is
                # deliberately rejected here for manual recovery.
                temporary_identity = self._validate_owned_regular(
                    outbox_descriptor,
                    intent.temporary_name,
                )
                control.check()
                deletion = logical_quarantine(
                    temporary_identity,
                    quarantine_prefix=".artifact-reconcile-quarantine-",
                )
                if not deletion.logical_deletion_confirmed:
                    raise RuntimeError("artifact temporary quarantine was not durable")
                assert deletion.quarantine_name is not None
                self._record_quarantine(deletion.quarantine_name, "artifact_temporary")
                protected_temporaries.discard(intent.temporary_name)
            control.check()
            intent_deletion = logical_quarantine(
                intent.identity,
                quarantine_prefix=".artifact-intent-quarantine-",
            )
            if not intent_deletion.logical_deletion_confirmed:
                raise RuntimeError("artifact intent quarantine was not durable")
            assert intent_deletion.quarantine_name is not None
            self._record_quarantine(intent_deletion.quarantine_name, "artifact_intent")
        elif self._entry_exists(outbox_descriptor, intent.temporary_name):
            temporary_identity = self._validate_named_artifact(
                outbox_descriptor,
                intent.temporary_name,
                expected_size=cast(int, intent.manifest["size_bytes"]),
                expected_sha256=str(intent.manifest["sha256"]),
                control=control,
            )
            control.check()
            if intent.capture_authority is None:
                deletion = logical_quarantine(
                    temporary_identity,
                    quarantine_prefix=".artifact-reconcile-quarantine-",
                )
                if not deletion.logical_deletion_confirmed:
                    raise RuntimeError("artifact temporary quarantine was not durable")
                assert deletion.quarantine_name is not None
                self._record_quarantine(deletion.quarantine_name, "artifact_temporary")
                control.check()
                intent_deletion = logical_quarantine(
                    intent.identity,
                    quarantine_prefix=".artifact-intent-quarantine-",
                )
                if not intent_deletion.logical_deletion_confirmed:
                    raise RuntimeError("artifact intent quarantine was not durable")
                assert intent_deletion.quarantine_name is not None
                self._record_quarantine(intent_deletion.quarantine_name, "artifact_intent")
                protected_temporaries.discard(intent.temporary_name)
            else:
                # A capture v2 intent is the durable authority for the
                # source -> outbox -> SQLite transaction.  Once the capture
                # marker records STAGING_INTENT_DURABLE, recovery must finish
                # that exact transaction instead of discarding its bytes.
                self._publish_without_overwrite(
                    intent.temporary_name,
                    intent.final_name,
                    outbox_descriptor,
                )
                protected_temporaries.discard(intent.temporary_name)
                os.fsync(outbox_descriptor)
                self._validate_named_artifact(
                    outbox_descriptor,
                    intent.final_name,
                    expected_size=cast(int, intent.manifest["size_bytes"]),
                    expected_sha256=str(intent.manifest["sha256"]),
                    control=control,
                )
                control.check()
                self.store.ensure_artifact_queued(
                    task_id=intent.task_id,
                    relative_path=intent.relative_path,
                    media_type=str(intent.manifest["media_type"]),
                    payload=intent.manifest,
                )
                control.check()
                intent_deletion = logical_quarantine(
                    intent.identity,
                    quarantine_prefix=".artifact-intent-quarantine-",
                )
                if not intent_deletion.logical_deletion_confirmed:
                    raise RuntimeError("artifact intent quarantine was not durable")
                assert intent_deletion.quarantine_name is not None
                self._record_quarantine(intent_deletion.quarantine_name, "artifact_intent")
        else:
            if intent.capture_authority is not None:
                raise RuntimeError("capture artifact intent has neither staged nor published bytes")
            control.check()
            intent_deletion = logical_quarantine(
                intent.identity,
                quarantine_prefix=".artifact-intent-quarantine-",
            )
            if not intent_deletion.logical_deletion_confirmed:
                raise RuntimeError("artifact intent quarantine was not durable")
            assert intent_deletion.quarantine_name is not None
            self._record_quarantine(intent_deletion.quarantine_name, "artifact_intent")

    def _reconcile_relevant_sync(
        self,
        control: _ReconciliationControl,
        *,
        artifact_id: str | None,
        execution_id: str | None,
    ) -> None:
        descriptors = self._open_managed_tree()
        _, _, outbox_descriptor, intent_descriptor = descriptors
        issues: list[str] = []
        protected_temporaries: set[str] = set()
        primary_error: BaseException | None = None
        try:
            with os.scandir(intent_descriptor) as entries:
                for entry in entries:
                    control.inspect_entry()
                    name = entry.name
                    if self._has_prefix(name, self._intent_quarantine_prefixes):
                        self._record_quarantine(name, "artifact_intent")
                        continue
                    try:
                        intent = self._read_intent(intent_descriptor, name, control)
                        if (
                            intent.artifact_id == artifact_id
                            or intent.manifest.get("execution_id") == execution_id
                        ):
                            self._reconcile_intent(
                                control,
                                outbox_descriptor,
                                intent_descriptor,
                                intent,
                                protected_temporaries,
                            )
                    except BaseException as error:
                        self._raise_if_reconciliation_stopped(error)
                        issues.append(f"{name}:{type(error).__name__}")

            if artifact_id is not None:
                control.inspect_entry()
                row = self.store.artifact_upload(artifact_id)
                if row is not None:
                    relative_value = str(row["relative_path"])
                    relative = Path(relative_value)
                    if not self._is_safe_outbox_relative(relative_value):
                        issues.append(f"{relative}:unsafe_sqlite_path")
                    elif not self._entry_exists(outbox_descriptor, relative.name):
                        issues.append(f"{relative}:sqlite_artifact_missing")
                    else:
                        try:
                            self._validate_named_artifact(
                                outbox_descriptor,
                                relative.name,
                                expected_size=int(row["size_bytes"]),
                                expected_sha256=str(row["sha256"]),
                                control=control,
                            )
                        except BaseException as error:
                            self._raise_if_reconciliation_stopped(error)
                            issues.append(f"{relative.name}:{type(error).__name__}")
            if issues:
                raise ArtifactReconciliationError(
                    "artifact reconciliation failed: " + ",".join(sorted(issues))
                )
        except BaseException as error:
            primary_error = error
            raise
        finally:
            self._close_descriptors(descriptors, primary_error=primary_error)

    def _reconcile_sync(self, control: _ReconciliationControl) -> None:
        descriptors = self._open_managed_tree()
        _, _, outbox_descriptor, intent_descriptor = descriptors
        prune_descriptor = self._open_prune_intent_directory(outbox_descriptor)
        active_descriptor = self._open_prune_active_directory(outbox_descriptor)
        retired_descriptor = self._open_prune_retired_directory(outbox_descriptor)
        conflicts_descriptor = self._open_prune_conflicts_directory(outbox_descriptor)
        issues: list[str] = []
        protected_temporaries: set[str] = set()
        primary_error: BaseException | None = None
        try:
            self._reconcile_prune_intents(
                self._prune_reconciliation_control(control),
                outbox_descriptor,
                prune_descriptor,
                active_descriptor,
                retired_descriptor,
                conflicts_descriptor,
            )
            with os.scandir(intent_descriptor) as entries:
                for entry in entries:
                    control.inspect_entry()
                    name = entry.name
                    if self._has_prefix(name, self._intent_quarantine_prefixes):
                        self._record_quarantine(name, "artifact_intent")
                        continue
                    try:
                        intent = self._read_intent(intent_descriptor, name, control)
                        self._reconcile_intent(
                            control,
                            outbox_descriptor,
                            intent_descriptor,
                            intent,
                            protected_temporaries,
                        )
                    except BaseException as error:
                        self._raise_if_reconciliation_stopped(error)
                        issues.append(f"{name}:{type(error).__name__}")

            remaining_entries = max(1, control.maximum_entries - control.entries + 1)
            rows = self.store.artifact_uploads(limit=min(10_000, remaining_entries))
            for _row in rows:
                control.inspect_entry()
            rows_by_path = {str(row["relative_path"]): row for row in rows}
            with os.scandir(outbox_descriptor) as entries:
                for entry in entries:
                    control.inspect_entry()
                    name = entry.name
                    if name in {
                        "intents",
                        "prune-intents",
                        "prune-active",
                        "prune-retired",
                        "prune-conflicts",
                    }:
                        continue
                    relative = f"outbox/{name}"
                    row = rows_by_path.get(relative)
                    if is_artifact_prune_quarantine_path(relative):
                        self._record_quarantine(name, "artifact_outbox")
                        if row is not None:
                            try:
                                self._validate_named_artifact(
                                    outbox_descriptor,
                                    name,
                                    expected_size=int(row["size_bytes"]),
                                    expected_sha256=str(row["sha256"]),
                                    control=control,
                                )
                            except BaseException as error:
                                self._raise_if_reconciliation_stopped(error)
                                issues.append(f"{name}:{type(error).__name__}")
                        continue
                    if self._has_prefix(name, self._outbox_quarantine_prefixes):
                        self._record_quarantine(name, "artifact_outbox")
                        if row is not None:
                            try:
                                self._validate_named_artifact(
                                    outbox_descriptor,
                                    name,
                                    expected_size=int(row["size_bytes"]),
                                    expected_sha256=str(row["sha256"]),
                                    control=control,
                                )
                            except BaseException as error:
                                self._raise_if_reconciliation_stopped(error)
                                issues.append(f"{name}:{type(error).__name__}")
                        continue
                    if name.startswith(".staging-"):
                        if name in protected_temporaries:
                            continue
                        try:
                            identity = self._validate_owned_regular(outbox_descriptor, name)
                            control.check()
                            deletion = logical_quarantine(
                                identity,
                                quarantine_prefix=".artifact-orphan-quarantine-",
                            )
                            if not deletion.logical_deletion_confirmed:
                                raise RuntimeError("artifact orphan quarantine was not durable")
                            assert deletion.quarantine_name is not None
                            self._record_quarantine(
                                deletion.quarantine_name,
                                "artifact_orphan",
                            )
                        except BaseException as error:
                            self._raise_if_reconciliation_stopped(error)
                            issues.append(f"{name}:{type(error).__name__}")
                        continue
                    if row is not None:
                        try:
                            self._validate_named_artifact(
                                outbox_descriptor,
                                name,
                                expected_size=int(row["size_bytes"]),
                                expected_sha256=str(row["sha256"]),
                                control=control,
                            )
                        except BaseException as error:
                            self._raise_if_reconciliation_stopped(error)
                            issues.append(f"{name}:{type(error).__name__}")
                    else:
                        issues.append(f"{name}:untracked_outbox_entry")

            for relative in rows_by_path:
                control.check()
                path = Path(relative)
                if not self._is_safe_outbox_relative(relative):
                    issues.append(f"{relative}:unsafe_sqlite_path")
                    continue
                if not self._entry_exists(outbox_descriptor, path.name):
                    issues.append(f"{relative}:sqlite_artifact_missing")
            if issues:
                raise ArtifactReconciliationError(
                    "artifact reconciliation failed: " + ",".join(sorted(issues))
                )
        except BaseException as error:
            primary_error = error
            raise
        finally:
            self._close_descriptors(
                (
                    conflicts_descriptor,
                    retired_descriptor,
                    active_descriptor,
                    prune_descriptor,
                    *descriptors,
                ),
                primary_error=primary_error,
            )

    def _reconcile_startup_sync(self, control: _ReconciliationControl) -> None:
        """Recover durable intents and audit only rows that still require upload work."""

        descriptors = self._open_managed_tree()
        _, _, outbox_descriptor, intent_descriptor = descriptors
        prune_descriptor = self._open_prune_intent_directory(outbox_descriptor)
        active_descriptor = self._open_prune_active_directory(outbox_descriptor)
        retired_descriptor = self._open_prune_retired_directory(outbox_descriptor)
        conflicts_descriptor = self._open_prune_conflicts_directory(outbox_descriptor)
        issues: list[str] = []
        protected_temporaries: set[str] = set()
        primary_error: BaseException | None = None
        try:
            prune_control = self._prune_reconciliation_control(control)
            try:
                prune_result = self._reconcile_prune_intents(
                    prune_control,
                    outbox_descriptor,
                    prune_descriptor,
                    active_descriptor,
                    retired_descriptor,
                    conflicts_descriptor,
                )
                if prune_result.has_more:
                    self._record_maintenance_issue(
                        "prune_journal:reconciliation_deferred:operation_limit"
                    )
            except _ReconciliationLimitExceeded as error:
                self._record_maintenance_issue(
                    f"prune_journal:reconciliation_deferred:{type(error).__name__}"
                )
            with os.scandir(intent_descriptor) as entries:
                for entry in entries:
                    control.inspect_entry()
                    if self._has_prefix(entry.name, self._intent_quarantine_prefixes):
                        self._record_quarantine(entry.name, "artifact_intent")
                        continue
                    try:
                        intent = self._read_intent(intent_descriptor, entry.name, control)
                        self._reconcile_intent(
                            control,
                            outbox_descriptor,
                            intent_descriptor,
                            intent,
                            protected_temporaries,
                        )
                    except BaseException as error:
                        self._raise_if_reconciliation_stopped(error)
                        issues.append(f"{entry.name}:{type(error).__name__}")

            remaining_entries = max(1, control.maximum_entries - control.entries)
            active_states = frozenset({"pending", "in_flight", "failed"})
            control.check()
            if self.store.artifact_upload_count(states=active_states) > remaining_entries:
                raise _ReconciliationLimitExceeded(
                    "artifact startup reconciliation entry limit exceeded"
                )
            control.check()
            rows = self.store.artifact_uploads(
                states=active_states,
                limit=min(10_000, remaining_entries),
            )
            for row in rows:
                control.inspect_entry()
                relative_value = str(row["relative_path"])
                relative = Path(relative_value)
                if not self._is_safe_outbox_relative(relative_value):
                    issues.append(f"{relative}:unsafe_sqlite_path")
                    continue
                if not self._entry_exists(outbox_descriptor, relative.name):
                    issues.append(f"{relative}:sqlite_artifact_missing")
                    continue
                try:
                    self._validate_named_artifact(
                        outbox_descriptor,
                        relative.name,
                        expected_size=int(row["size_bytes"]),
                        expected_sha256=str(row["sha256"]),
                        control=control,
                    )
                except BaseException as error:
                    self._raise_if_reconciliation_stopped(error)
                    issues.append(f"{relative.name}:{type(error).__name__}")
            if issues:
                raise ArtifactReconciliationError(
                    "artifact startup reconciliation failed: " + ",".join(sorted(issues))
                )
        except BaseException as error:
            primary_error = error
            raise
        finally:
            self._close_descriptors(
                (
                    conflicts_descriptor,
                    retired_descriptor,
                    active_descriptor,
                    prune_descriptor,
                    *descriptors,
                ),
                primary_error=primary_error,
            )

    def _validate_upload_row(
        self,
        row: dict[str, Any],
        *,
        control: _ReconciliationControl | None = None,
    ) -> Path:
        relative_value = str(row["relative_path"])
        relative = Path(relative_value)
        if not self._is_safe_outbox_relative(relative_value):
            raise ValueError("queued artifact path is unsafe")
        descriptors = self._open_managed_tree()
        primary_error: BaseException | None = None
        try:
            self._validate_named_artifact(
                descriptors[2],
                relative.name,
                expected_size=int(row["size_bytes"]),
                expected_sha256=str(row["sha256"]),
                control=control,
            )
        except BaseException as error:
            primary_error = error
            raise
        finally:
            self._close_descriptors(
                tuple(reversed(descriptors)),
                primary_error=primary_error,
            )
        self._validate_row_payload(row)
        return self.artifact_root / relative

    @staticmethod
    def _validate_row_payload(row: dict[str, Any]) -> dict[str, object]:
        payload = json.loads(str(row["payload"]))
        if (
            not isinstance(payload, dict)
            or int(payload.get("size_bytes", -1)) != int(row["size_bytes"])
            or str(payload.get("sha256")) != str(row["sha256"])
        ):
            raise RuntimeError("queued artifact manifest is inconsistent")
        validate_contract("artifact-manifest.schema.json", payload)
        return cast(dict[str, object], payload)

    def _validate_named_artifact(
        self,
        directory_descriptor: int,
        name: str,
        *,
        expected_size: int,
        expected_sha256: str,
        control: _ReconciliationControl | None = None,
    ) -> FileIdentity:
        descriptor = os.open(name, self._read_flags(), dir_fd=directory_descriptor)
        primary_error: BaseException | None = None
        identity: FileIdentity | None = None
        try:
            metadata = os.fstat(descriptor)
            self._validate_private_file(metadata, self._final_mode)
            identity = capture_file_identity(
                directory_descriptor,
                name,
                descriptor,
                expected_uid=self._effective_uid(metadata),
                expected_mode=self._final_mode,
            )
            if metadata.st_size != expected_size:
                raise RuntimeError("queued artifact size changed")
            digest, size = self._hash_descriptor(descriptor, control=control)
            if size != expected_size or digest != expected_sha256:
                raise RuntimeError("queued artifact integrity changed")
            after = os.fstat(descriptor)
            if self._source_fingerprint(metadata) != self._source_fingerprint(after):
                raise RuntimeError("queued artifact changed during validation")
        except BaseException as error:
            primary_error = error
            raise
        finally:
            self._close_descriptors((descriptor,), primary_error=primary_error)
        if identity is None:
            raise RuntimeError("queued artifact identity is unavailable")
        return identity

    def _open_source(self, source: Path, artifact_descriptor: int) -> int:
        if source.parent != self.artifact_root or source.name in {"", ".", ".."}:
            raise ValueError("artifact escaped the configured root")
        try:
            return os.open(source.name, self._read_flags(), dir_fd=artifact_descriptor)
        except OSError as error:
            raise ValueError("artifact source could not be opened safely") from error

    @staticmethod
    def _validate_source(metadata: os.stat_result, maximum_size_bytes: int) -> None:
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("artifact source is not a regular file")
        if metadata.st_nlink != 1:
            raise PermissionError("artifact source must have exactly one hard link")
        if metadata.st_size <= 0 or metadata.st_size > maximum_size_bytes:
            raise RuntimeError("artifact size limit was violated")
        if metadata.st_uid != SQLiteArtifactStager._effective_uid(metadata):
            raise PermissionError("artifact source owner does not match the service account")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise PermissionError("artifact source has group/world permissions")

    @staticmethod
    def _source_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    def _before_commit(self, transaction: _StagingTransaction) -> None:
        del transaction

    def _after_publish(self, intent: _ArtifactIntent) -> None:
        del intent

    def _after_queue(self, intent: _ArtifactIntent) -> None:
        del intent

    def _after_prune_prepared(self, operation: _PruneOperation) -> None:
        del operation

    def _after_prune_quarantine(self, operation: _PruneOperation) -> None:
        del operation

    def _after_prune_sqlite_update(self, operation: _PruneOperation) -> None:
        del operation

    def _before_prune_event_open(self, candidate: _PruneEventCandidate) -> None:
        del candidate

    def _after_prune_event_open(
        self,
        candidate: _PruneEventCandidate,
        descriptor: int,
    ) -> None:
        del candidate, descriptor

    def _after_prune_events_parsed(self, events: tuple[_OpenPruneEvent, ...]) -> None:
        del events

    def _before_prune_active_open(self, candidate: _PruneActiveCandidate) -> None:
        del candidate

    def _after_prune_active_open(
        self,
        candidate: _PruneActiveCandidate,
        descriptor: int,
    ) -> None:
        del candidate, descriptor

    def _after_prune_active_parsed(self, active: _OpenPruneActive) -> None:
        del active

    def _after_prune_operation_reconciled(self, operation_id: str) -> None:
        del operation_id

    def _after_chunk(self, copied: int) -> None:
        del copied

    @staticmethod
    def _publish_without_overwrite(
        temporary: str,
        final: str,
        directory_descriptor: int,
    ) -> None:
        try:
            rename_noreplace(
                directory_descriptor,
                temporary,
                directory_descriptor,
                final,
            )
        except SecureFilesystemUnavailableError as error:
            raise PluginUnavailableError(
                "safe artifact publication requires renameat2(RENAME_NOREPLACE)"
            ) from error

    def _open_managed_tree(self) -> tuple[int, int, int, int]:
        trusted = self._open_directory_path(self.trusted_root, self._trusted_root_identity)
        current = trusted
        owned: list[int] = [trusted]
        try:
            for name, identity in self._managed_components:
                child = self._open_private_child(current, name, identity)
                owned.append(child)
                current = child
            if self._managed_components:
                artifact = current
            else:
                artifact = os.dup(trusted)
                owned.append(artifact)
            if self._identity(os.fstat(artifact)) != self._artifact_root_identity:
                raise PermissionError("artifact root identity changed")
            outbox = self._open_private_child(artifact, "outbox", self._outbox_root_identity)
            owned.append(outbox)
            intents = self._open_private_child(outbox, "intents", self._intent_root_identity)
            owned.append(intents)
            keep = {trusted, artifact, outbox, intents}
            for descriptor in tuple(owned):
                if descriptor not in keep:
                    owned.remove(descriptor)
                    self._close_descriptors((descriptor,))
            return trusted, artifact, outbox, intents
        except BaseException as error:
            self._close_descriptors(
                list(reversed(owned)),
                primary_error=error,
            )
            raise

    def _open_prune_intent_directory(self, outbox_descriptor: int) -> int:
        return self._open_private_child(
            outbox_descriptor,
            "prune-intents",
            self._prune_intent_root_identity,
        )

    def _open_prune_active_directory(self, outbox_descriptor: int) -> int:
        return self._open_private_child(
            outbox_descriptor,
            "prune-active",
            self._prune_active_root_identity,
        )

    def _open_prune_retired_directory(self, outbox_descriptor: int) -> int:
        return self._open_private_child(
            outbox_descriptor,
            "prune-retired",
            self._prune_retired_root_identity,
        )

    def _open_prune_conflicts_directory(self, outbox_descriptor: int) -> int:
        return self._open_private_child(
            outbox_descriptor,
            "prune-conflicts",
            self._prune_conflicts_root_identity,
        )

    def _open_trusted_root(self, path: Path) -> int:
        metadata = path.lstat()
        self._validate_directory_metadata(metadata)
        return self._open_directory_path(path, self._identity(metadata))

    def _ensure_managed_path(
        self,
        trusted_descriptor: int,
        parts: tuple[str, ...],
    ) -> tuple[int, list[tuple[str, tuple[int, int]]]]:
        parent = trusted_descriptor
        opened: list[int] = []
        components: list[tuple[str, tuple[int, int]]] = []
        primary_error: BaseException | None = None
        try:
            if not parts:
                return os.dup(trusted_descriptor), components
            for name in parts:
                descriptor = self._ensure_private_child(parent, name)
                identity = self._identity(os.fstat(descriptor))
                components.append((name, identity))
                opened.append(descriptor)
                parent = descriptor
            result = opened.pop()
            return result, components
        except BaseException as error:
            primary_error = error
            raise
        finally:
            self._close_descriptors(
                list(reversed(opened)),
                primary_error=primary_error,
            )

    def _ensure_private_child(self, parent_descriptor: int, name: str) -> int:
        if name in {"", ".", ".."} or "/" in name:
            raise ValueError("artifact directory component is unsafe")
        try:
            os.mkdir(name, self._directory_mode, dir_fd=parent_descriptor)
        except FileExistsError:
            pass
        descriptor = os.open(name, self._directory_flags(), dir_fd=parent_descriptor)
        try:
            metadata = os.fstat(descriptor)
            if metadata.st_uid != self._effective_uid(metadata):
                raise PermissionError("artifact directory owner does not match service account")
            self._set_descriptor_mode(descriptor, self._directory_mode)
            self._validate_directory_metadata(os.fstat(descriptor))
            return descriptor
        except BaseException as error:
            self._close_descriptors((descriptor,), primary_error=error)
            raise

    def _open_private_child(
        self,
        parent_descriptor: int,
        name: str,
        expected_identity: tuple[int, int],
    ) -> int:
        descriptor = os.open(name, self._directory_flags(), dir_fd=parent_descriptor)
        try:
            metadata = os.fstat(descriptor)
            self._validate_directory_metadata(metadata)
            if self._identity(metadata) != expected_identity:
                raise PermissionError("artifact directory identity changed")
            return descriptor
        except BaseException as error:
            self._close_descriptors((descriptor,), primary_error=error)
            raise

    def _open_directory_path(self, path: Path, expected_identity: tuple[int, int]) -> int:
        descriptor = os.open(path, self._directory_flags())
        try:
            metadata = os.fstat(descriptor)
            self._validate_directory_metadata(metadata)
            if self._identity(metadata) != expected_identity:
                raise PermissionError("trusted artifact root identity changed")
            return descriptor
        except BaseException as error:
            self._close_descriptors((descriptor,), primary_error=error)
            raise

    @classmethod
    def _validate_directory_metadata(cls, metadata: os.stat_result) -> None:
        if not stat.S_ISDIR(metadata.st_mode) or cls._is_reparse(metadata):
            raise PermissionError("artifact directory is not a plain directory")
        if metadata.st_uid != cls._effective_uid(metadata):
            raise PermissionError("artifact directory owner does not match service account")
        if stat.S_IMODE(metadata.st_mode) != cls._directory_mode:
            raise PermissionError("artifact directory must have mode 0700")

    @classmethod
    def _validate_private_file(cls, metadata: os.stat_result, expected_mode: int) -> None:
        if not stat.S_ISREG(metadata.st_mode) or cls._is_reparse(metadata):
            raise PermissionError("artifact object is not a regular file")
        if metadata.st_uid != cls._effective_uid(metadata):
            raise PermissionError("artifact object owner does not match service account")
        if metadata.st_nlink != 1:
            raise PermissionError("artifact object must have one hard link")
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise PermissionError("artifact object mode is invalid")

    def _validate_owned_regular(self, directory_descriptor: int, name: str) -> FileIdentity:
        descriptor = os.open(name, self._read_flags(), dir_fd=directory_descriptor)
        primary_error: BaseException | None = None
        identity: FileIdentity | None = None
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or self._is_reparse(metadata):
                raise PermissionError("untracked artifact is not a regular file")
            if metadata.st_uid != self._effective_uid(metadata) or metadata.st_nlink != 1:
                raise PermissionError("untracked artifact ownership is invalid")
            identity = capture_file_identity(
                directory_descriptor,
                name,
                descriptor,
                expected_uid=self._effective_uid(metadata),
                expected_mode=stat.S_IMODE(metadata.st_mode),
            )
        except BaseException as error:
            primary_error = error
            raise
        finally:
            self._close_descriptors((descriptor,), primary_error=primary_error)
        if identity is None:
            raise RuntimeError("untracked artifact identity is unavailable")
        return identity

    def _hash_descriptor(
        self,
        descriptor: int,
        *,
        control: _ReconciliationControl | None = None,
    ) -> tuple[str, int]:
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        size = 0
        while True:
            if control is not None:
                control.check()
            chunk = os.read(descriptor, SQLiteArtifactStager._chunk_size)
            if not chunk:
                break
            if control is not None:
                control.inspect_bytes(len(chunk))
                self._after_reconciliation_chunk(control, size + len(chunk))
            digest.update(chunk)
            size += len(chunk)
        return digest.hexdigest(), size

    def _after_reconciliation_chunk(
        self,
        control: _ReconciliationControl,
        bytes_inspected: int,
    ) -> None:
        del control, bytes_inspected

    @staticmethod
    def _read_exact_file(descriptor: int, size: int) -> bytes:
        result = bytearray()
        while len(result) < size:
            chunk = os.read(descriptor, size - len(result))
            if not chunk:
                raise EOFError("artifact intent was truncated")
            result.extend(chunk)
        return bytes(result)

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("artifact write made no progress")
            view = view[written:]

    @staticmethod
    def _set_descriptor_mode(descriptor: int, mode: int) -> None:
        if _FCHMOD is None:
            raise RuntimeError("descriptor-anchored mode changes are unavailable")
        _FCHMOD(descriptor, mode)

    def _close_descriptor(self, descriptor: int) -> None:
        os.close(descriptor)

    def _close_descriptors(
        self,
        descriptors: tuple[int | None, ...] | list[int | None],
        *,
        primary_error: BaseException | None = None,
    ) -> None:
        errors: list[BaseException] = []
        closed: set[int] = set()
        for descriptor in descriptors:
            if descriptor is None or descriptor in closed:
                continue
            closed.add(descriptor)
            try:
                self._close_descriptor(descriptor)
            except BaseException as close_error:
                errors.append(close_error)
        if not errors:
            return
        if primary_error is not None:
            for secondary_close in errors:
                primary_error.add_note(
                    f"artifact descriptor close also failed: {secondary_close!r}"
                )
            return
        for secondary in errors[1:]:
            errors[0].add_note(f"additional artifact descriptor close error: {secondary!r}")
        raise errors[0]

    @staticmethod
    def _entry_exists(directory_descriptor: int, name: str) -> bool:
        try:
            os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    @staticmethod
    def _identity(metadata: os.stat_result) -> tuple[int, int]:
        return metadata.st_dev, metadata.st_ino

    @classmethod
    def _is_reparse(cls, metadata: os.stat_result) -> bool:
        return bool(int(getattr(metadata, "st_file_attributes", 0)) & cls._reparse_point)

    @staticmethod
    def _effective_uid(metadata: os.stat_result) -> int:
        getter = getattr(os, "geteuid", None)
        return int(getter()) if getter is not None else int(metadata.st_uid)

    @staticmethod
    def _directory_flags() -> int:
        return (
            os.O_RDONLY
            | int(getattr(os, "O_DIRECTORY", 0))
            | int(getattr(os, "O_CLOEXEC", 0))
            | int(getattr(os, "O_NOFOLLOW", 0))
        )

    @staticmethod
    def _read_flags() -> int:
        return os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))

    @staticmethod
    def _write_flags() -> int:
        return (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | int(getattr(os, "O_CLOEXEC", 0))
            | int(getattr(os, "O_NOFOLLOW", 0))
        )
