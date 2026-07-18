from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from wto_desktop_agent.platforms.linux.secure_fs import (
    FileIdentity,
    capture_file_identity,
    close_descriptor,
    logical_quarantine,
    rename_noreplace,
)

_MARKER_SCHEMA_VERSION = 1
_BINDING_SCHEMA_VERSION = 1
_MAXIMUM_MARKER_BYTES = 4 * 1024 * 1024
_MAXIMUM_BINDING_BYTES = 2 * 1024 * 1024
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-" r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
_MARKER_NAME = re.compile(rf"^(?P<idempotency>{_UUID})\.jsonl$")
_BINDING_NAME = re.compile(rf"^(?P<idempotency>{_UUID})\.json$")
_MARKER_RETIRED_NAME = re.compile(r"^\.capture-marker-retired-[0-9a-f]{64}$")
_BINDING_TEMPORARY_NAME = re.compile(
    rf"^\.(?P<idempotency>{_UUID})\.pending\.(?P<nonce>[0-9a-f]{{48}})$"
)
_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CaptureRecoveryError(RuntimeError):
    pass


class CaptureInProgressError(CaptureRecoveryError):
    pass


class CaptureIdempotencyConflict(CaptureRecoveryError):
    pass


class CaptureManualRecoveryRequired(CaptureRecoveryError):
    pass


class CaptureMarkerState(str, Enum):
    RESERVATION_PLANNED = "RESERVATION_PLANNED"
    RESERVED = "RESERVED"
    CAPTURE_COMPLETE = "CAPTURE_COMPLETE"
    ROLLBACK_VERIFICATION_PENDING = "ROLLBACK_VERIFICATION_PENDING"
    INTERFACE_RESTORED = "INTERFACE_RESTORED"
    STAGING_INTENT_DURABLE = "STAGING_INTENT_DURABLE"
    LOCAL_ARTIFACT_COMMITTED = "LOCAL_ARTIFACT_COMMITTED"
    BINDING_PUBLISHED = "BINDING_PUBLISHED"
    RETIRED = "RETIRED"


_SUCCESSOR = {
    CaptureMarkerState.RESERVATION_PLANNED: CaptureMarkerState.RESERVED,
    CaptureMarkerState.RESERVED: CaptureMarkerState.CAPTURE_COMPLETE,
    CaptureMarkerState.CAPTURE_COMPLETE: CaptureMarkerState.ROLLBACK_VERIFICATION_PENDING,
    CaptureMarkerState.ROLLBACK_VERIFICATION_PENDING: CaptureMarkerState.INTERFACE_RESTORED,
    CaptureMarkerState.INTERFACE_RESTORED: CaptureMarkerState.STAGING_INTENT_DURABLE,
    CaptureMarkerState.STAGING_INTENT_DURABLE: CaptureMarkerState.LOCAL_ARTIFACT_COMMITTED,
    CaptureMarkerState.LOCAL_ARTIFACT_COMMITTED: CaptureMarkerState.BINDING_PUBLISHED,
    CaptureMarkerState.BINDING_PUBLISHED: CaptureMarkerState.RETIRED,
}

_DETAIL_FIELDS: dict[CaptureMarkerState, frozenset[str]] = {
    CaptureMarkerState.RESERVATION_PLANNED: frozenset(
        {
            "request",
            "source_name",
            "capture_format",
            "artifact_root",
            "artifact_root_dev",
            "artifact_root_ino",
        }
    ),
    CaptureMarkerState.RESERVED: frozenset(
        {
            "directory_dev",
            "directory_ino",
            "st_dev",
            "st_ino",
            "st_uid",
            "file_type",
            "mode",
            "st_nlink",
        }
    ),
    CaptureMarkerState.CAPTURE_COMPLETE: frozenset(
        {"size_bytes", "sha256", "st_mtime_ns", "st_ctime_ns", "started_at"}
    ),
    CaptureMarkerState.ROLLBACK_VERIFICATION_PENDING: frozenset({"rollback"}),
    CaptureMarkerState.INTERFACE_RESTORED: frozenset({"rollback", "metadata"}),
    CaptureMarkerState.STAGING_INTENT_DURABLE: frozenset(
        {"intent_name", "source_st_dev", "source_st_ino", "source_sha256"}
    ),
    CaptureMarkerState.LOCAL_ARTIFACT_COMMITTED: frozenset(
        {"artifact_path", "artifact_relative_path", "manifest", "metadata", "rollback"}
    ),
    CaptureMarkerState.BINDING_PUBLISHED: frozenset({"binding_name"}),
    CaptureMarkerState.RETIRED: frozenset(
        {"reason", "source_quarantine_name", "marker_quarantine_name"}
    ),
}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return int(metadata.st_dev), int(metadata.st_ino)


def _effective_uid(metadata: os.stat_result) -> int:
    getter = getattr(os, "geteuid", None)
    return int(getter()) if getter is not None else int(metadata.st_uid)


def _required_int(value: object, *, label: str) -> int:
    if type(value) is not int:
        raise CaptureManualRecoveryRequired(f"{label} is invalid")
    return value


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | int(getattr(os, "O_DIRECTORY", 0))
        | int(getattr(os, "O_CLOEXEC", 0))
        | int(getattr(os, "O_NOFOLLOW", 0))
    )


def _read_flags() -> int:
    return os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))


def _read_write_flags() -> int:
    return os.O_RDWR | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))


def _validate_directory(metadata: os.stat_result, *, label: str) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise PermissionError(f"{label} is not a directory")
    if int(metadata.st_uid) != _effective_uid(metadata):
        raise PermissionError(f"{label} owner does not match the service account")
    if stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE:
        raise PermissionError(f"{label} must have mode 0700")


def _ensure_private_child(parent_descriptor: int, name: str) -> int:
    if name in {"", ".", ".."} or "/" in name:
        raise ValueError("capture recovery directory name is unsafe")
    try:
        os.mkdir(name, _PRIVATE_DIRECTORY_MODE, dir_fd=parent_descriptor)
    except FileExistsError:
        pass
    return _open_private_child(parent_descriptor, name)


def _open_private_child(parent_descriptor: int, name: str) -> int:
    """Open an existing private child without creating filesystem state."""

    if name in {"", ".", ".."} or "/" in name:
        raise ValueError("capture recovery directory name is unsafe")
    descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
    try:
        metadata = os.fstat(descriptor)
        _validate_directory(metadata, label=f"capture recovery {name} directory")
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if _identity(metadata) != _identity(named):
            raise PermissionError("capture recovery directory name changed")
        return descriptor
    except BaseException as error:
        close_descriptor(descriptor, primary_error=error, context="capture recovery directory")
        raise


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("capture recovery write made no progress")
        view = view[written:]


def _lock_exclusive(descriptor: int, *, blocking: bool) -> None:
    if os.name != "posix":
        return
    fcntl = cast(Any, __import__("fcntl"))
    operation = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
    try:
        fcntl.flock(descriptor, operation)
    except BlockingIOError as error:
        raise CaptureInProgressError("capture operation is already active") from error


@dataclass(frozen=True)
class CaptureFingerprint:
    version: str
    sha256: str

    def __post_init__(self) -> None:
        if not self.version or _SHA256.fullmatch(self.sha256) is None:
            raise ValueError("capture fingerprint is invalid")


@dataclass(frozen=True)
class CaptureAuthority:
    task_id: str
    execution_id: str
    idempotency_key: str
    fingerprint: CaptureFingerprint
    operation_token: str

    def __post_init__(self) -> None:
        for value in (self.task_id, self.execution_id, self.idempotency_key):
            if str(UUID(value)) != value:
                raise ValueError("capture authority UUID is not canonical")
        if _HEX_32.fullmatch(self.operation_token) is None:
            raise ValueError("capture operation token is invalid")

    def intent_payload(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "execution_id": self.execution_id,
            "idempotency_key": self.idempotency_key,
            "fingerprint_version": self.fingerprint.version,
            "fingerprint_sha256": self.fingerprint.sha256,
            "operation_token": self.operation_token,
        }


@dataclass(frozen=True)
class CaptureMarkerSnapshot:
    authority: CaptureAuthority
    state: CaptureMarkerState
    sequence: int
    event_digest: str
    details: dict[CaptureMarkerState, dict[str, object]]

    @property
    def planned(self) -> dict[str, object]:
        return self.details[CaptureMarkerState.RESERVATION_PLANNED]

    def detail(self, state: CaptureMarkerState) -> dict[str, object] | None:
        return self.details.get(state)


@dataclass(frozen=True)
class CaptureBinding:
    authority: CaptureAuthority
    artifact_root: str
    artifact_root_dev: int
    artifact_root_ino: int
    artifact_path: str
    artifact_relative_path: str
    artifact_st_dev: int
    artifact_st_ino: int
    artifact_st_uid: int
    artifact_mode: int
    artifact_st_nlink: int
    manifest: dict[str, object]
    metadata: dict[str, object]
    rollback: dict[str, object]
    status: str
    reason: str | None
    binding_name: str


class CaptureMarker:
    def __init__(
        self,
        *,
        descriptor: int,
        root_descriptor: int,
        identity: FileIdentity,
        snapshot: CaptureMarkerSnapshot,
    ) -> None:
        self.descriptor = descriptor
        self.root_descriptor = root_descriptor
        self.identity = identity
        self.snapshot = snapshot
        self.closed = False

    def _validate_open_identity(self) -> None:
        if self.closed:
            raise CaptureRecoveryError("capture marker is closed")
        metadata = os.fstat(self.descriptor)
        if not self.identity.matches_with_size(metadata):
            raise CaptureManualRecoveryRequired("capture marker inode changed")
        current = capture_file_identity(
            self.root_descriptor,
            self.identity.relative_name,
            self.descriptor,
            expected_uid=self.identity.st_uid,
            expected_mode=_PRIVATE_FILE_MODE,
        )
        if current != self.identity:
            raise CaptureManualRecoveryRequired("capture marker name changed")

    def advance(
        self,
        state: CaptureMarkerState,
        details: dict[str, object],
    ) -> None:
        expected = _SUCCESSOR.get(self.snapshot.state)
        if expected is not state:
            raise CaptureRecoveryError(
                f"capture marker transition {self.snapshot.state.value}->{state.value} is invalid"
            )
        self._append(state, details)

    def note_intent_durable(self, details: dict[str, object]) -> None:
        if self.snapshot.state is CaptureMarkerState.STAGING_INTENT_DURABLE:
            persisted = self.snapshot.detail(CaptureMarkerState.STAGING_INTENT_DURABLE)
            if persisted != details:
                raise CaptureManualRecoveryRequired(
                    "artifact intent authority differs from the capture marker"
                )
            return
        self.advance(CaptureMarkerState.STAGING_INTENT_DURABLE, details)

    def note_rollback_verification(self, rollback: dict[str, object]) -> None:
        details: dict[str, object] = {"rollback": rollback}
        if self.snapshot.state is CaptureMarkerState.CAPTURE_COMPLETE:
            self.advance(CaptureMarkerState.ROLLBACK_VERIFICATION_PENDING, details)
            return
        if self.snapshot.state is CaptureMarkerState.RESERVED:
            # A capture may fail (or the process may die) after the interface
            # journal is durable but before CAPTURE_COMPLETE.  Persist rollback
            # progress on the same marker so recovery never has to repeat a
            # mutator whose successful return was already checkpointed.
            self._append(CaptureMarkerState.ROLLBACK_VERIFICATION_PENDING, details)
            return
        if self.snapshot.state is not CaptureMarkerState.ROLLBACK_VERIFICATION_PENDING:
            raise CaptureRecoveryError("capture marker is not awaiting rollback verification")
        self._append(CaptureMarkerState.ROLLBACK_VERIFICATION_PENDING, details)

    def _append(self, state: CaptureMarkerState, details: dict[str, object]) -> None:
        if set(details) != _DETAIL_FIELDS[state]:
            raise ValueError(f"capture marker {state.value} details are invalid")
        self._validate_open_identity()
        authority = self.snapshot.authority
        event = {
            "version": _MARKER_SCHEMA_VERSION,
            "sequence": self.snapshot.sequence + 1,
            "state": state.value,
            "previous_digest": self.snapshot.event_digest,
            "recorded_at": _utc_now(),
            "task_id": authority.task_id,
            "execution_id": authority.execution_id,
            "idempotency_key": authority.idempotency_key,
            "fingerprint_version": authority.fingerprint.version,
            "fingerprint_sha256": authority.fingerprint.sha256,
            "operation_token": authority.operation_token,
            "details": details,
        }
        encoded = _canonical_json(event) + b"\n"
        current_size = int(os.fstat(self.descriptor).st_size)
        if current_size + len(encoded) > _MAXIMUM_MARKER_BYTES:
            raise CaptureRecoveryError("capture marker exceeds its size limit")
        os.lseek(self.descriptor, 0, os.SEEK_END)
        _write_all(self.descriptor, encoded)
        os.fsync(self.descriptor)
        refreshed = capture_file_identity(
            self.root_descriptor,
            self.identity.relative_name,
            self.descriptor,
            expected_uid=self.identity.st_uid,
            expected_mode=_PRIVATE_FILE_MODE,
        )
        self.identity = refreshed
        event_digest = hashlib.sha256(encoded[:-1]).hexdigest()
        updated = dict(self.snapshot.details)
        updated[state] = dict(details)
        self.snapshot = CaptureMarkerSnapshot(
            authority=authority,
            state=state,
            sequence=self.snapshot.sequence + 1,
            event_digest=event_digest,
            details=updated,
        )

    def retire(
        self,
        *,
        reason: str,
        source_quarantine_name: str | None,
    ) -> None:
        if self.snapshot.state is not CaptureMarkerState.BINDING_PUBLISHED:
            raise CaptureRecoveryError("successful capture marker cannot retire before binding")
        self._logical_retire(
            reason=reason,
            source_quarantine_name=source_quarantine_name,
        )

    def retire_aborted(
        self,
        *,
        reason: str,
        source_quarantine_name: str | None,
    ) -> None:
        if self.snapshot.state is CaptureMarkerState.RETIRED:
            return
        self._logical_retire(
            reason=reason,
            source_quarantine_name=source_quarantine_name,
        )

    def _logical_retire(
        self,
        *,
        reason: str,
        source_quarantine_name: str | None,
    ) -> None:
        self._validate_open_identity()
        outcome = logical_quarantine(
            self.identity,
            quarantine_prefix=".capture-marker-retired-",
        )
        if not outcome.logical_deletion_confirmed or outcome.quarantine_name is None:
            raise CaptureManualRecoveryRequired("capture marker retirement was not durable")
        if _MARKER_RETIRED_NAME.fullmatch(outcome.quarantine_name) is None:
            raise CaptureManualRecoveryRequired("capture marker retired name is invalid")
        self.identity = replace(self.identity, relative_name=outcome.quarantine_name)
        expected = _SUCCESSOR.get(self.snapshot.state)
        if expected is CaptureMarkerState.RETIRED:
            self.advance(
                CaptureMarkerState.RETIRED,
                {
                    "reason": reason,
                    "source_quarantine_name": source_quarantine_name,
                    "marker_quarantine_name": outcome.quarantine_name,
                },
            )
        else:
            self._append(
                CaptureMarkerState.RETIRED,
                {
                    "reason": reason,
                    "source_quarantine_name": source_quarantine_name,
                    "marker_quarantine_name": outcome.quarantine_name,
                },
            )
        os.fsync(self.root_descriptor)

    def close(self, *, primary_error: BaseException | None = None) -> None:
        if self.closed:
            return
        self.closed = True
        close_descriptor(
            self.descriptor,
            primary_error=primary_error,
            context="capture marker",
        )


class CaptureOperationLock:
    def __init__(self, descriptor: int) -> None:
        self.descriptor = descriptor
        self.closed = False

    def close(self, *, primary_error: BaseException | None = None) -> None:
        if self.closed:
            return
        self.closed = True
        close_descriptor(
            self.descriptor,
            primary_error=primary_error,
            context="capture idempotency lock",
        )


class CaptureRecoveryStore:
    def __init__(
        self,
        state_dir: Path,
        artifact_root: Path,
        *,
        reuse_only: bool = False,
    ) -> None:
        if os.name != "posix":
            raise RuntimeError("capture recovery requires POSIX descriptor semantics")
        if not state_dir.is_absolute() or not artifact_root.is_absolute():
            raise ValueError("capture recovery roots must be absolute")
        self.closed = False
        self._marker_descriptor = -1
        self._binding_descriptor = -1
        self._lock_descriptor = -1
        self._artifact_descriptor = -1
        self._reuse_only = reuse_only
        self.state_dir = state_dir.absolute()
        self.artifact_root = artifact_root.absolute()
        self.artifact_root_identity = (0, 0)
        state_descriptor = os.open(self.state_dir, _directory_flags())
        primary: BaseException | None = None
        try:
            state_metadata = os.fstat(state_descriptor)
            _validate_directory(state_metadata, label="capture state directory")
            named_state = self.state_dir.lstat()
            if _identity(state_metadata) != _identity(named_state):
                raise PermissionError("capture state directory identity changed")
            if reuse_only:
                try:
                    self._binding_descriptor = _open_private_child(
                        state_descriptor, "capture-bindings"
                    )
                except FileNotFoundError:
                    self._binding_descriptor = -1
                try:
                    self._lock_descriptor = _open_private_child(state_descriptor, "capture-locks")
                except FileNotFoundError:
                    self._lock_descriptor = -1
            else:
                self._marker_descriptor = _ensure_private_child(state_descriptor, "capture-markers")
                self._binding_descriptor = _ensure_private_child(
                    state_descriptor, "capture-bindings"
                )
                self._lock_descriptor = _ensure_private_child(state_descriptor, "capture-locks")
        except BaseException as error:
            primary = error
            for descriptor, context in (
                (self._lock_descriptor, "capture lock directory"),
                (self._binding_descriptor, "capture binding directory"),
                (self._marker_descriptor, "capture marker directory"),
            ):
                if descriptor >= 0:
                    close_descriptor(descriptor, primary_error=error, context=context)
            raise
        finally:
            close_descriptor(
                state_descriptor,
                primary_error=primary,
                context="capture state directory",
            )
        if not reuse_only:
            self._open_artifact_root()

    def _open_artifact_root(self) -> None:
        if self._artifact_descriptor >= 0:
            return
        self._artifact_descriptor = os.open(self.artifact_root, _directory_flags())
        try:
            artifact_metadata = os.fstat(self._artifact_descriptor)
            _validate_directory(artifact_metadata, label="capture artifact root")
            named = self.artifact_root.lstat()
            if _identity(artifact_metadata) != _identity(named):
                raise PermissionError("capture artifact root identity changed")
            self.artifact_root_identity = _identity(artifact_metadata)
        except BaseException as error:
            close_descriptor(
                self._artifact_descriptor,
                primary_error=error,
                context="capture artifact root",
            )
            self._artifact_descriptor = -1
            self.close(primary_error=error)
            raise

    def binding_exists(self, idempotency_key: UUID | str) -> bool:
        """Check only the binding name; content is validated under its operation lock."""

        if self._binding_descriptor < 0:
            return False
        name = self.binding_name(idempotency_key)
        try:
            os.stat(name, dir_fd=self._binding_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True

    def operation_lock_exists(self, idempotency_key: UUID | str) -> bool:
        """Check whether an operation already owns durable idempotency state."""

        if self._lock_descriptor < 0:
            return False
        value = str(idempotency_key)
        if str(UUID(value)) != value:
            raise ValueError("capture lock idempotency key is invalid")
        try:
            os.stat(
                f"{value}.lock",
                dir_fd=self._lock_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False
        return True

    @property
    def marker_root_descriptor(self) -> int:
        return self._marker_descriptor

    @property
    def artifact_root_descriptor(self) -> int:
        return self._artifact_descriptor

    @staticmethod
    def source_name(
        execution_id: UUID,
        capture_format: str,
        operation_token: str,
    ) -> str:
        if capture_format not in {"pcap", "pcapng"}:
            raise ValueError("capture source format is invalid")
        if _HEX_32.fullmatch(operation_token) is None:
            raise ValueError("capture source operation token is invalid")
        return f"capture-{execution_id}-{operation_token}.{capture_format}"

    @staticmethod
    def marker_name(idempotency_key: UUID | str) -> str:
        value = str(idempotency_key)
        if str(UUID(value)) != value:
            raise ValueError("capture marker idempotency key is invalid")
        return f"{value}.jsonl"

    @staticmethod
    def binding_name(idempotency_key: UUID | str) -> str:
        value = str(idempotency_key)
        if str(UUID(value)) != value:
            raise ValueError("capture binding idempotency key is invalid")
        return f"{value}.json"

    def acquire_operation_lock(
        self,
        idempotency_key: UUID | str,
        *,
        blocking: bool = False,
        create: bool = True,
    ) -> CaptureOperationLock:
        value = str(idempotency_key)
        if str(UUID(value)) != value:
            raise ValueError("capture lock idempotency key is invalid")
        name = f"{value}.lock"
        if self._lock_descriptor < 0:
            raise CaptureManualRecoveryRequired(
                "capture binding exists without its idempotency lock directory"
            )
        created = False
        if create:
            try:
                descriptor = os.open(
                    name,
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | int(getattr(os, "O_CLOEXEC", 0))
                    | int(getattr(os, "O_NOFOLLOW", 0)),
                    _PRIVATE_FILE_MODE,
                    dir_fd=self._lock_descriptor,
                )
                created = True
            except FileExistsError:
                descriptor = os.open(name, _read_write_flags(), dir_fd=self._lock_descriptor)
        else:
            try:
                descriptor = os.open(name, _read_flags(), dir_fd=self._lock_descriptor)
            except FileNotFoundError as error:
                raise CaptureManualRecoveryRequired(
                    "capture binding exists without its idempotency lock"
                ) from error
        try:
            _lock_exclusive(descriptor, blocking=blocking)
            metadata = os.fstat(descriptor)
            capture_file_identity(
                self._lock_descriptor,
                name,
                descriptor,
                expected_uid=_effective_uid(metadata),
                expected_mode=_PRIVATE_FILE_MODE,
            )
            if metadata.st_size != 0:
                raise CaptureManualRecoveryRequired("capture idempotency lock is not empty")
            if created:
                os.fsync(descriptor)
                os.fsync(self._lock_descriptor)
            return CaptureOperationLock(descriptor)
        except BaseException as error:
            close_descriptor(
                descriptor,
                primary_error=error,
                context="capture idempotency lock",
            )
            raise

    def begin_marker(
        self,
        *,
        task_id: UUID,
        execution_id: UUID,
        idempotency_key: UUID,
        fingerprint: CaptureFingerprint,
        request: dict[str, object],
        capture_format: str,
    ) -> tuple[CaptureMarker, bool]:
        if self._marker_descriptor < 0:
            raise CaptureRecoveryError("capture marker store is unavailable in reuse-only mode")
        name = self.marker_name(idempotency_key)
        operation_token = secrets.token_hex(16)
        authority = CaptureAuthority(
            str(task_id),
            str(execution_id),
            str(idempotency_key),
            fingerprint,
            operation_token,
        )
        source_name = self.source_name(execution_id, capture_format, operation_token)
        try:
            descriptor = os.open(
                name,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | int(getattr(os, "O_CLOEXEC", 0))
                | int(getattr(os, "O_NOFOLLOW", 0)),
                _PRIVATE_FILE_MODE,
                dir_fd=self._marker_descriptor,
            )
        except FileExistsError:
            marker = self.open_marker(idempotency_key, blocking=False)
            try:
                self._assert_authority(
                    marker.snapshot.authority,
                    authority,
                    compare_token=False,
                )
                return marker, False
            except BaseException as error:
                marker.close(primary_error=error)
                raise
        try:
            _lock_exclusive(descriptor, blocking=False)
            metadata = os.fstat(descriptor)
            identity = capture_file_identity(
                self._marker_descriptor,
                name,
                descriptor,
                expected_uid=_effective_uid(metadata),
                expected_mode=_PRIVATE_FILE_MODE,
            )
            details: dict[str, object] = {
                "request": request,
                "source_name": source_name,
                "capture_format": capture_format,
                "artifact_root": str(self.artifact_root),
                "artifact_root_dev": self.artifact_root_identity[0],
                "artifact_root_ino": self.artifact_root_identity[1],
            }
            event = {
                "version": _MARKER_SCHEMA_VERSION,
                "sequence": 0,
                "state": CaptureMarkerState.RESERVATION_PLANNED.value,
                "previous_digest": None,
                "recorded_at": _utc_now(),
                "task_id": authority.task_id,
                "execution_id": authority.execution_id,
                "idempotency_key": authority.idempotency_key,
                "fingerprint_version": authority.fingerprint.version,
                "fingerprint_sha256": authority.fingerprint.sha256,
                "operation_token": authority.operation_token,
                "details": details,
            }
            encoded = _canonical_json(event) + b"\n"
            _write_all(descriptor, encoded)
            os.fsync(descriptor)
            os.fsync(self._marker_descriptor)
            identity = capture_file_identity(
                self._marker_descriptor,
                name,
                descriptor,
                expected_uid=identity.st_uid,
                expected_mode=_PRIVATE_FILE_MODE,
            )
            snapshot = CaptureMarkerSnapshot(
                authority=authority,
                state=CaptureMarkerState.RESERVATION_PLANNED,
                sequence=0,
                event_digest=hashlib.sha256(encoded[:-1]).hexdigest(),
                details={CaptureMarkerState.RESERVATION_PLANNED: details},
            )
            return (
                CaptureMarker(
                    descriptor=descriptor,
                    root_descriptor=self._marker_descriptor,
                    identity=identity,
                    snapshot=snapshot,
                ),
                True,
            )
        except BaseException as error:
            close_descriptor(descriptor, primary_error=error, context="capture marker")
            raise

    def marker_exists(self, idempotency_key: UUID | str) -> bool:
        name = self.marker_name(idempotency_key)
        try:
            os.stat(name, dir_fd=self._marker_descriptor, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def open_marker(
        self,
        idempotency_key: UUID | str,
        *,
        blocking: bool,
    ) -> CaptureMarker:
        name = self.marker_name(idempotency_key)
        descriptor = os.open(name, _read_write_flags(), dir_fd=self._marker_descriptor)
        try:
            _lock_exclusive(descriptor, blocking=blocking)
            metadata = os.fstat(descriptor)
            identity = capture_file_identity(
                self._marker_descriptor,
                name,
                descriptor,
                expected_uid=_effective_uid(metadata),
                expected_mode=_PRIVATE_FILE_MODE,
            )
            snapshot = self._read_marker_snapshot(descriptor, identity)
            return CaptureMarker(
                descriptor=descriptor,
                root_descriptor=self._marker_descriptor,
                identity=identity,
                snapshot=snapshot,
            )
        except BaseException as error:
            close_descriptor(descriptor, primary_error=error, context="capture marker")
            raise

    def _read_marker_snapshot(
        self,
        descriptor: int,
        identity: FileIdentity,
    ) -> CaptureMarkerSnapshot:
        before = os.fstat(descriptor)
        if before.st_size <= 0 or before.st_size > _MAXIMUM_MARKER_BYTES:
            raise CaptureManualRecoveryRequired("capture marker size is invalid")
        os.lseek(descriptor, 0, os.SEEK_SET)
        encoded = bytearray()
        while len(encoded) < before.st_size:
            chunk = os.read(descriptor, before.st_size - len(encoded))
            if not chunk:
                raise CaptureManualRecoveryRequired("capture marker is truncated")
            encoded.extend(chunk)
        if os.read(descriptor, 1) or not encoded.endswith(b"\n"):
            raise CaptureManualRecoveryRequired("capture marker has an incomplete event")
        after = os.fstat(descriptor)
        if not identity.matches_with_size(after) or (
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (after.st_mtime_ns, after.st_ctime_ns):
            raise CaptureManualRecoveryRequired("capture marker changed during inspection")
        authority: CaptureAuthority | None = None
        details_by_state: dict[CaptureMarkerState, dict[str, object]] = {}
        previous_digest: str | None = None
        last_state: CaptureMarkerState | None = None
        sequence = -1
        for raw_line in bytes(encoded).splitlines():
            try:
                payload = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise CaptureManualRecoveryRequired("capture marker JSON is corrupt") from error
            expected_fields = {
                "version",
                "sequence",
                "state",
                "previous_digest",
                "recorded_at",
                "task_id",
                "execution_id",
                "idempotency_key",
                "fingerprint_version",
                "fingerprint_sha256",
                "operation_token",
                "details",
            }
            if not isinstance(payload, dict) or set(payload) != expected_fields:
                raise CaptureManualRecoveryRequired("capture marker fields are invalid")
            try:
                state = CaptureMarkerState(str(payload["state"]))
                current_authority = CaptureAuthority(
                    str(payload["task_id"]),
                    str(payload["execution_id"]),
                    str(payload["idempotency_key"]),
                    CaptureFingerprint(
                        str(payload["fingerprint_version"]),
                        str(payload["fingerprint_sha256"]),
                    ),
                    str(payload["operation_token"]),
                )
            except (TypeError, ValueError) as error:
                raise CaptureManualRecoveryRequired(
                    "capture marker authority is invalid"
                ) from error
            event_sequence = payload["sequence"]
            event_details = payload["details"]
            if (
                payload["version"] != _MARKER_SCHEMA_VERSION
                or type(event_sequence) is not int
                or event_sequence != sequence + 1
                or not isinstance(event_details, dict)
                or set(event_details) != _DETAIL_FIELDS[state]
                or payload["previous_digest"] != previous_digest
            ):
                raise CaptureManualRecoveryRequired("capture marker event chain is invalid")
            if authority is None:
                authority = current_authority
                if state is not CaptureMarkerState.RESERVATION_PLANNED:
                    raise CaptureManualRecoveryRequired("capture marker lacks planned state")
            else:
                self._assert_authority(current_authority, authority, compare_token=True)
                expected_state = _SUCCESSOR.get(last_state) if last_state is not None else None
                repeated_verification = (
                    last_state is CaptureMarkerState.ROLLBACK_VERIFICATION_PENDING
                    and state is CaptureMarkerState.ROLLBACK_VERIFICATION_PENDING
                )
                aborted_capture_rollback = (
                    last_state is CaptureMarkerState.RESERVED
                    and state is CaptureMarkerState.ROLLBACK_VERIFICATION_PENDING
                )
                if (
                    state is not expected_state
                    and state is not CaptureMarkerState.RETIRED
                    and not repeated_verification
                    and not aborted_capture_rollback
                ):
                    raise CaptureManualRecoveryRequired("capture marker transition is invalid")
            sequence = event_sequence
            last_state = state
            details_by_state[state] = cast(dict[str, object], dict(event_details))
            previous_digest = hashlib.sha256(raw_line).hexdigest()
        if authority is None or last_state is None or previous_digest is None:
            raise CaptureManualRecoveryRequired("capture marker is empty")
        return CaptureMarkerSnapshot(
            authority=authority,
            state=last_state,
            sequence=sequence,
            event_digest=previous_digest,
            details=details_by_state,
        )

    @staticmethod
    def _assert_authority(
        observed: CaptureAuthority,
        expected: CaptureAuthority,
        *,
        compare_token: bool,
    ) -> None:
        for field_name in ("task_id", "execution_id", "idempotency_key"):
            if getattr(observed, field_name) != getattr(expected, field_name):
                raise CaptureIdempotencyConflict(f"capture idempotency conflict: {field_name}")
        if observed.fingerprint != expected.fingerprint:
            raise CaptureIdempotencyConflict("capture idempotency conflict: fingerprint")
        if compare_token and observed.operation_token != expected.operation_token:
            raise CaptureManualRecoveryRequired("capture operation token is inconsistent")

    def read_binding(
        self,
        *,
        task_id: UUID,
        execution_id: UUID,
        idempotency_key: UUID,
        fingerprint: CaptureFingerprint,
        alternate_fingerprints: tuple[CaptureFingerprint, ...] = (),
    ) -> CaptureBinding | None:
        if self._binding_descriptor < 0:
            return None
        name = self.binding_name(idempotency_key)
        try:
            descriptor = os.open(name, _read_flags(), dir_fd=self._binding_descriptor)
        except FileNotFoundError:
            return None
        primary: BaseException | None = None
        try:
            metadata = os.fstat(descriptor)
            identity = capture_file_identity(
                self._binding_descriptor,
                name,
                descriptor,
                expected_uid=_effective_uid(metadata),
                expected_mode=_PRIVATE_FILE_MODE,
            )
            if metadata.st_size <= 0 or metadata.st_size > _MAXIMUM_BINDING_BYTES:
                raise CaptureManualRecoveryRequired("capture binding size is invalid")
            os.lseek(descriptor, 0, os.SEEK_SET)
            encoded = bytearray()
            while len(encoded) < metadata.st_size:
                chunk = os.read(descriptor, metadata.st_size - len(encoded))
                if not chunk:
                    raise CaptureManualRecoveryRequired("capture binding is truncated")
                encoded.extend(chunk)
            if os.read(descriptor, 1):
                raise CaptureManualRecoveryRequired("capture binding grew during inspection")
            after = os.fstat(descriptor)
            current = capture_file_identity(
                self._binding_descriptor,
                name,
                descriptor,
                expected_uid=identity.st_uid,
                expected_mode=_PRIVATE_FILE_MODE,
            )
            if current != identity or not identity.matches_with_size(after):
                raise CaptureManualRecoveryRequired("capture binding identity changed")
            try:
                payload = json.loads(bytes(encoded).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise CaptureManualRecoveryRequired("capture binding JSON is corrupt") from error
            binding = self._binding_from_payload(name, payload)
            accepted_fingerprints = {fingerprint, *alternate_fingerprints}
            if binding.authority.fingerprint not in accepted_fingerprints:
                raise CaptureIdempotencyConflict("capture idempotency conflict: fingerprint")
            requested = CaptureAuthority(
                str(task_id),
                str(execution_id),
                str(idempotency_key),
                binding.authority.fingerprint,
                binding.authority.operation_token,
            )
            self._assert_authority(binding.authority, requested, compare_token=True)
            self._open_artifact_root()
            self._validate_root_authority(
                binding.artifact_root,
                binding.artifact_root_dev,
                binding.artifact_root_ino,
            )
            return binding
        except BaseException as error:
            primary = error
            raise
        finally:
            close_descriptor(
                descriptor,
                primary_error=primary,
                context="capture binding",
            )

    def publish_binding(
        self,
        *,
        authority: CaptureAuthority,
        artifact_path: Path,
        artifact_relative_path: str,
        manifest: dict[str, object],
        metadata: dict[str, object],
        rollback: dict[str, object],
        status: str,
        reason: str | None,
    ) -> CaptureBinding:
        if self._reuse_only:
            raise CaptureRecoveryError(
                "capture binding publication is unavailable in reuse-only mode"
            )
        name = self.binding_name(authority.idempotency_key)
        manifest_size = _required_int(manifest.get("size_bytes"), label="capture manifest size")
        artifact_metadata = self._inspect_artifact(
            artifact_relative_path,
            expected_size=manifest_size,
            expected_sha256=str(manifest.get("sha256", "")),
        )
        expected_path = self.artifact_root / Path(artifact_relative_path)
        if artifact_path != expected_path:
            raise CaptureManualRecoveryRequired("capture binding artifact path is inconsistent")
        payload: dict[str, object] = {
            "version": _BINDING_SCHEMA_VERSION,
            "state": CaptureMarkerState.BINDING_PUBLISHED.value,
            "published_at": _utc_now(),
            "task_id": authority.task_id,
            "execution_id": authority.execution_id,
            "idempotency_key": authority.idempotency_key,
            "fingerprint_version": authority.fingerprint.version,
            "fingerprint_sha256": authority.fingerprint.sha256,
            "operation_token": authority.operation_token,
            "artifact_root": str(self.artifact_root),
            "artifact_root_dev": self.artifact_root_identity[0],
            "artifact_root_ino": self.artifact_root_identity[1],
            "artifact_path": str(artifact_path),
            "artifact_relative_path": artifact_relative_path,
            "artifact_st_dev": int(artifact_metadata.st_dev),
            "artifact_st_ino": int(artifact_metadata.st_ino),
            "artifact_st_uid": int(artifact_metadata.st_uid),
            "artifact_mode": stat.S_IMODE(artifact_metadata.st_mode),
            "artifact_st_nlink": int(artifact_metadata.st_nlink),
            "manifest": manifest,
            "metadata": metadata,
            "rollback": rollback,
            "status": status,
            "reason": reason,
            "size_bytes": manifest.get("size_bytes"),
            "sha256": manifest.get("sha256"),
        }
        binding = self._binding_from_payload(name, payload)
        encoded = _canonical_json(payload)
        if len(encoded) > _MAXIMUM_BINDING_BYTES:
            raise CaptureRecoveryError("capture binding exceeds its size limit")
        temporary = f".{authority.idempotency_key}.pending.{secrets.token_hex(24)}"
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | int(getattr(os, "O_CLOEXEC", 0))
            | int(getattr(os, "O_NOFOLLOW", 0)),
            _PRIVATE_FILE_MODE,
            dir_fd=self._binding_descriptor,
        )
        primary: BaseException | None = None
        identity: FileIdentity | None = None
        try:
            metadata_stat = os.fstat(descriptor)
            identity = capture_file_identity(
                self._binding_descriptor,
                temporary,
                descriptor,
                expected_uid=_effective_uid(metadata_stat),
                expected_mode=_PRIVATE_FILE_MODE,
            )
            _write_all(descriptor, encoded)
            os.fsync(descriptor)
            close_descriptor(descriptor, context="capture binding temporary")
            descriptor = -1
            try:
                rename_noreplace(
                    self._binding_descriptor,
                    temporary,
                    self._binding_descriptor,
                    name,
                )
            except FileExistsError as publication_error:
                existing = self.read_binding(
                    task_id=UUID(authority.task_id),
                    execution_id=UUID(authority.execution_id),
                    idempotency_key=UUID(authority.idempotency_key),
                    fingerprint=authority.fingerprint,
                )
                if existing is None or existing != binding:
                    raise CaptureManualRecoveryRequired(
                        "capture binding publication conflict"
                    ) from publication_error
                if identity is not None:
                    outcome = logical_quarantine(
                        identity,
                        quarantine_prefix=".capture-binding-retired-",
                    )
                    if not outcome.logical_deletion_confirmed:
                        raise CaptureManualRecoveryRequired(
                            "duplicate capture binding temporary was not retired"
                        ) from publication_error
                return existing
            os.fsync(self._binding_descriptor)
            return binding
        except BaseException as error:
            primary = error
            if identity is not None and descriptor >= 0:
                logical_quarantine(
                    identity,
                    quarantine_prefix=".capture-binding-manual-",
                    primary_error=error,
                )
            raise
        finally:
            if descriptor >= 0:
                close_descriptor(
                    descriptor,
                    primary_error=primary,
                    context="capture binding temporary",
                )

    def _binding_from_payload(self, name: str, payload: object) -> CaptureBinding:
        expected_fields = {
            "version",
            "state",
            "published_at",
            "task_id",
            "execution_id",
            "idempotency_key",
            "fingerprint_version",
            "fingerprint_sha256",
            "operation_token",
            "artifact_root",
            "artifact_root_dev",
            "artifact_root_ino",
            "artifact_path",
            "artifact_relative_path",
            "artifact_st_dev",
            "artifact_st_ino",
            "artifact_st_uid",
            "artifact_mode",
            "artifact_st_nlink",
            "manifest",
            "metadata",
            "rollback",
            "status",
            "reason",
            "size_bytes",
            "sha256",
        }
        if not isinstance(payload, dict) or set(payload) != expected_fields:
            raise CaptureManualRecoveryRequired("capture binding is legacy or lacks a fingerprint")
        try:
            authority = CaptureAuthority(
                str(payload["task_id"]),
                str(payload["execution_id"]),
                str(payload["idempotency_key"]),
                CaptureFingerprint(
                    str(payload["fingerprint_version"]),
                    str(payload["fingerprint_sha256"]),
                ),
                str(payload["operation_token"]),
            )
        except (TypeError, ValueError) as error:
            raise CaptureManualRecoveryRequired("capture binding authority is invalid") from error
        manifest = payload["manifest"]
        metadata = payload["metadata"]
        rollback = payload["rollback"]
        if (
            payload["version"] != _BINDING_SCHEMA_VERSION
            or payload["state"] != CaptureMarkerState.BINDING_PUBLISHED.value
            or not isinstance(manifest, dict)
            or not isinstance(metadata, dict)
            or not isinstance(rollback, dict)
            or type(payload["artifact_root_dev"]) is not int
            or type(payload["artifact_root_ino"]) is not int
            or any(
                type(payload[field]) is not int
                for field in (
                    "artifact_st_dev",
                    "artifact_st_ino",
                    "artifact_st_uid",
                    "artifact_mode",
                    "artifact_st_nlink",
                )
            )
            or payload["size_bytes"] != manifest.get("size_bytes")
            or payload["sha256"] != manifest.get("sha256")
            or str(manifest.get("artifact_id")) != authority.idempotency_key
            or str(manifest.get("execution_id")) != authority.execution_id
            or metadata.get("fingerprint_version") != authority.fingerprint.version
            or metadata.get("fingerprint_sha256") != authority.fingerprint.sha256
        ):
            raise CaptureManualRecoveryRequired("capture binding payload is inconsistent")
        status = str(payload["status"])
        reason_value = payload["reason"]
        if status not in {"completed", "failed", "cancelled"} or (
            reason_value is not None and not isinstance(reason_value, str)
        ):
            raise CaptureManualRecoveryRequired("capture binding result is invalid")
        return CaptureBinding(
            authority=authority,
            artifact_root=str(payload["artifact_root"]),
            artifact_root_dev=int(payload["artifact_root_dev"]),
            artifact_root_ino=int(payload["artifact_root_ino"]),
            artifact_path=str(payload["artifact_path"]),
            artifact_relative_path=str(payload["artifact_relative_path"]),
            artifact_st_dev=int(payload["artifact_st_dev"]),
            artifact_st_ino=int(payload["artifact_st_ino"]),
            artifact_st_uid=int(payload["artifact_st_uid"]),
            artifact_mode=int(payload["artifact_mode"]),
            artifact_st_nlink=int(payload["artifact_st_nlink"]),
            manifest=cast(dict[str, object], dict(manifest)),
            metadata=cast(dict[str, object], dict(metadata)),
            rollback=cast(dict[str, object], dict(rollback)),
            status=status,
            reason=reason_value,
            binding_name=name,
        )

    def _inspect_artifact(
        self,
        relative_path: str,
        *,
        expected_size: int,
        expected_sha256: str,
        expected_identity: tuple[int, int, int, int, int] | None = None,
    ) -> os.stat_result:
        relative = Path(relative_path)
        if (
            relative.is_absolute()
            or relative.parts[:1] != ("outbox",)
            or len(relative.parts) != 2
            or not relative.parts[1].startswith("artifact-")
            or "/" in relative.parts[1]
            or expected_size <= 0
            or _SHA256.fullmatch(expected_sha256) is None
        ):
            raise CaptureManualRecoveryRequired("capture binding artifact reference is invalid")
        outbox_descriptor = os.open("outbox", _directory_flags(), dir_fd=self._artifact_descriptor)
        descriptor = -1
        primary: BaseException | None = None
        try:
            outbox_metadata = os.fstat(outbox_descriptor)
            _validate_directory(outbox_metadata, label="capture artifact outbox")
            named_outbox = os.stat(
                "outbox", dir_fd=self._artifact_descriptor, follow_symlinks=False
            )
            if _identity(outbox_metadata) != _identity(named_outbox):
                raise CaptureManualRecoveryRequired("capture artifact outbox identity changed")
            descriptor = os.open(relative.parts[1], _read_flags(), dir_fd=outbox_descriptor)
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or int(before.st_uid) != _effective_uid(before)
                or stat.S_IMODE(before.st_mode) != 0o400
                or int(before.st_nlink) != 1
                or int(before.st_size) != expected_size
            ):
                raise CaptureManualRecoveryRequired("capture binding artifact identity is unsafe")
            observed_identity = (
                int(before.st_dev),
                int(before.st_ino),
                int(before.st_uid),
                stat.S_IMODE(before.st_mode),
                int(before.st_nlink),
            )
            if expected_identity is not None and observed_identity != expected_identity:
                raise CaptureManualRecoveryRequired("capture binding artifact inode changed")
            named = os.stat(relative.parts[1], dir_fd=outbox_descriptor, follow_symlinks=False)
            if _identity(before) != _identity(named):
                raise CaptureManualRecoveryRequired("capture binding artifact name changed")
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(descriptor, 1_048_576)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
            after = os.fstat(descriptor)
            if (
                observed_identity
                != (
                    int(after.st_dev),
                    int(after.st_ino),
                    int(after.st_uid),
                    stat.S_IMODE(after.st_mode),
                    int(after.st_nlink),
                )
                or int(after.st_size) != expected_size
                or (before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_mtime_ns, after.st_ctime_ns)
                or size != expected_size
                or digest.hexdigest() != expected_sha256
            ):
                raise CaptureManualRecoveryRequired("capture binding artifact content changed")
            return after
        except BaseException as error:
            primary = error
            raise
        finally:
            if descriptor >= 0:
                close_descriptor(
                    descriptor, primary_error=primary, context="capture binding artifact"
                )
            close_descriptor(
                outbox_descriptor,
                primary_error=primary,
                context="capture artifact outbox",
            )

    def validate_binding_artifact(self, binding: CaptureBinding) -> Path:
        self._open_artifact_root()
        self._validate_root_authority(
            binding.artifact_root,
            binding.artifact_root_dev,
            binding.artifact_root_ino,
        )
        expected_path = self.artifact_root / Path(binding.artifact_relative_path)
        if binding.artifact_path != str(expected_path):
            raise CaptureManualRecoveryRequired("capture binding artifact path changed")
        try:
            self._inspect_artifact(
                binding.artifact_relative_path,
                expected_size=_required_int(
                    binding.manifest["size_bytes"], label="capture binding size"
                ),
                expected_sha256=str(binding.manifest["sha256"]),
                expected_identity=(
                    binding.artifact_st_dev,
                    binding.artifact_st_ino,
                    binding.artifact_st_uid,
                    binding.artifact_mode,
                    binding.artifact_st_nlink,
                ),
            )
        except FileNotFoundError as error:
            raise CaptureManualRecoveryRequired("capture binding artifact is missing") from error
        return expected_path

    def _validate_root_authority(self, path: str, device: int, inode: int) -> None:
        if path != str(self.artifact_root) or (device, inode) != self.artifact_root_identity:
            raise CaptureManualRecoveryRequired("capture artifact root changed")
        metadata = os.fstat(self._artifact_descriptor)
        named = self.artifact_root.lstat()
        if _identity(metadata) != self.artifact_root_identity or _identity(named) != (
            device,
            inode,
        ):
            raise CaptureManualRecoveryRequired("capture artifact root identity changed")

    def validate_marker_root(self, snapshot: CaptureMarkerSnapshot) -> None:
        planned = snapshot.planned
        try:
            expected_source = self.source_name(
                UUID(snapshot.authority.execution_id),
                str(planned["capture_format"]),
                snapshot.authority.operation_token,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise CaptureManualRecoveryRequired(
                "capture marker source authority is invalid"
            ) from error
        if planned.get("source_name") != expected_source:
            raise CaptureManualRecoveryRequired("capture marker source authority changed")
        self._validate_root_authority(
            str(planned["artifact_root"]),
            _required_int(planned["artifact_root_dev"], label="capture artifact root device"),
            _required_int(planned["artifact_root_ino"], label="capture artifact root inode"),
        )

    def close(self, *, primary_error: BaseException | None = None) -> None:
        if getattr(self, "closed", False):
            return
        self.closed = True
        for descriptor, context in (
            (getattr(self, "_artifact_descriptor", -1), "capture artifact root"),
            (getattr(self, "_lock_descriptor", -1), "capture lock directory"),
            (getattr(self, "_binding_descriptor", -1), "capture binding directory"),
            (getattr(self, "_marker_descriptor", -1), "capture marker directory"),
        ):
            if descriptor >= 0:
                close_descriptor(
                    descriptor,
                    primary_error=primary_error,
                    context=context,
                )

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            return
