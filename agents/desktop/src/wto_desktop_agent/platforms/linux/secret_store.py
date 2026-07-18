from __future__ import annotations

import asyncio
import errno
import hashlib
import importlib
import logging
import os
import queue
import re
import secrets
import stat
import struct
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import IntEnum
from pathlib import Path
from typing import Any, cast

from wto_desktop_agent.domain.errors import (
    MutationCommitIndeterminateError,
    SecureStoreUnavailableError,
)
from wto_desktop_agent.domain.models import DoctorCheck
from wto_desktop_agent.platforms.linux.secure_fs import (
    FileIdentity,
    QuarantinedObject,
    capture_file_identity,
    close_descriptor,
    logical_quarantine,
    rename_exchange,
    rename_noreplace,
)

_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_MAX_SECRET_BYTES = 1_048_576
_FCHMOD = cast(Callable[[int, int], None] | None, getattr(os, "fchmod", None))
_PREAD = cast(Callable[[int, int, int], bytes] | None, getattr(os, "pread", None))
_PWRITE = cast(Callable[[int, bytes, int], int] | None, getattr(os, "pwrite", None))
_POSIX_FALLOCATE = cast(
    Callable[[int, int, int], None] | None,
    getattr(os, "posix_fallocate", None),
)
_LOGGER = logging.getLogger(__name__)

_READ_ONLY_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | int(getattr(os, "O_DIRECTORY", 0))
    | int(getattr(os, "O_CLOEXEC", 0))
    | int(getattr(os, "O_NOFOLLOW", 0))
)
_READ_ONLY_FILE_FLAGS = (
    os.O_RDONLY
    | int(getattr(os, "O_CLOEXEC", 0))
    | int(getattr(os, "O_NOFOLLOW", 0))
    | int(getattr(os, "O_NOATIME", 0))
)


def _effective_user_id() -> int:
    getter = getattr(os, "geteuid", None)
    if getter is None:
        raise SecureStoreUnavailableError("Linux ownership APIs are unavailable")
    return int(getter())


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _validate_directory_components(path: Path) -> None:
    absolute = _absolute_path(path)
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            try:
                os.mkdir(current, 0o700)
                os.chmod(current, 0o700)
                metadata = os.lstat(current)
            except (FileExistsError, OSError) as error:
                raise SecureStoreUnavailableError("secret directory creation failed") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise SecureStoreUnavailableError("secret directory cannot contain symlinks")
        if not stat.S_ISDIR(metadata.st_mode):
            raise SecureStoreUnavailableError("secret directory contains a non-directory")


def _validate_private_directory_metadata(metadata: os.stat_result) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise SecureStoreUnavailableError("secret path is not a directory")
    if metadata.st_uid != _effective_user_id():
        raise SecureStoreUnavailableError("secret directory owner is invalid")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SecureStoreUnavailableError("secret directory permissions must be 0700")


def ensure_private_directory(path: Path) -> None:
    _validate_directory_components(path)
    try:
        metadata = os.lstat(_absolute_path(path))
    except OSError as error:
        raise SecureStoreUnavailableError("secret directory validation failed") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise SecureStoreUnavailableError("secret directory cannot be a symlink")
    _validate_private_directory_metadata(metadata)


def _validate_secret_metadata(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise SecureStoreUnavailableError("secret path is not a regular file")
    if metadata.st_nlink != 1:
        raise SecureStoreUnavailableError("secret file must have exactly one link")
    if metadata.st_uid != _effective_user_id():
        raise SecureStoreUnavailableError("secret file owner is invalid")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SecureStoreUnavailableError(
            "secret file permissions must be 0600; group/world access is rejected"
        )


def _metadata_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


@dataclass(frozen=True)
class _Deadline:
    expires_at: float

    @classmethod
    def start(cls, seconds: float) -> _Deadline:
        return cls(time.monotonic() + seconds)

    def timeout(self, operation_timeout_seconds: float) -> float:
        remaining = self.expires_at - time.monotonic()
        if remaining <= 0:
            raise SecureStoreUnavailableError("Linux Secret Service total timeout expired")
        return min(remaining, operation_timeout_seconds)


@dataclass
class _OpenSecretFile:
    name: str
    descriptor: int
    identity: FileIdentity
    expected_size: int
    closed: bool = False


class _StoreHealth(IntEnum):
    HEALTHY = 1
    POISONED = 2
    MUTATING = 3


class _CompletionGuardState(IntEnum):
    IDLE = 1
    FINALIZING = 2


@dataclass(frozen=True)
class _StoreStateSlot:
    slot_index: int
    sequence: int
    state: _StoreHealth
    reason: str
    operation_token: str


@dataclass(frozen=True)
class _CompletionGuardSlot:
    slot_index: int
    sequence: int
    state: _CompletionGuardState
    store_sequence: int
    operation_token: str
    reason: str = ""


class _MutationCommitOutcome(IntEnum):
    NOT_COMMITTED = 1
    COMMITTED = 2
    COMMIT_INDETERMINATE = 3


@dataclass
class _MutationCommitTracker:
    outcome: _MutationCommitOutcome = _MutationCommitOutcome.NOT_COMMITTED
    operation_token: str = ""
    expected_mutating: _StoreStateSlot | None = None
    expected_healthy: _StoreStateSlot | None = None
    expected_idle: _CompletionGuardSlot | None = None
    idle_write_started: bool = False
    idle_write_completed: bool = False
    idle_fsync_completed: bool = False
    body_succeeded: bool = False


class _AppliedMutationCleanupError(SecureStoreUnavailableError):
    """A durable mutation was applied before descriptor cleanup failed."""

    def __init__(self, cleanup_error: BaseException) -> None:
        super().__init__("secret mutation descriptor cleanup failed after application")
        self.cleanup_error = cleanup_error


def _bounded_blocking_call[T](
    operation: Callable[[], T],
    *,
    deadline: _Deadline,
    operation_timeout_seconds: float,
    mutating: bool = False,
) -> T:
    result: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)
    timeout = deadline.timeout(operation_timeout_seconds)

    def invoke() -> None:
        try:
            result.put((True, operation()), block=False)
        except BaseException as error:  # the caller re-raises on its own thread
            result.put((False, error), block=False)

    worker = threading.Thread(target=invoke, name="wto-secret-service-call", daemon=True)
    worker.start()
    try:
        succeeded, value = result.get(timeout=timeout)
    except queue.Empty as error:
        if mutating:
            raise MutationCommitIndeterminateError() from error
        raise SecureStoreUnavailableError("Linux Secret Service operation timed out") from error
    if succeeded:
        return value  # type: ignore[return-value]
    if isinstance(value, SecureStoreUnavailableError):
        raise value
    if isinstance(value, BaseException):
        raise SecureStoreUnavailableError("Linux Secret Service operation failed") from value
    raise SecureStoreUnavailableError("Linux Secret Service returned an invalid result")


class LinuxSecretServiceStore:
    """Fail-closed Secret Service adapter with lazy, bounded D-Bus operations."""

    _SERVICE = "org.wifi_test_orchestrator.DesktopAgent"

    def __init__(
        self,
        *,
        total_timeout_seconds: float = 5.0,
        operation_timeout_seconds: float = 2.0,
    ) -> None:
        if total_timeout_seconds <= 0 or operation_timeout_seconds <= 0:
            raise ValueError("Secret Service timeouts must be positive")
        if operation_timeout_seconds > total_timeout_seconds:
            raise ValueError("Secret Service operation timeout cannot exceed total timeout")
        self._total_timeout_seconds = total_timeout_seconds
        self._operation_timeout_seconds = operation_timeout_seconds
        self._collection: Any = None
        self._initialization_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._failed = False
        self._commit_indeterminate = False

    @property
    def secure(self) -> bool:
        return True

    def _mark_failed(self, *, commit_indeterminate: bool = False) -> None:
        with self._state_lock:
            self._failed = True
            if commit_indeterminate:
                self._commit_indeterminate = True
            self._collection = None

    def _check_available(self) -> None:
        with self._state_lock:
            failed = self._failed
            commit_indeterminate = self._commit_indeterminate
        if failed:
            if commit_indeterminate:
                raise MutationCommitIndeterminateError()
            raise SecureStoreUnavailableError("Linux Secret Service backend is unavailable")

    def _call[T](
        self,
        operation: Callable[[], T],
        deadline: _Deadline,
        *,
        mutating: bool = False,
    ) -> T:
        self._check_available()
        try:
            return _bounded_blocking_call(
                operation,
                deadline=deadline,
                operation_timeout_seconds=self._operation_timeout_seconds,
                mutating=mutating,
            )
        except MutationCommitIndeterminateError:
            self._mark_failed(commit_indeterminate=True)
            raise
        except SecureStoreUnavailableError:
            self._mark_failed()
            raise

    def _ensure_collection(self, deadline: _Deadline) -> Any:
        self._check_available()
        if self._collection is not None:
            return self._collection
        acquired = self._initialization_lock.acquire(
            timeout=deadline.timeout(self._operation_timeout_seconds)
        )
        if not acquired:
            self._mark_failed()
            raise SecureStoreUnavailableError("Linux Secret Service initialization timed out")
        try:
            self._check_available()
            if self._collection is not None:
                return self._collection
            try:
                secretstorage = importlib.import_module("secretstorage")
            except Exception as error:
                self._mark_failed()
                raise SecureStoreUnavailableError(
                    "Linux Secret Service dependency is unavailable"
                ) from error
            connection = self._call(secretstorage.dbus_init, deadline)
            collection = self._call(
                lambda: secretstorage.get_collection_by_alias(connection, "default"),
                deadline,
            )
            if self._call(collection.is_locked, deadline):
                self._mark_failed()
                raise SecureStoreUnavailableError(
                    "Linux Secret Service is locked; interactive unlock is not attempted"
                )
            with self._state_lock:
                self._collection = collection
            return collection
        finally:
            self._initialization_lock.release()

    def _attributes(self, key: str) -> dict[str, str]:
        if not _KEY.fullmatch(key):
            raise ValueError("invalid secret key")
        return {"application": self._SERVICE, "key": key}

    def put(self, key: str, value: str) -> None:
        deadline = _Deadline.start(self._total_timeout_seconds)
        attributes = self._attributes(key)
        collection = self._ensure_collection(deadline)
        self._call(
            lambda: collection.create_item(
                "WTO desktop agent credential",
                attributes,
                value.encode("utf-8"),
                replace=True,
            ),
            deadline,
            mutating=True,
        )

    def get(self, key: str) -> str | None:
        deadline = _Deadline.start(self._total_timeout_seconds)
        collection = self._ensure_collection(deadline)
        items = self._call(lambda: list(collection.search_items(self._attributes(key))), deadline)
        if not items:
            return None
        secret = bytes(self._call(items[0].get_secret, deadline))
        try:
            return secret.decode("utf-8")
        except UnicodeDecodeError as error:
            self._mark_failed()
            raise SecureStoreUnavailableError(
                "Linux Secret Service returned invalid text"
            ) from error

    def delete(self, key: str) -> None:
        deadline = _Deadline.start(self._total_timeout_seconds)
        collection = self._ensure_collection(deadline)
        items = self._call(lambda: list(collection.search_items(self._attributes(key))), deadline)
        for item in items:
            self._call(item.delete, deadline, mutating=True)

    async def aput(self, key: str, value: str) -> None:
        try:
            await asyncio.to_thread(self.put, key, value)
        except asyncio.CancelledError as error:
            self._mark_failed(commit_indeterminate=True)
            raise MutationCommitIndeterminateError() from error

    async def aget(self, key: str) -> str | None:
        try:
            return await asyncio.to_thread(self.get, key)
        except asyncio.CancelledError:
            self._mark_failed()
            raise

    async def adelete(self, key: str) -> None:
        try:
            await asyncio.to_thread(self.delete, key)
        except asyncio.CancelledError as error:
            self._mark_failed(commit_indeterminate=True)
            raise MutationCommitIndeterminateError() from error

    def doctor(self) -> DoctorCheck:
        try:
            self._ensure_collection(_Deadline.start(self._total_timeout_seconds))
        except MutationCommitIndeterminateError:
            return DoctorCheck(
                name="secret_store",
                status="BLOCKED",
                detail="BLOCKED_MUTATION_COMMIT_INDETERMINATE",
            )
        except SecureStoreUnavailableError:
            return DoctorCheck(
                name="secret_store",
                status="BLOCKED",
                detail="Linux Secret Service is unavailable, locked, or timed out",
            )
        return DoctorCheck(
            name="secret_store", status="OK", detail="Linux Secret Service is available"
        )


class LinuxEncryptedFileSecretStore:
    """Explicit headless backend anchored to an owner-only directory descriptor."""

    _lock_name = ".store.lock"
    _state_name = ".store-state"
    _completion_guard_name = ".store-completion-guard"
    _poison_name = ".store-manual-recovery"
    _poison_payload = b"manual_recovery_required:v1\n"
    _state_magic = b"WTOST01\0"
    _state_version = 1
    _state_slot_size = 256
    _state_slot_count = 2
    _state_file_size = _state_slot_size * _state_slot_count
    _state_checksum_size = hashlib.sha256().digest_size
    _state_header = struct.Struct(">8sHBBQ64s32s")
    _state_reason = re.compile(r"^[a-z0-9_]{1,64}$")
    _state_operation_token = re.compile(r"^[0-9a-f]{32}$")
    _state_max_sequence = (1 << 64) - 1
    _completion_guard_magic = b"WTOCG01\0"
    _completion_guard_version = 1
    _completion_guard_slot_size = 256
    _completion_guard_slot_count = 2
    _completion_guard_file_size = _completion_guard_slot_size * _completion_guard_slot_count
    _completion_guard_checksum_size = hashlib.sha256().digest_size
    _completion_guard_header = struct.Struct(">8sHBBQQ32s")

    def __init__(
        self,
        state_dir: Path,
        *,
        process_lock_timeout_seconds: float = 5.0,
        process_lock_retry_seconds: float = 0.01,
    ) -> None:
        if process_lock_timeout_seconds <= 0 or process_lock_retry_seconds <= 0:
            raise ValueError("secret store process lock timing must be positive")
        self._root = _absolute_path(state_dir) / "secrets"
        self._operation_lock = threading.RLock()
        self._recovery_issues: list[str] = []
        self._process_lock_timeout_seconds = process_lock_timeout_seconds
        self._process_lock_retry_seconds = process_lock_retry_seconds
        self._lock_fd = -1
        self._state_fd = -1
        self._store_state_issue: str | None = None
        self._completion_guard_fd = -1
        self._completion_guard_issue: str | None = None
        self._fatal_reason: str | None = None
        ensure_private_directory(_absolute_path(state_dir))
        state_fd = self._open_directory(_absolute_path(state_dir))
        state_primary: BaseException | None = None
        try:
            try:
                os.mkdir("secrets", 0o700, dir_fd=state_fd)
                os.chmod("secrets", 0o700, dir_fd=state_fd, follow_symlinks=False)
                self._fsync_directory(state_fd)
            except FileExistsError:
                pass
            self._root_fd = self._open_directory("secrets", dir_fd=state_fd)
        except BaseException as error:
            state_primary = error
            raise
        finally:
            try:
                close_descriptor(
                    state_fd,
                    primary_error=state_primary,
                    context="secret state directory",
                )
            except BaseException as close_error:
                root_descriptor = getattr(self, "_root_fd", -1)
                self._root_fd = -1
                if root_descriptor >= 0:
                    close_descriptor(
                        root_descriptor,
                        primary_error=close_error,
                        context="secret root directory",
                    )
                raise
        try:
            _validate_private_directory_metadata(os.fstat(self._root_fd))
            self._lock_fd, self._lock_identity = self._open_store_lock()
            initialization_commit = _MutationCommitTracker()
            with self._operation_lock:
                with self._process_shared_lock(
                    allow_poisoned=True,
                    state_required=False,
                    commit_tracker=initialization_commit,
                ):
                    state_present = self._named_entry_exists(self._state_name)
                    guard_present = self._named_entry_exists(self._completion_guard_name)
                    state_created = False
                    guard_created = False
                    if state_present or not guard_present:
                        (
                            self._state_fd,
                            self._state_identity,
                            state_created,
                        ) = self._open_store_state()
                    else:
                        self._store_state_issue = "store_state_missing"
                    if guard_present or state_created:
                        (
                            self._completion_guard_fd,
                            self._completion_guard_identity,
                            guard_created,
                        ) = self._open_completion_guard(
                            create_if_missing=state_created,
                        )
                    else:
                        self._completion_guard_issue = "completion_guard_missing"
                    if state_created != guard_created:
                        self._completion_guard_issue = "completion_guard_bootstrap_inconsistent"
                    try:
                        self._raise_if_poisoned()
                    except SecureStoreUnavailableError:
                        self._master_key = b""
                    else:
                        self._master_key = self._load_or_create_master_key(initialization_commit)
        except BaseException as error:
            guard_descriptor = self._completion_guard_fd
            self._completion_guard_fd = -1
            if guard_descriptor >= 0:
                close_descriptor(
                    guard_descriptor,
                    primary_error=error,
                    context="secret store completion guard",
                )
            state_descriptor = self._state_fd
            self._state_fd = -1
            if state_descriptor >= 0:
                close_descriptor(
                    state_descriptor,
                    primary_error=error,
                    context="secret store state",
                )
            lock_descriptor = self._lock_fd
            self._lock_fd = -1
            if lock_descriptor >= 0:
                close_descriptor(
                    lock_descriptor,
                    primary_error=error,
                    context="secret store process lock",
                )
            descriptor = self._root_fd
            self._root_fd = -1
            close_descriptor(
                descriptor,
                primary_error=error,
                context="secret root directory",
            )
            raise

    @property
    def secure(self) -> bool:
        return True

    @staticmethod
    def _log_post_commit_failure(event: str, error: BaseException) -> None:
        try:
            _LOGGER.error(
                event,
                extra={"failure_type": type(error).__name__},
            )
        except BaseException:
            return

    @staticmethod
    def _aesgcm(key: bytes) -> Any:
        try:
            module = importlib.import_module("cryptography.hazmat.primitives.ciphers.aead")
            return module.AESGCM(key)
        except Exception as error:
            raise SecureStoreUnavailableError("AES-GCM backend is unavailable") from error

    @staticmethod
    def _open_directory(path: Path | str, *, dir_fd: int | None = None) -> int:
        flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        try:
            descriptor = os.open(path, flags, dir_fd=dir_fd)
        except OSError as error:
            raise SecureStoreUnavailableError("secret directory open failed") from error
        try:
            _validate_private_directory_metadata(os.fstat(descriptor))
        except BaseException as error:
            close_descriptor(
                descriptor,
                primary_error=error,
                context="secret directory",
            )
            raise
        return descriptor

    @staticmethod
    def _fsync_directory(descriptor: int) -> None:
        try:
            os.fsync(descriptor)
        except OSError as error:
            raise SecureStoreUnavailableError("secret directory fsync failed") from error

    @property
    def recovery_issues(self) -> tuple[str, ...]:
        return tuple(self._recovery_issues)

    def _record_quarantine(self, result: QuarantinedObject, context: str) -> None:
        if result.quarantine_name is None:
            return
        issue = f"{context}:physical_delete_pending:{result.quarantine_name}"
        if issue not in self._recovery_issues:
            self._recovery_issues.append(issue)

    def _quarantine_identity(
        self,
        identity: FileIdentity,
        *,
        prefix: str,
        context: str,
        primary_error: BaseException | None = None,
    ) -> QuarantinedObject:
        result = logical_quarantine(
            identity,
            quarantine_prefix=prefix,
            primary_error=primary_error,
        )
        if result.logical_deletion_confirmed:
            self._record_quarantine(result, context)
        return result

    def _open_store_lock(self) -> tuple[int, FileIdentity]:
        common_flags = os.O_RDWR | int(getattr(os, "O_CLOEXEC", 0))
        common_flags |= int(getattr(os, "O_NOFOLLOW", 0))
        created = False
        try:
            descriptor = os.open(
                self._lock_name,
                common_flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=self._root_fd,
            )
            created = True
        except FileExistsError:
            try:
                descriptor = os.open(
                    self._lock_name,
                    common_flags,
                    dir_fd=self._root_fd,
                )
            except OSError as error:
                raise SecureStoreUnavailableError("secret store lock open failed") from error
        except OSError as error:
            raise SecureStoreUnavailableError("secret store lock creation failed") from error
        primary: BaseException | None = None
        try:
            if created:
                if _FCHMOD is None:
                    raise SecureStoreUnavailableError("secret file mode API is unavailable")
                _FCHMOD(descriptor, 0o600)
            metadata = os.fstat(descriptor)
            _validate_secret_metadata(metadata)
            if not self._valid_lock_payload(descriptor, int(metadata.st_size)):
                raise SecureStoreUnavailableError("secret store lock content is invalid")
            identity = capture_file_identity(
                self._root_fd,
                self._lock_name,
                descriptor,
                expected_uid=_effective_user_id(),
                expected_mode=0o600,
            )
            if not identity.matches_with_size(metadata):
                raise SecureStoreUnavailableError("secret store lock identity changed")
            self._fsync_directory(self._root_fd)
            return descriptor, identity
        except BaseException as error:
            primary = error
            raise
        finally:
            if primary is not None:
                close_descriptor(
                    descriptor,
                    primary_error=primary,
                    context="secret store process lock",
                )

    @classmethod
    def _encode_state_slot(
        cls,
        *,
        sequence: int,
        state: _StoreHealth,
        reason: str,
        operation_token: str,
    ) -> bytes:
        if (
            sequence < 0
            or sequence > cls._state_max_sequence
            or not cls._state_reason.fullmatch(reason)
            or (state is _StoreHealth.HEALTHY and reason != "healthy")
            or (state is not _StoreHealth.HEALTHY and reason == "healthy")
            or (
                state is _StoreHealth.HEALTHY
                and operation_token != ""
                and not cls._state_operation_token.fullmatch(operation_token)
            )
            or (
                state is not _StoreHealth.HEALTHY
                and not cls._state_operation_token.fullmatch(operation_token)
            )
        ):
            raise SecureStoreUnavailableError("secret store state fields are invalid")
        encoded_reason = reason.encode("ascii")
        reason_field = encoded_reason + b"\0" * (64 - len(encoded_reason))
        encoded_token = operation_token.encode("ascii")
        token_field = encoded_token + b"\0" * (32 - len(encoded_token))
        header = cls._state_header.pack(
            cls._state_magic,
            cls._state_version,
            int(state),
            0,
            sequence,
            reason_field,
            token_field,
        )
        body_size = cls._state_slot_size - cls._state_checksum_size
        body = header + b"\0" * (body_size - len(header))
        return body + hashlib.sha256(body).digest()

    @classmethod
    def _decode_state_slot(cls, slot_index: int, payload: bytes) -> _StoreStateSlot | None:
        if len(payload) != cls._state_slot_size:
            return None
        body = payload[: -cls._state_checksum_size]
        checksum = payload[-cls._state_checksum_size :]
        if not secrets.compare_digest(hashlib.sha256(body).digest(), checksum):
            return None
        try:
            magic, version, state_value, reserved, sequence, reason_field, token_field = (
                cls._state_header.unpack(body[: cls._state_header.size])
            )
            state = _StoreHealth(state_value)
        except (ValueError, struct.error):
            return None
        if (
            magic != cls._state_magic
            or version != cls._state_version
            or reserved != 0
            or any(body[cls._state_header.size :])
        ):
            return None
        encoded_reason, separator, trailing = reason_field.partition(b"\0")
        if separator and any(trailing):
            return None
        try:
            reason = encoded_reason.decode("ascii")
        except UnicodeDecodeError:
            return None
        if not cls._state_reason.fullmatch(reason):
            return None
        encoded_token, token_separator, token_trailing = token_field.partition(b"\0")
        if token_separator and any(token_trailing):
            return None
        try:
            operation_token = encoded_token.decode("ascii")
        except UnicodeDecodeError:
            return None
        if state is _StoreHealth.HEALTHY:
            if reason != "healthy" or (
                operation_token != "" and not cls._state_operation_token.fullmatch(operation_token)
            ):
                return None
        elif not cls._state_operation_token.fullmatch(operation_token):
            return None
        return _StoreStateSlot(slot_index, int(sequence), state, reason, operation_token)

    @staticmethod
    def _pwrite_all(descriptor: int, payload: bytes, offset: int) -> None:
        if _PWRITE is None:
            raise SecureStoreUnavailableError("secret descriptor write API is unavailable")
        view = memoryview(payload)
        current_offset = offset
        while view:
            written = _PWRITE(descriptor, view.tobytes(), current_offset)
            if written <= 0:
                raise SecureStoreUnavailableError("secret state write made no progress")
            current_offset += written
            view = view[written:]

    def _open_store_state(self) -> tuple[int, FileIdentity, bool]:
        common_flags = os.O_RDWR | int(getattr(os, "O_CLOEXEC", 0))
        common_flags |= int(getattr(os, "O_NOFOLLOW", 0))
        created = False
        try:
            descriptor = os.open(
                self._state_name,
                common_flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=self._root_fd,
            )
            created = True
        except FileExistsError:
            try:
                descriptor = os.open(self._state_name, common_flags, dir_fd=self._root_fd)
            except OSError as error:
                raise SecureStoreUnavailableError("secret store state open failed") from error
        except OSError as error:
            raise SecureStoreUnavailableError("secret store state creation failed") from error
        primary: BaseException | None = None
        try:
            if created:
                if _FCHMOD is None or _POSIX_FALLOCATE is None:
                    raise SecureStoreUnavailableError(
                        "secret store state preallocation APIs are unavailable"
                    )
                _FCHMOD(descriptor, 0o600)
                _POSIX_FALLOCATE(descriptor, 0, self._state_file_size)
                initial = b"".join(
                    (
                        self._encode_state_slot(
                            sequence=1,
                            state=_StoreHealth.HEALTHY,
                            reason="healthy",
                            operation_token="",
                        ),
                        self._encode_state_slot(
                            sequence=0,
                            state=_StoreHealth.HEALTHY,
                            reason="healthy",
                            operation_token="",
                        ),
                    )
                )
                self._pwrite_all(descriptor, initial, 0)
                os.fsync(descriptor)
                if _PREAD is None:
                    raise SecureStoreUnavailableError("secret descriptor read API is unavailable")
                readback = _PREAD(descriptor, self._state_file_size, 0)
                if not secrets.compare_digest(readback, initial):
                    raise SecureStoreUnavailableError(
                        "secret store initial state readback did not match"
                    )
                decoded = tuple(
                    self._decode_state_slot(
                        slot_index,
                        readback[
                            slot_index
                            * self._state_slot_size : (slot_index + 1)
                            * self._state_slot_size
                        ],
                    )
                    for slot_index in range(self._state_slot_count)
                )
                if decoded != (
                    _StoreStateSlot(0, 1, _StoreHealth.HEALTHY, "healthy", ""),
                    _StoreStateSlot(1, 0, _StoreHealth.HEALTHY, "healthy", ""),
                ):
                    raise SecureStoreUnavailableError(
                        "secret store initial state validation failed"
                    )
            metadata = os.fstat(descriptor)
            _validate_secret_metadata(metadata)
            if int(metadata.st_size) != self._state_file_size:
                raise SecureStoreUnavailableError("secret store state size is invalid")
            identity = capture_file_identity(
                self._root_fd,
                self._state_name,
                descriptor,
                expected_uid=_effective_user_id(),
                expected_mode=0o600,
            )
            if not identity.matches_with_size(metadata):
                raise SecureStoreUnavailableError("secret store state identity changed")
            if created:
                self._fsync_directory(self._root_fd)
            return descriptor, identity, created
        except BaseException as error:
            primary = error
            if created:
                error.add_note("manual recovery may be required for an incomplete .store-state")
            raise
        finally:
            if primary is not None:
                close_descriptor(
                    descriptor,
                    primary_error=primary,
                    context="secret store state",
                )

    def _named_entry_exists(self, name: str) -> bool:
        try:
            os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True

    @classmethod
    def _encode_completion_guard_slot(
        cls,
        *,
        sequence: int,
        state: _CompletionGuardState,
        store_sequence: int,
        operation_token: str,
    ) -> bytes:
        if (
            sequence < 0
            or sequence > cls._state_max_sequence
            or store_sequence <= 0
            or store_sequence > cls._state_max_sequence
            or (operation_token != "" and not cls._state_operation_token.fullmatch(operation_token))
            or (state is _CompletionGuardState.FINALIZING and operation_token == "")
            or (
                state is _CompletionGuardState.IDLE
                and operation_token == ""
                and store_sequence != 1
            )
        ):
            raise SecureStoreUnavailableError("secret store completion guard fields are invalid")
        encoded_token = operation_token.encode("ascii")
        token_field = encoded_token + b"\0" * (32 - len(encoded_token))
        header = cls._completion_guard_header.pack(
            cls._completion_guard_magic,
            cls._completion_guard_version,
            int(state),
            0,
            sequence,
            store_sequence,
            token_field,
        )
        body_size = cls._completion_guard_slot_size - cls._completion_guard_checksum_size
        body = header + b"\0" * (body_size - len(header))
        return body + hashlib.sha256(body).digest()

    @classmethod
    def _decode_completion_guard_slot(
        cls,
        slot_index: int,
        payload: bytes,
    ) -> _CompletionGuardSlot | None:
        if len(payload) != cls._completion_guard_slot_size:
            return None
        body = payload[: -cls._completion_guard_checksum_size]
        checksum = payload[-cls._completion_guard_checksum_size :]
        if not secrets.compare_digest(hashlib.sha256(body).digest(), checksum):
            return None
        try:
            (
                magic,
                version,
                state_value,
                reserved,
                sequence,
                store_sequence,
                token_field,
            ) = cls._completion_guard_header.unpack(body[: cls._completion_guard_header.size])
            state = _CompletionGuardState(state_value)
        except (ValueError, struct.error):
            return None
        if (
            magic != cls._completion_guard_magic
            or version != cls._completion_guard_version
            or reserved != 0
            or store_sequence <= 0
            or any(body[cls._completion_guard_header.size :])
        ):
            return None
        encoded_token, separator, trailing = token_field.partition(b"\0")
        if separator and any(trailing):
            return None
        try:
            operation_token = encoded_token.decode("ascii")
        except UnicodeDecodeError:
            return None
        if operation_token != "" and not cls._state_operation_token.fullmatch(operation_token):
            return None
        if state is _CompletionGuardState.FINALIZING and operation_token == "":
            return None
        if state is _CompletionGuardState.IDLE and operation_token == "" and store_sequence != 1:
            return None
        return _CompletionGuardSlot(
            slot_index,
            int(sequence),
            state,
            int(store_sequence),
            operation_token,
        )

    def _open_completion_guard(
        self,
        *,
        create_if_missing: bool,
    ) -> tuple[int, FileIdentity, bool]:
        common_flags = os.O_RDWR | int(getattr(os, "O_CLOEXEC", 0))
        common_flags |= int(getattr(os, "O_NOFOLLOW", 0))
        created = False
        try:
            descriptor = os.open(
                self._completion_guard_name,
                common_flags,
                dir_fd=self._root_fd,
            )
        except FileNotFoundError:
            if not create_if_missing:
                raise
            try:
                descriptor = os.open(
                    self._completion_guard_name,
                    common_flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=self._root_fd,
                )
                created = True
            except FileExistsError:
                descriptor = os.open(
                    self._completion_guard_name,
                    common_flags,
                    dir_fd=self._root_fd,
                )
        except OSError as error:
            raise SecureStoreUnavailableError(
                "secret store completion guard open failed"
            ) from error
        primary: BaseException | None = None
        try:
            if created:
                if _FCHMOD is None or _POSIX_FALLOCATE is None:
                    raise SecureStoreUnavailableError(
                        "secret store completion guard preallocation APIs are unavailable"
                    )
                _FCHMOD(descriptor, 0o600)
                _POSIX_FALLOCATE(descriptor, 0, self._completion_guard_file_size)
                initial = b"".join(
                    (
                        self._encode_completion_guard_slot(
                            sequence=1,
                            state=_CompletionGuardState.IDLE,
                            store_sequence=1,
                            operation_token="",
                        ),
                        self._encode_completion_guard_slot(
                            sequence=0,
                            state=_CompletionGuardState.IDLE,
                            store_sequence=1,
                            operation_token="",
                        ),
                    )
                )
                self._pwrite_all(descriptor, initial, 0)
                os.fsync(descriptor)
                if _PREAD is None:
                    raise SecureStoreUnavailableError("secret descriptor read API is unavailable")
                readback = _PREAD(descriptor, self._completion_guard_file_size, 0)
                if not secrets.compare_digest(readback, initial):
                    raise SecureStoreUnavailableError(
                        "secret store completion guard initial readback did not match"
                    )
                decoded = tuple(
                    self._decode_completion_guard_slot(
                        slot_index,
                        readback[
                            slot_index
                            * self._completion_guard_slot_size : (slot_index + 1)
                            * self._completion_guard_slot_size
                        ],
                    )
                    for slot_index in range(self._completion_guard_slot_count)
                )
                if decoded != (
                    _CompletionGuardSlot(
                        0,
                        1,
                        _CompletionGuardState.IDLE,
                        1,
                        "",
                    ),
                    _CompletionGuardSlot(
                        1,
                        0,
                        _CompletionGuardState.IDLE,
                        1,
                        "",
                    ),
                ):
                    raise SecureStoreUnavailableError(
                        "secret store completion guard initial validation failed"
                    )
            metadata = os.fstat(descriptor)
            _validate_secret_metadata(metadata)
            if int(metadata.st_size) != self._completion_guard_file_size:
                raise SecureStoreUnavailableError("secret store completion guard size is invalid")
            identity = capture_file_identity(
                self._root_fd,
                self._completion_guard_name,
                descriptor,
                expected_uid=_effective_user_id(),
                expected_mode=0o600,
            )
            if not identity.matches_with_size(metadata):
                raise SecureStoreUnavailableError("secret store completion guard identity changed")
            if created:
                self._fsync_directory(self._root_fd)
            return descriptor, identity, created
        except BaseException as error:
            primary = error
            if created:
                error.add_note(
                    "manual recovery may be required for an incomplete " ".store-completion-guard"
                )
            raise
        finally:
            if primary is not None:
                close_descriptor(
                    descriptor,
                    primary_error=primary,
                    context="secret store completion guard",
                )

    def _validate_completion_guard_identity(self) -> None:
        if self._completion_guard_issue is not None:
            raise SecureStoreUnavailableError(self._completion_guard_issue)
        if self._completion_guard_fd < 0:
            raise SecureStoreUnavailableError("completion_guard_missing")
        metadata = os.fstat(self._completion_guard_fd)
        _validate_secret_metadata(metadata)
        if int(metadata.st_size) != self._completion_guard_file_size:
            raise SecureStoreUnavailableError("completion_guard_size_invalid")
        current = capture_file_identity(
            self._root_fd,
            self._completion_guard_name,
            self._completion_guard_fd,
            expected_uid=_effective_user_id(),
            expected_mode=0o600,
        )
        if (
            not self._completion_guard_identity.matches_with_size(metadata)
            or current != self._completion_guard_identity
        ):
            raise SecureStoreUnavailableError("completion_guard_identity_changed")

    def _read_completion_guard_slots(
        self,
    ) -> tuple[_CompletionGuardSlot | None, _CompletionGuardSlot | None]:
        self._validate_completion_guard_identity()
        return self._read_completion_guard_slots_from_descriptor(self._completion_guard_fd)

    def _read_completion_guard_slots_from_descriptor(
        self,
        descriptor: int,
    ) -> tuple[_CompletionGuardSlot | None, _CompletionGuardSlot | None]:
        if _PREAD is None:
            raise SecureStoreUnavailableError("secret descriptor read API is unavailable")
        slots: list[_CompletionGuardSlot | None] = []
        for slot_index in range(self._completion_guard_slot_count):
            payload = _PREAD(
                descriptor,
                self._completion_guard_slot_size,
                slot_index * self._completion_guard_slot_size,
            )
            slots.append(self._decode_completion_guard_slot(slot_index, payload))
        return slots[0], slots[1]

    def _read_completion_guard(self) -> _CompletionGuardSlot:
        if self._completion_guard_issue is not None:
            return _CompletionGuardSlot(
                -1,
                0,
                _CompletionGuardState.FINALIZING,
                0,
                "",
                self._completion_guard_issue,
            )
        return self._select_completion_guard_slots(*self._read_completion_guard_slots())

    @staticmethod
    def _select_completion_guard_slots(
        first: _CompletionGuardSlot | None,
        second: _CompletionGuardSlot | None,
    ) -> _CompletionGuardSlot:
        if first is None or second is None:
            valid_sequence = max(
                (slot.sequence for slot in (first, second) if slot is not None),
                default=0,
            )
            return _CompletionGuardSlot(
                -1,
                valid_sequence,
                _CompletionGuardState.FINALIZING,
                0,
                "",
                "completion_guard_corrupt",
            )
        if first.sequence == second.sequence:
            return _CompletionGuardSlot(
                -1,
                first.sequence,
                _CompletionGuardState.FINALIZING,
                0,
                "",
                "completion_guard_ambiguous",
            )
        older, newer = sorted((first, second), key=lambda slot: slot.sequence)
        if newer.sequence != older.sequence + 1:
            return _CompletionGuardSlot(
                -1,
                newer.sequence,
                _CompletionGuardState.FINALIZING,
                0,
                "",
                "completion_guard_sequence_invalid",
            )
        bootstrap = (
            older.sequence == 0
            and newer.sequence == 1
            and older.state is newer.state is _CompletionGuardState.IDLE
            and older.store_sequence == newer.store_sequence == 1
            and older.operation_token == newer.operation_token == ""
        )
        allowed = (
            older.state is _CompletionGuardState.IDLE
            and newer.state is _CompletionGuardState.FINALIZING
            and newer.store_sequence == older.store_sequence + 2
            and newer.operation_token != older.operation_token
        ) or (
            older.state is _CompletionGuardState.FINALIZING
            and newer.state is _CompletionGuardState.IDLE
            and newer.store_sequence == older.store_sequence
            and newer.operation_token == older.operation_token
        )
        if not bootstrap and not allowed:
            return _CompletionGuardSlot(
                -1,
                newer.sequence,
                _CompletionGuardState.FINALIZING,
                0,
                "",
                "completion_guard_transition_invalid",
            )
        return newer

    def _persist_completion_guard(
        self,
        current: _CompletionGuardSlot,
        *,
        state: _CompletionGuardState,
        store_sequence: int,
        operation_token: str,
        commit_tracker: _MutationCommitTracker | None = None,
    ) -> _CompletionGuardSlot:
        observed = self._read_completion_guard()
        if observed != current or current.slot_index < 0:
            raise SecureStoreUnavailableError("secret store completion guard changed unexpectedly")
        transition = (current.state, state)
        if transition not in {
            (_CompletionGuardState.IDLE, _CompletionGuardState.FINALIZING),
            (_CompletionGuardState.FINALIZING, _CompletionGuardState.IDLE),
        }:
            raise SecureStoreUnavailableError("secret store completion guard transition is invalid")
        if current.sequence >= self._state_max_sequence:
            raise SecureStoreUnavailableError("secret store completion guard sequence exhausted")
        target = _CompletionGuardSlot(
            1 - current.slot_index,
            current.sequence + 1,
            state,
            store_sequence,
            operation_token,
        )
        encoded = self._encode_completion_guard_slot(
            sequence=target.sequence,
            state=target.state,
            store_sequence=target.store_sequence,
            operation_token=target.operation_token,
        )
        before = os.fstat(self._completion_guard_fd)
        if state is _CompletionGuardState.IDLE and commit_tracker is not None:
            commit_tracker.expected_idle = target
            commit_tracker.idle_write_started = True
        self._pwrite_all(
            self._completion_guard_fd,
            encoded,
            target.slot_index * self._completion_guard_slot_size,
        )
        if state is _CompletionGuardState.IDLE and commit_tracker is not None:
            commit_tracker.idle_write_completed = True
        os.fsync(self._completion_guard_fd)
        if state is _CompletionGuardState.IDLE and commit_tracker is not None:
            commit_tracker.idle_fsync_completed = True
        if _PREAD is None:
            raise SecureStoreUnavailableError("secret descriptor read API is unavailable")
        readback = _PREAD(
            self._completion_guard_fd,
            self._completion_guard_slot_size,
            target.slot_index * self._completion_guard_slot_size,
        )
        if not secrets.compare_digest(readback, encoded):
            raise SecureStoreUnavailableError(
                "secret store completion guard readback did not match"
            )
        if self._decode_completion_guard_slot(target.slot_index, readback) != target:
            raise SecureStoreUnavailableError("secret store completion guard validation failed")
        after = os.fstat(self._completion_guard_fd)
        if (
            int(before.st_size) != self._completion_guard_file_size
            or int(after.st_size) != self._completion_guard_file_size
            or (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_nlink,
                before.st_size,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_nlink,
                after.st_size,
            )
        ):
            raise SecureStoreUnavailableError(
                "secret store completion guard identity changed during update"
            )
        self._validate_completion_guard_identity()
        if self._read_completion_guard() != target:
            raise SecureStoreUnavailableError(
                "secret store completion guard transition validation failed"
            )
        if state is _CompletionGuardState.IDLE and commit_tracker is not None:
            commit_tracker.outcome = _MutationCommitOutcome.COMMITTED
        return target

    @staticmethod
    def _completion_guard_block_reason(
        state: _StoreStateSlot,
        guard: _CompletionGuardSlot,
    ) -> str | None:
        if guard.slot_index < 0:
            return guard.reason or "completion_guard_corrupt"
        if state.slot_index < 0 or state.state is _StoreHealth.POISONED:
            return None
        if state.state is _StoreHealth.HEALTHY:
            compatible = (
                guard.store_sequence == state.sequence
                and guard.operation_token == state.operation_token
            )
            if not compatible:
                return "completion_guard_incompatible"
            if guard.state is _CompletionGuardState.FINALIZING:
                return "completion_guard_finalizing"
            return None
        if guard.state is _CompletionGuardState.FINALIZING:
            compatible = (
                guard.store_sequence == state.sequence + 1
                and guard.operation_token == state.operation_token
            )
        else:
            compatible = guard.store_sequence == state.sequence - 1
        if not compatible:
            return "completion_guard_incompatible"
        return (
            "completion_guard_finalizing"
            if guard.state is _CompletionGuardState.FINALIZING
            else None
        )

    def _persist_completion_guard_finalizing(
        self,
        mutating: _StoreStateSlot,
    ) -> _CompletionGuardSlot:
        if mutating.state is not _StoreHealth.MUTATING:
            raise SecureStoreUnavailableError("secret store mutation state is invalid")
        current = self._read_completion_guard()
        if (
            current.slot_index < 0
            or current.state is not _CompletionGuardState.IDLE
            or current.store_sequence != mutating.sequence - 1
        ):
            raise SecureStoreUnavailableError(
                "secret store completion guard is not compatible with MUTATING"
            )
        return self._persist_completion_guard(
            current,
            state=_CompletionGuardState.FINALIZING,
            store_sequence=mutating.sequence + 1,
            operation_token=mutating.operation_token,
        )

    def _persist_completion_guard_idle(
        self,
        finalizing: _CompletionGuardSlot,
        healthy: _StoreStateSlot,
        commit_tracker: _MutationCommitTracker,
    ) -> _CompletionGuardSlot:
        if (
            finalizing.state is not _CompletionGuardState.FINALIZING
            or healthy.state is not _StoreHealth.HEALTHY
            or finalizing.store_sequence != healthy.sequence
            or finalizing.operation_token != healthy.operation_token
        ):
            raise SecureStoreUnavailableError("secret store completion records are incompatible")
        commit_tracker.expected_healthy = healthy
        return self._persist_completion_guard(
            finalizing,
            state=_CompletionGuardState.IDLE,
            store_sequence=healthy.sequence,
            operation_token=healthy.operation_token,
            commit_tracker=commit_tracker,
        )

    def _validate_store_state_identity(self) -> None:
        if self._store_state_issue is not None:
            raise SecureStoreUnavailableError(self._store_state_issue)
        if self._state_fd < 0:
            raise SecureStoreUnavailableError("secret store state is closed")
        metadata = os.fstat(self._state_fd)
        _validate_secret_metadata(metadata)
        if int(metadata.st_size) != self._state_file_size:
            raise SecureStoreUnavailableError("secret store state size is invalid")
        current = capture_file_identity(
            self._root_fd,
            self._state_name,
            self._state_fd,
            expected_uid=_effective_user_id(),
            expected_mode=0o600,
        )
        if not self._state_identity.matches_with_size(metadata) or current != self._state_identity:
            raise SecureStoreUnavailableError("secret store state identity changed")

    def _read_store_state_slots(self) -> tuple[_StoreStateSlot | None, _StoreStateSlot | None]:
        self._validate_store_state_identity()
        return self._read_store_state_slots_from_descriptor(self._state_fd)

    def _read_store_state_slots_from_descriptor(
        self,
        descriptor: int,
    ) -> tuple[_StoreStateSlot | None, _StoreStateSlot | None]:
        if _PREAD is None:
            raise SecureStoreUnavailableError("secret descriptor read API is unavailable")
        slots: list[_StoreStateSlot | None] = []
        for slot_index in range(self._state_slot_count):
            payload = _PREAD(
                descriptor,
                self._state_slot_size,
                slot_index * self._state_slot_size,
            )
            slots.append(self._decode_state_slot(slot_index, payload))
        return slots[0], slots[1]

    def _read_store_state(self) -> _StoreStateSlot:
        return self._select_store_state_slots(*self._read_store_state_slots())

    @staticmethod
    def _select_store_state_slots(
        first: _StoreStateSlot | None,
        second: _StoreStateSlot | None,
    ) -> _StoreStateSlot:
        if first is None or second is None:
            valid_sequence = max(
                (slot.sequence for slot in (first, second) if slot is not None),
                default=0,
            )
            return _StoreStateSlot(
                -1,
                valid_sequence,
                _StoreHealth.POISONED,
                "state_corrupt",
                "",
            )
        if first.sequence == second.sequence:
            return _StoreStateSlot(
                -1,
                first.sequence,
                _StoreHealth.POISONED,
                "state_ambiguous",
                "",
            )
        older, newer = sorted((first, second), key=lambda slot: slot.sequence)
        if newer.sequence != older.sequence + 1:
            return _StoreStateSlot(
                -1,
                newer.sequence,
                _StoreHealth.POISONED,
                "state_sequence_invalid",
                "",
            )
        bootstrap = (
            older.sequence == 0
            and newer.sequence == 1
            and older.state is _StoreHealth.HEALTHY
            and newer.state is _StoreHealth.HEALTHY
            and older.operation_token == newer.operation_token == ""
        )
        allowed = (
            newer.state is _StoreHealth.MUTATING
            and older.state is _StoreHealth.HEALTHY
            and newer.operation_token != older.operation_token
        ) or (
            older.state is _StoreHealth.MUTATING
            and newer.state in {_StoreHealth.HEALTHY, _StoreHealth.POISONED}
            and newer.operation_token == older.operation_token
        )
        if not bootstrap and not allowed:
            return _StoreStateSlot(
                -1,
                newer.sequence,
                _StoreHealth.POISONED,
                "state_transition_invalid",
                "",
            )
        return newer

    def _persist_store_state(
        self,
        current: _StoreStateSlot,
        *,
        state: _StoreHealth,
        reason: str,
        operation_token: str,
    ) -> _StoreStateSlot:
        observed = self._read_store_state()
        if observed != current or current.slot_index < 0:
            raise SecureStoreUnavailableError("secret store state changed unexpectedly")
        transition = (current.state, state)
        if transition not in {
            (_StoreHealth.HEALTHY, _StoreHealth.MUTATING),
            (_StoreHealth.MUTATING, _StoreHealth.HEALTHY),
            (_StoreHealth.MUTATING, _StoreHealth.POISONED),
        }:
            raise SecureStoreUnavailableError("secret store state transition is invalid")
        if current.sequence >= self._state_max_sequence:
            raise SecureStoreUnavailableError("secret store state sequence exhausted")
        target_index = 1 - current.slot_index
        target = _StoreStateSlot(
            target_index,
            current.sequence + 1,
            state,
            reason,
            operation_token,
        )
        encoded = self._encode_state_slot(
            sequence=target.sequence,
            state=target.state,
            reason=target.reason,
            operation_token=target.operation_token,
        )
        before = os.fstat(self._state_fd)
        self._pwrite_all(
            self._state_fd,
            encoded,
            target.slot_index * self._state_slot_size,
        )
        os.fsync(self._state_fd)
        if _PREAD is None:
            raise SecureStoreUnavailableError("secret descriptor read API is unavailable")
        readback = _PREAD(
            self._state_fd,
            self._state_slot_size,
            target.slot_index * self._state_slot_size,
        )
        if not secrets.compare_digest(readback, encoded):
            raise SecureStoreUnavailableError("secret store state readback did not match")
        decoded = self._decode_state_slot(target.slot_index, readback)
        if decoded != target:
            raise SecureStoreUnavailableError("secret store state validation failed")
        after = os.fstat(self._state_fd)
        if (
            int(before.st_size) != self._state_file_size
            or int(after.st_size) != self._state_file_size
            or (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_nlink,
                before.st_size,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_nlink,
                after.st_size,
            )
        ):
            raise SecureStoreUnavailableError("secret store state identity changed during update")
        self._validate_store_state_identity()
        if self._read_store_state() != target:
            raise SecureStoreUnavailableError("secret store state transition validation failed")
        return target

    def _persist_store_mutating(self, reason: str) -> _StoreStateSlot:
        current = self._read_store_state()
        if current.slot_index < 0 or current.state is not _StoreHealth.HEALTHY:
            raise SecureStoreUnavailableError("secret store is not healthy")
        guard = self._read_completion_guard()
        guard_reason = self._completion_guard_block_reason(current, guard)
        if (
            guard_reason is not None
            or guard.slot_index < 0
            or guard.state is not _CompletionGuardState.IDLE
        ):
            raise SecureStoreUnavailableError(
                guard_reason or "secret store completion guard is not idle"
            )
        return self._persist_store_state(
            current,
            state=_StoreHealth.MUTATING,
            reason=reason,
            operation_token=secrets.token_hex(16),
        )

    def _persist_store_healthy(self, mutating: _StoreStateSlot) -> _StoreStateSlot:
        if mutating.state is not _StoreHealth.MUTATING:
            raise SecureStoreUnavailableError("secret store mutation state is invalid")
        return self._persist_store_state(
            mutating,
            state=_StoreHealth.HEALTHY,
            reason="healthy",
            operation_token=mutating.operation_token,
        )

    def _persist_store_poisoned(self, reason: str) -> _StoreStateSlot:
        current = self._read_store_state()
        if current.slot_index < 0 or current.state is not _StoreHealth.MUTATING:
            raise SecureStoreUnavailableError("secret store mutation state is unavailable")
        return self._persist_store_state(
            current,
            state=_StoreHealth.POISONED,
            reason=reason,
            operation_token=current.operation_token,
        )

    @contextmanager
    def _authoritative_protocol_descriptor(
        self,
        name: str,
        expected_identity: FileIdentity,
        expected_size: int,
    ) -> Iterator[int]:
        flags = os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(name, flags, dir_fd=self._root_fd)
        primary: BaseException | None = None
        try:
            metadata = os.fstat(descriptor)
            _validate_secret_metadata(metadata)
            if int(metadata.st_size) != expected_size:
                raise SecureStoreUnavailableError("secret protocol file size changed")
            current = capture_file_identity(
                self._root_fd,
                name,
                descriptor,
                expected_uid=_effective_user_id(),
                expected_mode=0o600,
            )
            if not expected_identity.matches_with_size(metadata) or current != expected_identity:
                raise SecureStoreUnavailableError("secret protocol file identity changed")
            yield descriptor
        except BaseException as error:
            primary = error
            raise
        finally:
            close_descriptor(
                descriptor,
                primary_error=primary,
                context=f"secret protocol file {name}",
            )

    def _authoritative_commit_outcome(
        self,
        commit_tracker: _MutationCommitTracker,
    ) -> _MutationCommitOutcome:
        expected_mutating = commit_tracker.expected_mutating
        expected_healthy = commit_tracker.expected_healthy
        expected_idle = commit_tracker.expected_idle
        if expected_mutating is None or expected_healthy is None or expected_idle is None:
            return _MutationCommitOutcome.COMMIT_INDETERMINATE
        with self._authoritative_protocol_descriptor(
            self._state_name,
            self._state_identity,
            self._state_file_size,
        ) as state_descriptor:
            with self._authoritative_protocol_descriptor(
                self._completion_guard_name,
                self._completion_guard_identity,
                self._completion_guard_file_size,
            ) as guard_descriptor:
                state = self._select_store_state_slots(
                    *self._read_store_state_slots_from_descriptor(state_descriptor)
                )
                guard = self._select_completion_guard_slots(
                    *self._read_completion_guard_slots_from_descriptor(guard_descriptor)
                )
                current_state_identity = capture_file_identity(
                    self._root_fd,
                    self._state_name,
                    state_descriptor,
                    expected_uid=_effective_user_id(),
                    expected_mode=0o600,
                )
                current_guard_identity = capture_file_identity(
                    self._root_fd,
                    self._completion_guard_name,
                    guard_descriptor,
                    expected_uid=_effective_user_id(),
                    expected_mode=0o600,
                )
                if (
                    current_state_identity != self._state_identity
                    or current_guard_identity != self._completion_guard_identity
                ):
                    raise SecureStoreUnavailableError(
                        "secret protocol identity changed during commit validation"
                    )
        if state == expected_healthy and guard == expected_idle:
            return _MutationCommitOutcome.COMMITTED
        expected_finalizing = _CompletionGuardSlot(
            slot_index=1 - expected_idle.slot_index,
            sequence=expected_idle.sequence - 1,
            state=_CompletionGuardState.FINALIZING,
            store_sequence=expected_healthy.sequence,
            operation_token=expected_healthy.operation_token,
        )
        if guard == expected_finalizing and state in (expected_mutating, expected_healthy):
            return _MutationCommitOutcome.NOT_COMMITTED
        return _MutationCommitOutcome.COMMIT_INDETERMINATE

    def _complete_store_mutation(
        self,
        mutating: _StoreStateSlot,
        finalizing: _CompletionGuardSlot,
        commit_tracker: _MutationCommitTracker,
        *,
        primary_error: BaseException | None = None,
    ) -> None:
        try:
            healthy = self._persist_store_healthy(mutating)
            commit_tracker.expected_healthy = healthy
            self._persist_completion_guard_idle(finalizing, healthy, commit_tracker)
            return
        except BaseException as state_error:
            if commit_tracker.outcome is not _MutationCommitOutcome.COMMITTED:
                if commit_tracker.idle_fsync_completed:
                    try:
                        commit_tracker.outcome = self._authoritative_commit_outcome(commit_tracker)
                    except BaseException as validation_error:
                        commit_tracker.outcome = _MutationCommitOutcome.COMMIT_INDETERMINATE
                        state_error.add_note(
                            "authoritative commit validation failed with "
                            f"{type(validation_error).__name__}"
                        )
                elif commit_tracker.idle_write_started:
                    commit_tracker.outcome = _MutationCommitOutcome.COMMIT_INDETERMINATE
            if commit_tracker.outcome is _MutationCommitOutcome.COMMITTED:
                self._log_post_commit_failure(
                    "secret mutation committed before post-commit failure",
                    state_error,
                )
                if primary_error is not None:
                    primary_error.add_note(
                        "secret store mutation was durably committed before a "
                        f"post-commit {type(state_error).__name__}"
                    )
                return
            if commit_tracker.outcome is _MutationCommitOutcome.COMMIT_INDETERMINATE:
                self._fatal_reason = "mutation_commit_indeterminate"
                indeterminate_failure = MutationCommitIndeterminateError()
                indeterminate_failure.add_note(
                    "commit validation failed with " f"{type(state_error).__name__}"
                )
                if primary_error is not None:
                    indeterminate_failure.add_note(
                        "mutation body also failed with " f"{type(primary_error).__name__}"
                    )
                raise indeterminate_failure from state_error
            self._fatal_reason = "mutation_not_committed"
            if primary_error is not None:
                primary_error.add_note(
                    "secondary mutation completion failure: " f"{type(state_error).__name__}"
                )
                return
            not_committed_failure = SecureStoreUnavailableError("mutation_not_committed")
            not_committed_failure.add_note(
                "HEALTHY or IDLE persistence failure: " f"{type(state_error).__name__}"
            )
            raise not_committed_failure from state_error

    @contextmanager
    def _durable_mutation(
        self,
        reason: str,
        commit_tracker: _MutationCommitTracker,
    ) -> Iterator[_StoreStateSlot]:
        mutating = self._persist_store_mutating(reason)
        commit_tracker.operation_token = mutating.operation_token
        commit_tracker.expected_mutating = mutating
        try:
            finalizing = self._persist_completion_guard_finalizing(mutating)
        except BaseException as guard_error:
            self._fatal_reason = "completion_guard_finalizing_failed"
            failure = SecureStoreUnavailableError("completion_guard_finalizing_failed")
            failure.add_note(f"FINALIZING persistence failure: {guard_error!r}")
            raise failure from guard_error
        try:
            yield mutating
        except BaseException as primary:
            current = self._read_store_state()
            if current == mutating and self._fatal_reason is None:
                self._complete_store_mutation(
                    mutating,
                    finalizing,
                    commit_tracker,
                    primary_error=primary,
                )
            elif current.slot_index >= 0 and current.state is _StoreHealth.HEALTHY:
                primary.add_note("secret store mutation ended in an unexpected HEALTHY state")
                self._fatal_reason = "mutation_state_invalid"
            if (
                isinstance(primary, _AppliedMutationCleanupError)
                and commit_tracker.outcome is _MutationCommitOutcome.COMMITTED
            ):
                commit_tracker.body_succeeded = True
                self._fatal_reason = "post_commit_close_failed"
                self._log_post_commit_failure(
                    "secret mutation committed but descriptor cleanup failed",
                    primary.cleanup_error,
                )
                return
            raise
        else:
            commit_tracker.body_succeeded = True
            current = self._read_store_state()
            if current != mutating:
                self._fatal_reason = "mutation_state_invalid"
                raise SecureStoreUnavailableError("secret store mutation state changed")
            self._complete_store_mutation(mutating, finalizing, commit_tracker)

    def _validate_store_lock_identity(self) -> None:
        metadata = os.fstat(self._lock_fd)
        _validate_secret_metadata(metadata)
        current = capture_file_identity(
            self._root_fd,
            self._lock_name,
            self._lock_fd,
            expected_uid=_effective_user_id(),
            expected_mode=0o600,
        )
        if (
            not self._lock_identity.matches(metadata)
            or current.directory_dev != self._lock_identity.directory_dev
            or current.directory_ino != self._lock_identity.directory_ino
            or current.relative_name != self._lock_identity.relative_name
            or not self._valid_lock_payload(self._lock_fd, int(metadata.st_size))
        ):
            raise SecureStoreUnavailableError("secret store lock identity changed")

    @classmethod
    def _valid_lock_payload(cls, descriptor: int, size: int) -> bool:
        del cls, descriptor
        return size == 0

    @staticmethod
    def _flock(descriptor: int, operation: int) -> None:
        fcntl = importlib.import_module("fcntl")
        fcntl.flock(descriptor, operation)

    def _raise_fatal_reason(self) -> None:
        if self._fatal_reason == "mutation_commit_indeterminate":
            raise MutationCommitIndeterminateError()
        if self._fatal_reason is not None:
            raise SecureStoreUnavailableError(self._fatal_reason)

    @contextmanager
    def _process_shared_lock(
        self,
        *,
        allow_poisoned: bool = False,
        state_required: bool = True,
        commit_tracker: _MutationCommitTracker | None = None,
    ) -> Iterator[None]:
        """Cooperative serialization; callers hold the instance RLock first."""

        try:
            fcntl = importlib.import_module("fcntl")
        except ModuleNotFoundError as error:
            raise SecureStoreUnavailableError("Linux process locking is unavailable") from error
        if self._fatal_reason is not None and not allow_poisoned:
            self._raise_fatal_reason()
        if self._lock_fd < 0:
            raise SecureStoreUnavailableError("secret store is closed")
        deadline = time.monotonic() + self._process_lock_timeout_seconds
        while True:
            try:
                self._flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as error:
                if error.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise SecureStoreUnavailableError("secret store process lock failed") from error
                if time.monotonic() >= deadline:
                    raise SecureStoreUnavailableError(
                        "secret store process lock timed out"
                    ) from error
                time.sleep(
                    min(
                        self._process_lock_retry_seconds,
                        max(0.0, deadline - time.monotonic()),
                    )
                )
        primary: BaseException | None = None
        lock_descriptor = self._lock_fd
        try:
            self._validate_store_lock_identity()
            if state_required:
                self._validate_store_state_identity()
                self._validate_completion_guard_identity()
            if not allow_poisoned:
                self._raise_if_poisoned()
            yield
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                self._flock(lock_descriptor, fcntl.LOCK_UN)
            except BaseException as unlock_error:
                if self._lock_fd == lock_descriptor:
                    self._lock_fd = -1
                try:
                    close_descriptor(
                        lock_descriptor,
                        primary_error=unlock_error,
                        context="secret store process lock after unlock failure",
                    )
                except BaseException as close_error:
                    unlock_error.add_note(
                        "lock descriptor close failed with " f"{type(close_error).__name__}"
                    )
                if primary is not None:
                    primary.add_note(
                        "secondary secret store unlock failure: " f"{type(unlock_error).__name__}"
                    )
                elif (
                    commit_tracker is not None
                    and commit_tracker.body_succeeded
                    and commit_tracker.outcome is _MutationCommitOutcome.COMMITTED
                ):
                    self._fatal_reason = "post_commit_unlock_failed"
                    self._log_post_commit_failure(
                        "secret mutation committed but process unlock failed",
                        unlock_error,
                    )
                else:
                    self._fatal_reason = "process_unlock_failed"
                    raise SecureStoreUnavailableError(
                        "secret store process unlock failed"
                    ) from unlock_error

    def _raise_if_poisoned(self) -> None:
        if self._fatal_reason is not None:
            self._raise_fatal_reason()
        state = self._read_store_state()
        if state.slot_index < 0:
            raise SecureStoreUnavailableError(f"secret store state is corrupt ({state.reason})")
        guard = self._read_completion_guard()
        if state.state is _StoreHealth.MUTATING:
            guard_reason = self._completion_guard_block_reason(state, guard)
            raise SecureStoreUnavailableError(
                "secret store requires manual recovery after interrupted mutation "
                f"({guard_reason or state.reason})"
            )
        if state.state is _StoreHealth.POISONED:
            raise SecureStoreUnavailableError(
                f"secret store requires manual recovery ({state.reason})"
            )
        guard_reason = self._completion_guard_block_reason(state, guard)
        if guard_reason is not None:
            raise SecureStoreUnavailableError(guard_reason)
        try:
            payload = self._read_file(self._poison_name, len(self._poison_payload))
        except FileNotFoundError:
            return
        if payload != self._poison_payload:
            raise SecureStoreUnavailableError("secret store recovery marker is invalid")
        raise SecureStoreUnavailableError("secret store requires manual recovery")

    def _mark_store_poisoned(self, primary: BaseException, reason: str) -> None:
        issue = f"manual_recovery_required:{reason}"
        if issue not in self._recovery_issues:
            self._recovery_issues.append(issue)
        try:
            persisted = self._persist_store_poisoned(reason)
        except BaseException as state_error:
            self._fatal_reason = "poison_persistence_failed"
            primary.add_note(
                f"secret store POISONED persistence failed; durable MUTATING remains: "
                f"{state_error!r}"
            )
            self._write_recovery_marker(primary)
            return
        primary.add_note(
            f"secret store durable poison sequence {persisted.sequence} reason {persisted.reason}"
        )
        self._fatal_reason = "store_poisoned"
        self._write_recovery_marker(primary)

    def _write_recovery_marker(self, primary: BaseException) -> None:
        descriptor = -1
        try:
            descriptor = os.open(
                self._poison_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | int(getattr(os, "O_CLOEXEC", 0))
                | int(getattr(os, "O_NOFOLLOW", 0)),
                0o600,
                dir_fd=self._root_fd,
            )
            if _FCHMOD is None:
                raise SecureStoreUnavailableError("secret file mode API is unavailable")
            _FCHMOD(descriptor, 0o600)
            self._write_all(descriptor, self._poison_payload)
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            _validate_secret_metadata(metadata)
            if int(metadata.st_size) != len(self._poison_payload):
                raise SecureStoreUnavailableError("secret store recovery marker is incomplete")
            capture_file_identity(
                self._root_fd,
                self._poison_name,
                descriptor,
                expected_uid=_effective_user_id(),
                expected_mode=0o600,
            )
            self._fsync_directory(self._root_fd)
        except FileExistsError:
            try:
                payload = self._read_file(self._poison_name, len(self._poison_payload))
                if payload != self._poison_payload:
                    raise SecureStoreUnavailableError("secret store recovery marker is invalid")
            except BaseException as marker_error:
                primary.add_note(f"secret recovery marker validation also failed: {marker_error!r}")
        except BaseException as marker_error:
            primary.add_note(f"secret recovery marker creation also failed: {marker_error!r}")
        finally:
            if descriptor >= 0:
                close_descriptor(
                    descriptor,
                    primary_error=primary,
                    context="secret store recovery marker",
                )

    def _open_file(self, name: str) -> int:
        flags = os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0))
        try:
            return os.open(name, flags, dir_fd=self._root_fd)
        except FileNotFoundError:
            raise
        except OSError as error:
            raise SecureStoreUnavailableError("secret file open failed") from error

    def _read_file(self, name: str, maximum_bytes: int) -> bytes:
        descriptor = self._open_file(name)
        primary: BaseException | None = None
        try:
            before = os.fstat(descriptor)
            _validate_secret_metadata(before)
            try:
                named_before = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
            except OSError as error:
                raise SecureStoreUnavailableError("secret file changed during read") from error
            _validate_secret_metadata(named_before)
            if _metadata_identity(before) != _metadata_identity(named_before):
                raise SecureStoreUnavailableError("secret file changed during read")
            chunks: list[bytes] = []
            remaining = maximum_bytes + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            after = os.fstat(descriptor)
            _validate_secret_metadata(after)
            try:
                named_after = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
            except OSError as error:
                raise SecureStoreUnavailableError("secret file changed during read") from error
            _validate_secret_metadata(named_after)
            if _metadata_identity(before) != _metadata_identity(after) or _metadata_identity(
                after
            ) != _metadata_identity(named_after):
                raise SecureStoreUnavailableError("secret file changed during read")
            if len(data) > maximum_bytes or len(data) != after.st_size:
                raise SecureStoreUnavailableError("secret file has an invalid size")
            return data
        except BaseException as error:
            primary = error
            raise
        finally:
            close_descriptor(
                descriptor,
                primary_error=primary,
                context=f"secret file {name}",
            )

    @staticmethod
    def _write_all(descriptor: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise SecureStoreUnavailableError("secret file write made no progress")
            view = view[written:]

    def _create_open_file(self, name: str, data: bytes) -> _OpenSecretFile:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(name, flags, 0o600, dir_fd=self._root_fd)
        identity: FileIdentity | None = None
        primary: BaseException | None = None
        try:
            self._write_all(descriptor, data)
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            _validate_secret_metadata(metadata)
            if int(metadata.st_size) != len(data):
                raise SecureStoreUnavailableError("secret file has an invalid size")
            identity = capture_file_identity(
                self._root_fd,
                name,
                descriptor,
                expected_uid=_effective_user_id(),
                expected_mode=0o600,
            )
            if not identity.matches_with_size(metadata) or identity.st_size != len(data):
                raise SecureStoreUnavailableError("secret file identity changed during creation")
            return _OpenSecretFile(name, descriptor, identity, len(data))
        except BaseException as error:
            primary = error
            if identity is not None:
                quarantine = self._quarantine_identity(
                    identity,
                    prefix=".secret-quarantine-",
                    context="secret_creation",
                    primary_error=primary,
                )
                if not quarantine.logical_deletion_confirmed:
                    self._mark_store_poisoned(primary, "secret_creation_cleanup_unproven")
            else:
                primary.add_note(f"manual recovery may be required for secret file {name}")
                self._mark_store_poisoned(primary, "secret_creation_identity_unproven")
            close_descriptor(
                descriptor,
                primary_error=primary,
                context=f"new secret file {name}",
            )
            raise

    @staticmethod
    def _close_open_file(
        opened: _OpenSecretFile | None,
        *,
        primary_error: BaseException | None = None,
    ) -> None:
        if opened is None or opened.closed:
            return
        opened.closed = True
        close_descriptor(
            opened.descriptor,
            primary_error=primary_error,
            context=f"secret file {opened.name}",
        )

    def _create_file(self, name: str, data: bytes) -> FileIdentity:
        opened = self._create_open_file(name, data)
        try:
            self._close_open_file(opened)
        except BaseException as error:
            quarantine = self._quarantine_identity(
                opened.identity,
                prefix=".secret-quarantine-",
                context="secret_creation",
                primary_error=error,
            )
            if not quarantine.logical_deletion_confirmed:
                self._mark_store_poisoned(error, "secret_creation_cleanup_unproven")
            raise
        return opened.identity

    def _load_or_create_master_key(
        self,
        commit_tracker: _MutationCommitTracker,
    ) -> bytes:
        try:
            stored = self._read_file(".master-key", 32)
        except FileNotFoundError:
            stored = b""
        if stored:
            if len(stored) != 32:
                raise SecureStoreUnavailableError("secret master key has an invalid length")
            self._aesgcm(stored)
            return stored

        with self._durable_mutation("master_key_init", commit_tracker):
            created_identity: FileIdentity | None = None
            key = secrets.token_bytes(32)
            try:
                created_identity = self._create_file(".master-key", key)
                self._fsync_directory(self._root_fd)
            except FileExistsError:
                pass
            except BaseException as error:
                failure = (
                    error
                    if isinstance(error, SecureStoreUnavailableError)
                    else SecureStoreUnavailableError("secret master key creation failed")
                )
                if created_identity is not None:
                    quarantine = self._quarantine_identity(
                        created_identity,
                        prefix=".master-key-quarantine-",
                        context="master_key",
                        primary_error=failure,
                    )
                    if not quarantine.logical_deletion_confirmed:
                        self._mark_store_poisoned(failure, "master_key_cleanup_unproven")
                if failure is error:
                    raise
                raise failure from error
            try:
                stored = self._read_file(".master-key", 32)
            except FileNotFoundError as error:
                failure = SecureStoreUnavailableError(
                    "secret master key disappeared during initialization"
                )
                if created_identity is not None:
                    quarantine = self._quarantine_identity(
                        created_identity,
                        prefix=".master-key-quarantine-",
                        context="master_key",
                        primary_error=failure,
                    )
                    if not quarantine.logical_deletion_confirmed:
                        self._mark_store_poisoned(failure, "master_key_cleanup_unproven")
                raise failure from error
            except BaseException as error:
                if created_identity is not None:
                    quarantine = self._quarantine_identity(
                        created_identity,
                        prefix=".master-key-quarantine-",
                        context="master_key",
                        primary_error=error,
                    )
                    if not quarantine.logical_deletion_confirmed:
                        self._mark_store_poisoned(error, "master_key_cleanup_unproven")
                raise
            try:
                if len(stored) != 32:
                    raise SecureStoreUnavailableError("secret master key has an invalid length")
                self._aesgcm(stored)
            except BaseException as error:
                if created_identity is not None:
                    quarantine = self._quarantine_identity(
                        created_identity,
                        prefix=".master-key-quarantine-",
                        context="master_key",
                        primary_error=error,
                    )
                    if not quarantine.logical_deletion_confirmed:
                        self._mark_store_poisoned(error, "master_key_cleanup_unproven")
                raise
            return stored

    def _validate_master_key(self) -> None:
        current = self._read_file(".master-key", 32)
        if len(current) != 32 or not secrets.compare_digest(current, self._master_key):
            raise SecureStoreUnavailableError("secret master key changed unexpectedly")

    @staticmethod
    def _name(key: str) -> str:
        if not _KEY.fullmatch(key):
            raise ValueError("invalid secret key")
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return f"secret-{digest}"

    def _read_open_file(self, opened: _OpenSecretFile, maximum_bytes: int) -> bytes:
        os.lseek(opened.descriptor, 0, os.SEEK_SET)
        before = os.fstat(opened.descriptor)
        _validate_secret_metadata(before)
        if (
            not opened.identity.matches_with_size(before)
            or int(before.st_size) != opened.expected_size
        ):
            raise SecureStoreUnavailableError("secret descriptor identity changed")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(opened.descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(opened.descriptor)
        _validate_secret_metadata(after)
        if (
            _metadata_identity(before) != _metadata_identity(after)
            or not opened.identity.matches_with_size(after)
            or len(data) > maximum_bytes
            or len(data) != int(after.st_size)
        ):
            raise SecureStoreUnavailableError("secret file changed during validation")
        return data

    def _validate_ciphertext(
        self,
        encrypted: bytes,
        *,
        key: str,
        expected_plaintext: bytes | None,
    ) -> bytes:
        if len(encrypted) < 29:
            raise SecureStoreUnavailableError("encrypted secret file has an invalid size")
        try:
            plaintext = cast(
                bytes,
                self._aesgcm(self._master_key).decrypt(
                    encrypted[:12],
                    encrypted[12:],
                    key.encode("utf-8"),
                ),
            )
        except Exception as error:
            raise SecureStoreUnavailableError("encrypted secret validation failed") from error
        if expected_plaintext is not None and not secrets.compare_digest(
            plaintext, expected_plaintext
        ):
            raise SecureStoreUnavailableError("encrypted secret plaintext self-check failed")
        return plaintext

    def _open_existing_secret(self, name: str, key: str) -> _OpenSecretFile:
        descriptor = self._open_file(name)
        opened: _OpenSecretFile | None = None
        primary: BaseException | None = None
        try:
            metadata = os.fstat(descriptor)
            _validate_secret_metadata(metadata)
            identity = capture_file_identity(
                self._root_fd,
                name,
                descriptor,
                expected_uid=_effective_user_id(),
                expected_mode=0o600,
            )
            opened = _OpenSecretFile(name, descriptor, identity, int(metadata.st_size))
            encrypted = self._read_open_file(opened, _MAX_SECRET_BYTES)
            self._validate_ciphertext(encrypted, key=key, expected_plaintext=None)
            return opened
        except BaseException as error:
            primary = error
            raise
        finally:
            if primary is not None:
                if opened is None:
                    close_descriptor(
                        descriptor,
                        primary_error=primary,
                        context=f"existing secret file {name}",
                    )
                else:
                    self._close_open_file(opened, primary_error=primary)

    def _temporary_file(self, data: bytes) -> _OpenSecretFile:
        for _ in range(16):
            name = f".pending-{secrets.token_hex(16)}"
            try:
                return self._create_open_file(name, data)
            except FileExistsError:
                continue
            except OSError as error:
                raise SecureStoreUnavailableError("temporary secret creation failed") from error
        raise SecureStoreUnavailableError("temporary secret name allocation failed")

    def _validate_published_secret(
        self,
        name: str,
        temporary: _OpenSecretFile,
        *,
        key: str,
        requested_plaintext: bytes,
        expected_ciphertext: bytes,
    ) -> None:
        descriptor = self._open_file(name)
        primary: BaseException | None = None
        try:
            before = os.fstat(descriptor)
            temporary_metadata = os.fstat(temporary.descriptor)
            _validate_secret_metadata(before)
            _validate_secret_metadata(temporary_metadata)
            if (
                not temporary.identity.matches_with_size(temporary_metadata)
                or not temporary.identity.matches_with_size(before)
                or _metadata_identity(temporary_metadata) != _metadata_identity(before)
                or int(before.st_size) != temporary.expected_size
            ):
                raise SecureStoreUnavailableError(
                    "published secret does not match the retained temporary identity"
                )
            published = _OpenSecretFile(
                name,
                descriptor,
                replace(temporary.identity, relative_name=name),
                temporary.expected_size,
            )
            encrypted = self._read_open_file(published, _MAX_SECRET_BYTES)
            if not secrets.compare_digest(encrypted, expected_ciphertext):
                raise SecureStoreUnavailableError("published secret ciphertext self-check failed")
            self._validate_ciphertext(
                encrypted,
                key=key,
                expected_plaintext=requested_plaintext,
            )
            os.fsync(descriptor)
        except BaseException as error:
            primary = error
            raise
        finally:
            close_descriptor(
                descriptor,
                primary_error=primary,
                context=f"published secret file {name}",
            )

    def _verify_named_open_file(self, name: str, opened: _OpenSecretFile) -> None:
        descriptor = self._open_file(name)
        primary: BaseException | None = None
        try:
            named = os.fstat(descriptor)
            retained = os.fstat(opened.descriptor)
            _validate_secret_metadata(named)
            if (
                not opened.identity.matches_with_size(named)
                or not opened.identity.matches_with_size(retained)
                or _metadata_identity(named) != _metadata_identity(retained)
            ):
                raise SecureStoreUnavailableError("secret rollback identity could not be proven")
        except BaseException as error:
            primary = error
            raise
        finally:
            close_descriptor(
                descriptor,
                primary_error=primary,
                context=f"rollback secret file {name}",
            )

    def _rollback_exchange(
        self,
        *,
        name: str,
        temporary: _OpenSecretFile,
        previous: _OpenSecretFile,
        primary: BaseException,
    ) -> bool:
        try:
            rename_exchange(self._root_fd, temporary.name, self._root_fd, name)
            self._verify_named_open_file(name, previous)
            self._verify_named_open_file(temporary.name, temporary)
            self._fsync_directory(self._root_fd)
        except BaseException as rollback_error:
            primary.add_note(f"secret exchange rollback also failed: {rollback_error!r}")
            primary.add_note("manual recovery required for retained secret exchange objects")
            self._mark_store_poisoned(primary, "exchange_rollback_unproven")
            return False
        restored_new_identity = replace(
            temporary.identity,
            relative_name=temporary.name,
        )
        result = self._quarantine_identity(
            restored_new_identity,
            prefix=".secret-quarantine-",
            context="secret_rollback",
            primary_error=primary,
        )
        if not result.logical_deletion_confirmed:
            primary.add_note("new secret remained outside a confirmed logical quarantine")
            self._mark_store_poisoned(primary, "exchange_cleanup_unproven")
            return False
        return True

    def put(self, key: str, value: str) -> None:
        name = self._name(key)
        commit_tracker = _MutationCommitTracker()
        with self._operation_lock:
            with self._process_shared_lock(commit_tracker=commit_tracker):
                with self._durable_mutation("put", commit_tracker):
                    self._put_locked(key, value, name)

    def _put_locked(self, key: str, value: str, name: str) -> None:
        self._validate_master_key()
        nonce = secrets.token_bytes(12)
        try:
            encrypted = nonce + self._aesgcm(self._master_key).encrypt(
                nonce, value.encode("utf-8"), key.encode("utf-8")
            )
        except Exception as error:
            raise SecureStoreUnavailableError("secret encryption failed") from error
        requested_plaintext = value.encode("utf-8")
        temporary = self._temporary_file(encrypted)
        previous: _OpenSecretFile | None = None
        publication: str | None = None
        final_validated = False
        primary: BaseException | None = None
        cause: BaseException | None = None
        try:
            try:
                previous = self._open_existing_secret(name, key)
            except FileNotFoundError:
                previous = None
            if previous is None:
                rename_noreplace(
                    self._root_fd,
                    temporary.name,
                    self._root_fd,
                    name,
                )
                publication = "create"
            else:
                rename_exchange(
                    self._root_fd,
                    temporary.name,
                    self._root_fd,
                    name,
                )
                publication = "exchange"
            self._validate_published_secret(
                name,
                temporary,
                key=key,
                requested_plaintext=requested_plaintext,
                expected_ciphertext=encrypted,
            )
            self._fsync_directory(self._root_fd)
            final_validated = True
            if previous is not None:
                old_identity = replace(previous.identity, relative_name=temporary.name)
                quarantine = self._quarantine_identity(
                    old_identity,
                    prefix=".secret-quarantine-",
                    context="previous_secret",
                )
                if not quarantine.logical_deletion_confirmed:
                    raise SecureStoreUnavailableError(
                        "previous secret logical quarantine was not durable"
                    )
        except SecureStoreUnavailableError as error:
            primary = error
        except OSError as error:
            primary = SecureStoreUnavailableError("encrypted secret write failed")
            cause = error
        except BaseException as error:
            primary = error
        if primary is not None:
            try:
                if publication == "exchange" and not final_validated and previous is not None:
                    self._rollback_exchange(
                        name=name,
                        temporary=temporary,
                        previous=previous,
                        primary=primary,
                    )
                elif publication == "exchange" and final_validated:
                    self._mark_store_poisoned(primary, "previous_secret_quarantine_unproven")
                elif publication == "create":
                    quarantine = self._quarantine_identity(
                        replace(temporary.identity, relative_name=name),
                        prefix=".secret-quarantine-",
                        context="failed_secret_create",
                        primary_error=primary,
                    )
                    if not quarantine.logical_deletion_confirmed:
                        self._mark_store_poisoned(primary, "secret_create_rollback_unproven")
                elif publication is None:
                    quarantine = self._quarantine_identity(
                        temporary.identity,
                        prefix=".secret-quarantine-",
                        context="failed_secret_publication",
                        primary_error=primary,
                    )
                    if not quarantine.logical_deletion_confirmed:
                        self._mark_store_poisoned(
                            primary,
                            "secret_publication_cleanup_unproven",
                        )
            except BaseException as recovery_error:
                if recovery_error is not primary:
                    recovery_error.add_note(
                        f"original secret update failure type: {type(primary).__name__}"
                    )
                primary = recovery_error
        applied = primary is None
        try:
            self._close_open_file(previous, primary_error=primary)
        except BaseException as close_error:
            primary = close_error
        try:
            self._close_open_file(temporary, primary_error=primary)
        except BaseException as close_error:
            primary = close_error
        if primary is not None:
            if applied:
                raise _AppliedMutationCleanupError(primary) from primary
            if cause is not None:
                raise primary from cause
            raise primary

    def get(self, key: str) -> str | None:
        name = self._name(key)
        with self._operation_lock:
            with self._process_shared_lock():
                self._validate_master_key()
                try:
                    encrypted = self._read_file(name, _MAX_SECRET_BYTES)
                except FileNotFoundError:
                    return None
                if len(encrypted) < 29:
                    raise SecureStoreUnavailableError("encrypted secret file has an invalid size")
                try:
                    plaintext = cast(
                        bytes,
                        self._aesgcm(self._master_key).decrypt(
                            encrypted[:12], encrypted[12:], key.encode("utf-8")
                        ),
                    )
                    return plaintext.decode("utf-8")
                except Exception as error:
                    raise SecureStoreUnavailableError(
                        "encrypted secret validation failed"
                    ) from error

    def delete(self, key: str) -> None:
        name = self._name(key)
        commit_tracker = _MutationCommitTracker()
        with self._operation_lock:
            with self._process_shared_lock(commit_tracker=commit_tracker):
                with self._durable_mutation("delete", commit_tracker):
                    self._delete_locked(name)

    def _delete_locked(self, name: str) -> None:
        self._validate_master_key()
        try:
            descriptor = self._open_file(name)
        except FileNotFoundError:
            return
        primary: BaseException | None = None
        cause: BaseException | None = None
        try:
            identity = capture_file_identity(
                self._root_fd,
                name,
                descriptor,
                expected_uid=_effective_user_id(),
                expected_mode=0o600,
            )
            quarantine = self._quarantine_identity(
                identity,
                prefix=".secret-quarantine-",
                context="deleted_secret",
            )
            if not quarantine.logical_deletion_confirmed:
                raise SecureStoreUnavailableError(
                    "encrypted secret logical quarantine was not durable"
                )
        except SecureStoreUnavailableError as error:
            primary = error
            self._mark_store_poisoned(primary, "secret_delete_unproven")
        except BaseException as error:
            primary = SecureStoreUnavailableError("encrypted secret deletion failed")
            cause = error
            self._mark_store_poisoned(primary, "secret_delete_unproven")
        applied = primary is None
        try:
            close_descriptor(
                descriptor,
                primary_error=primary,
                context=f"secret file {name}",
            )
        except BaseException as close_error:
            if applied:
                primary = _AppliedMutationCleanupError(close_error)
                cause = close_error
            else:
                primary = SecureStoreUnavailableError("encrypted secret descriptor close failed")
                cause = close_error
        if primary is not None:
            if cause is not None:
                raise primary from cause
            raise primary

    async def aput(self, key: str, value: str) -> None:
        await asyncio.to_thread(self.put, key, value)

    async def aget(self, key: str) -> str | None:
        return await asyncio.to_thread(self.get, key)

    async def adelete(self, key: str) -> None:
        await asyncio.to_thread(self.delete, key)

    def doctor(self) -> DoctorCheck:
        try:
            with self._operation_lock:
                if self._fatal_reason is not None:
                    return DoctorCheck(
                        name="secret_store",
                        status="BLOCKED",
                        detail=f"BLOCKED_{self._fatal_reason.upper()}",
                    )
                with self._process_shared_lock(
                    allow_poisoned=True,
                    state_required=False,
                ):
                    _validate_private_directory_metadata(os.fstat(self._root_fd))
                    if self._store_state_issue is not None:
                        return DoctorCheck(
                            name="secret_store",
                            status="BLOCKED",
                            detail=f"BLOCKED_{self._store_state_issue.upper()}",
                        )
                    self._validate_store_state_identity()
                    state = self._read_store_state()
                    if state.slot_index < 0:
                        return DoctorCheck(
                            name="secret_store",
                            status="BLOCKED",
                            detail=f"BLOCKED_STATE_CORRUPT ({state.reason})",
                        )
                    guard = self._read_completion_guard()
                    if guard.slot_index < 0:
                        guard_detail = (guard.reason or "completion_guard_corrupt").upper()
                        return DoctorCheck(
                            name="secret_store",
                            status="BLOCKED",
                            detail=f"BLOCKED_{guard_detail}",
                        )
                    if state.state is _StoreHealth.MUTATING:
                        guard_reason = self._completion_guard_block_reason(state, guard)
                        detail = (
                            "BLOCKED_MUTATING_FINALIZING"
                            if guard_reason == "completion_guard_finalizing"
                            else "BLOCKED_MUTATING"
                        )
                        return DoctorCheck(
                            name="secret_store",
                            status="BLOCKED",
                            detail=f"{detail} ({state.reason})",
                        )
                    if state.state is _StoreHealth.POISONED:
                        return DoctorCheck(
                            name="secret_store",
                            status="BLOCKED",
                            detail=f"BLOCKED_POISONED ({state.reason})",
                        )
                    guard_reason = self._completion_guard_block_reason(state, guard)
                    if guard_reason is not None:
                        detail = (
                            "BLOCKED_COMPLETION_FINALIZING"
                            if guard_reason == "completion_guard_finalizing"
                            else f"BLOCKED_{guard_reason.upper()}"
                        )
                        return DoctorCheck(
                            name="secret_store",
                            status="BLOCKED",
                            detail=detail,
                        )
                    try:
                        marker = self._read_file(self._poison_name, len(self._poison_payload))
                    except FileNotFoundError:
                        marker = None
                    if marker is not None:
                        return DoctorCheck(
                            name="secret_store",
                            status="BLOCKED",
                            detail="BLOCKED_MANUAL_RECOVERY",
                        )
                    self._validate_master_key()
                    pending = set(self._recovery_issues)
                    with os.scandir(self._root_fd) as entries:
                        for entry in entries:
                            if entry.name.startswith(
                                (".secret-quarantine-", ".master-key-quarantine-")
                            ):
                                pending.add(f"physical_delete_pending:{entry.name}")
        except (OSError, SecureStoreUnavailableError):
            return DoctorCheck(
                name="secret_store",
                status="BLOCKED",
                detail="Encrypted Linux secret store ownership or integrity is unsafe",
            )
        if pending:
            return DoctorCheck(
                name="secret_store",
                status="DEGRADED",
                detail=(
                    "Encrypted files are safe but logical quarantine requires offline "
                    f"physical maintenance ({len(pending)} objects)"
                ),
            )
        return DoctorCheck(
            name="secret_store",
            status="OK",
            detail="Encrypted files are anchored below owner-only 0700/0600 storage",
        )

    def close(self) -> None:
        with self._operation_lock:
            guard_descriptor = getattr(self, "_completion_guard_fd", -1)
            state_descriptor = getattr(self, "_state_fd", -1)
            lock_descriptor = getattr(self, "_lock_fd", -1)
            root_descriptor = getattr(self, "_root_fd", -1)
            self._completion_guard_fd = -1
            self._state_fd = -1
            self._lock_fd = -1
            self._root_fd = -1
            primary: BaseException | None = None
            if guard_descriptor >= 0:
                try:
                    close_descriptor(
                        guard_descriptor,
                        context="secret store completion guard",
                    )
                except BaseException as error:
                    primary = error
            if state_descriptor >= 0:
                try:
                    close_descriptor(
                        state_descriptor,
                        primary_error=primary,
                        context="secret store state",
                    )
                except BaseException as error:
                    if primary is None:
                        primary = error
            if lock_descriptor >= 0:
                try:
                    close_descriptor(
                        lock_descriptor,
                        primary_error=primary,
                        context="secret store process lock",
                    )
                except BaseException as error:
                    if primary is None:
                        primary = error
            if root_descriptor >= 0:
                close_descriptor(
                    root_descriptor,
                    primary_error=primary,
                    context="secret root directory",
                )
            if primary is not None:
                raise primary

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            return


def _secret_service_inspection_result(status: str) -> DoctorCheck:
    return DoctorCheck(
        name="secret_store",
        status="OK" if status == "available" else "BLOCKED",
        detail=f"backend=secret_service state={status}",
    )


def _exception_chain(error: BaseException) -> tuple[BaseException, ...]:
    chain: list[BaseException] = []
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return tuple(chain)


def _secret_service_failure_status(error: BaseException, *, stage: str) -> str:
    names: list[str] = []
    for cause in _exception_chain(error):
        names.append(type(cause).__name__.lower())
        names.append(str(cause).lower())
        get_dbus_name = getattr(cause, "get_dbus_name", None)
        if callable(get_dbus_name):
            try:
                names.append(str(get_dbus_name()).lower())
            except BaseException:
                names.append("dbus_name_unavailable")
    evidence = " ".join(names)
    if "timed out" in evidence or "timeout" in evidence or "noreply" in evidence:
        return "timeout"
    if any(
        token in evidence
        for token in ("accessdenied", "permissiondenied", "permission denied", "notauthorized")
    ):
        return "permission_denied"
    if any(
        token in evidence
        for token in (
            "serviceunknown",
            "namehasnoowner",
            "connectionrefused",
            "service unavailable",
        )
    ):
        return "service_unavailable"
    if any(
        token in evidence for token in ("nosuchobject", "unknownobject", "collection unavailable")
    ):
        return "collection_unavailable"
    if "typeerror" in evidence or "attributeerror" in evidence or "invalidargs" in evidence:
        return "malformed_response"
    if stage == "service":
        return "service_unavailable"
    if stage in {"alias", "locked"}:
        return "collection_unavailable"
    return "malformed_response"


_SECRET_SERVICE_INSPECTION_GATE = threading.Lock()


def _close_secret_service_inspection_connection(connection: object) -> None:
    close = getattr(connection, "close", None)
    if callable(close):
        close()


def _bounded_secret_service_inspection_call[T](
    operation: Callable[[], T],
    *,
    deadline: _Deadline,
    operation_timeout_seconds: float,
    late_cleanup: Callable[[T], None] | None = None,
) -> T:
    """Bound one read-only D-Bus call and cap abandoned workers at one."""

    if not _SECRET_SERVICE_INSPECTION_GATE.acquire(blocking=False):
        raise SecureStoreUnavailableError("Linux Secret Service operation timed out")
    result: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)
    state_lock = threading.Lock()
    abandoned = False

    def invoke() -> None:
        succeeded = False
        value: object
        try:
            value = operation()
            succeeded = True
        except BaseException as error:
            value = error
        cleanup_value: T | None = None
        gate_released = False
        try:
            with state_lock:
                if abandoned:
                    if succeeded and late_cleanup is not None:
                        cleanup_value = cast(T, value)
                else:
                    _SECRET_SERVICE_INSPECTION_GATE.release()
                    gate_released = True
                    result.put((succeeded, value), block=False)
        finally:
            if not gate_released:
                _SECRET_SERVICE_INSPECTION_GATE.release()
        if cleanup_value is not None and late_cleanup is not None:
            try:
                late_cleanup(cleanup_value)
            except BaseException:
                return

    worker = threading.Thread(
        target=invoke,
        name="wto-secret-service-doctor-call",
        daemon=True,
    )
    try:
        worker.start()
    except BaseException:
        _SECRET_SERVICE_INSPECTION_GATE.release()
        raise
    timeout = deadline.timeout(operation_timeout_seconds)
    try:
        succeeded, value = result.get(timeout=timeout)
    except queue.Empty as error:
        cleanup_value: T | None = None
        with state_lock:
            abandoned = True
            try:
                succeeded, value = result.get_nowait()
            except queue.Empty:
                pass
            else:
                if succeeded and late_cleanup is not None:
                    cleanup_value = cast(T, value)
        if cleanup_value is not None and late_cleanup is not None:
            try:
                late_cleanup(cleanup_value)
            except BaseException:
                _LOGGER.warning("late read-only Secret Service connection cleanup failed")
        raise SecureStoreUnavailableError("Linux Secret Service operation timed out") from error
    if succeeded:
        return cast(T, value)
    if isinstance(value, BaseException):
        raise SecureStoreUnavailableError("Linux Secret Service operation failed") from value
    raise SecureStoreUnavailableError("Linux Secret Service returned an invalid result")


def inspect_secret_service_read_only(
    *,
    total_timeout_seconds: float,
    operation_timeout_seconds: float,
) -> DoctorCheck:
    """Inspect Secret Service without opening a session or calling a mutator."""

    if total_timeout_seconds <= 0 or operation_timeout_seconds <= 0:
        return _secret_service_inspection_result("not_safely_inspectable")
    if operation_timeout_seconds > total_timeout_seconds:
        return _secret_service_inspection_result("not_safely_inspectable")
    try:
        secretstorage = importlib.import_module("secretstorage")
    except Exception:
        return _secret_service_inspection_result("service_unavailable")
    dbus_init = getattr(secretstorage, "dbus_init", None)
    read_default_alias = getattr(secretstorage, "get_collection_by_alias", None)
    if not callable(dbus_init) or not callable(read_default_alias):
        return _secret_service_inspection_result("not_safely_inspectable")

    deadline = _Deadline.start(total_timeout_seconds)
    connection: object | None = None
    try:
        connection = _bounded_secret_service_inspection_call(
            dbus_init,
            deadline=deadline,
            operation_timeout_seconds=operation_timeout_seconds,
            late_cleanup=_close_secret_service_inspection_connection,
        )
    except BaseException as error:
        return _secret_service_inspection_result(
            _secret_service_failure_status(error, stage="service")
        )
    if connection is None:
        return _secret_service_inspection_result("malformed_response")
    try:
        if not callable(getattr(connection, "close", None)):
            return _secret_service_inspection_result("not_safely_inspectable")
        try:
            collection = _bounded_secret_service_inspection_call(
                lambda: read_default_alias(connection, "default"),
                deadline=deadline,
                operation_timeout_seconds=operation_timeout_seconds,
            )
        except BaseException as error:
            return _secret_service_inspection_result(
                _secret_service_failure_status(error, stage="alias")
            )
        if collection is None:
            return _secret_service_inspection_result("collection_unavailable")
        is_locked = getattr(collection, "is_locked", None)
        if not callable(is_locked):
            return _secret_service_inspection_result("malformed_response")
        try:
            locked = _bounded_secret_service_inspection_call(
                is_locked,
                deadline=deadline,
                operation_timeout_seconds=operation_timeout_seconds,
            )
        except BaseException as error:
            return _secret_service_inspection_result(
                _secret_service_failure_status(error, stage="locked")
            )
        if type(locked) is not bool:
            return _secret_service_inspection_result("malformed_response")
        return _secret_service_inspection_result("locked" if locked else "available")
    finally:
        try:
            _close_secret_service_inspection_connection(connection)
        except BaseException:
            _LOGGER.warning("read-only Secret Service connection cleanup failed")


def _read_only_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_uid),
        int(metadata.st_mode),
        int(metadata.st_nlink),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _read_only_directory_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_uid),
        int(metadata.st_mode),
        int(metadata.st_nlink),
    )


class _ReadOnlyInspectionChanged(SecureStoreUnavailableError):
    pass


@dataclass(frozen=True)
class _ReadOnlyDirectoryChain:
    path: Path
    descriptors: tuple[int, ...]
    identities: tuple[tuple[int, int, int, int, int], ...]
    root_identity: tuple[int, int, int, int, int, int, int, int]

    @property
    def root_descriptor(self) -> int:
        return self.descriptors[-1]


def _close_read_only_directory_chain(
    descriptors: list[int] | tuple[int, ...],
    *,
    primary_error: BaseException | None,
) -> None:
    close_error: BaseException | None = None
    for descriptor in reversed(descriptors):
        try:
            close_descriptor(
                descriptor,
                primary_error=primary_error or close_error,
                context="read-only secret diagnostic directory",
            )
        except BaseException as error:
            if close_error is None:
                close_error = error
            else:
                close_error.add_note(f"another read-only secret directory close failed: {error!r}")
    if primary_error is None and close_error is not None:
        raise close_error


def _open_secret_directory_read_only(path: Path) -> _ReadOnlyDirectoryChain | None:
    absolute = _absolute_path(path)
    components = absolute.parts[1:]
    descriptors: list[int] = []
    identities: list[tuple[int, int, int, int, int]] = []
    primary_error: BaseException | None = None
    try:
        descriptor = os.open(Path(absolute.anchor), _READ_ONLY_DIRECTORY_FLAGS)
        descriptors.append(descriptor)
        identities.append(_read_only_directory_identity(os.fstat(descriptor)))
        final_named = os.fstat(descriptor)
        for component in components:
            try:
                named = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                opened_descriptors = tuple(descriptors)
                descriptors.clear()
                _close_read_only_directory_chain(opened_descriptors, primary_error=None)
                return None
            if not stat.S_ISDIR(named.st_mode):
                raise SecureStoreUnavailableError("secret directory component is unsafe")
            child = os.open(component, _READ_ONLY_DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                identity = _read_only_directory_identity(opened)
                if _read_only_directory_identity(named) != identity:
                    raise SecureStoreUnavailableError("secret directory identity changed")
            except BaseException:
                os.close(child)
                raise
            descriptor = child
            descriptors.append(descriptor)
            identities.append(identity)
            final_named = named
        opened_root = os.fstat(descriptor)
        _validate_private_directory_metadata(opened_root)
        if _read_only_identity(final_named) != _read_only_identity(opened_root):
            raise SecureStoreUnavailableError("secret directory identity changed")
        return _ReadOnlyDirectoryChain(
            path=absolute,
            descriptors=tuple(descriptors),
            identities=tuple(identities),
            root_identity=_read_only_identity(opened_root),
        )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if primary_error is not None:
            _close_read_only_directory_chain(descriptors, primary_error=primary_error)


def _revalidate_secret_directory_read_only(chain: _ReadOnlyDirectoryChain) -> None:
    if len(chain.descriptors) != len(chain.identities):
        raise _ReadOnlyInspectionChanged("secret directory chain is incomplete")
    if _read_only_directory_identity(os.fstat(chain.descriptors[0])) != chain.identities[0]:
        raise _ReadOnlyInspectionChanged("secret directory anchor changed during inspection")
    for component, parent, descriptor, identity in zip(
        chain.path.parts[1:],
        chain.descriptors[:-1],
        chain.descriptors[1:],
        chain.identities[1:],
        strict=True,
    ):
        named = os.stat(component, dir_fd=parent, follow_symlinks=False)
        opened = os.fstat(descriptor)
        if (
            _read_only_directory_identity(named) != identity
            or _read_only_directory_identity(opened) != identity
        ):
            raise _ReadOnlyInspectionChanged("secret directory identity changed during inspection")
    root_metadata = os.fstat(chain.root_descriptor)
    _validate_private_directory_metadata(root_metadata)
    if _read_only_identity(root_metadata) != chain.root_identity:
        raise _ReadOnlyInspectionChanged("secret directory contents changed during inspection")


def _open_secret_metadata_read_only(
    root_descriptor: int,
    name: str,
    *,
    expected_size: int | None,
) -> tuple[int, tuple[int, int, int, int, int, int, int, int]]:
    named = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
    _validate_secret_metadata(named)
    if expected_size is not None and int(named.st_size) != expected_size:
        raise SecureStoreUnavailableError("secret diagnostic file size is invalid")
    descriptor = os.open(name, _READ_ONLY_FILE_FLAGS, dir_fd=root_descriptor)
    try:
        opened = os.fstat(descriptor)
        _validate_secret_metadata(opened)
        identity = _read_only_identity(named)
        if identity != _read_only_identity(opened):
            raise SecureStoreUnavailableError("secret diagnostic file identity changed")
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _validate_secret_metadata_after_read(
    root_descriptor: int,
    name: str,
    descriptor: int,
    identity: tuple[int, int, int, int, int, int, int, int],
) -> None:
    opened = os.fstat(descriptor)
    named = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
    _validate_secret_metadata(opened)
    _validate_secret_metadata(named)
    if identity != _read_only_identity(opened) or identity != _read_only_identity(named):
        raise SecureStoreUnavailableError("secret diagnostic file identity changed")


def _read_secret_diagnostic_file(
    root_descriptor: int,
    name: str,
    expected_size: int,
) -> tuple[bytes, tuple[int, int, int, int, int, int, int, int]]:
    if _PREAD is None:
        raise SecureStoreUnavailableError("secret descriptor read API is unavailable")
    descriptor, identity = _open_secret_metadata_read_only(
        root_descriptor,
        name,
        expected_size=expected_size,
    )
    primary: BaseException | None = None
    try:
        payload = _PREAD(descriptor, expected_size + 1, 0)
        if len(payload) != expected_size:
            raise SecureStoreUnavailableError("secret diagnostic file size is invalid")
        _validate_secret_metadata_after_read(root_descriptor, name, descriptor, identity)
        return payload, identity
    except BaseException as error:
        primary = error
        raise
    finally:
        close_descriptor(
            descriptor,
            primary_error=primary,
            context=f"read-only secret diagnostic file {name}",
        )


def _validate_secret_metadata_without_read(
    root_descriptor: int,
    name: str,
    *,
    expected_size: int | None,
) -> tuple[int, int, int, int, int, int, int, int]:
    descriptor, identity = _open_secret_metadata_read_only(
        root_descriptor,
        name,
        expected_size=expected_size,
    )
    primary: BaseException | None = None
    try:
        _validate_secret_metadata_after_read(root_descriptor, name, descriptor, identity)
        return identity
    except BaseException as error:
        primary = error
        raise
    finally:
        close_descriptor(
            descriptor,
            primary_error=primary,
            context=f"read-only secret metadata {name}",
        )


def _revalidate_secret_metadata_identity(
    root_descriptor: int,
    name: str,
    identity: tuple[int, int, int, int, int, int, int, int],
) -> None:
    try:
        named = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
    except FileNotFoundError as error:
        raise _ReadOnlyInspectionChanged(
            "secret diagnostic component disappeared during inspection"
        ) from error
    _validate_secret_metadata(named)
    if _read_only_identity(named) != identity:
        raise _ReadOnlyInspectionChanged("secret diagnostic component changed during inspection")


def _revalidate_optional_secret_metadata_identity(
    root_descriptor: int,
    name: str,
    identity: tuple[int, int, int, int, int, int, int, int] | None,
) -> None:
    try:
        named = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        if identity is None:
            return
        raise _ReadOnlyInspectionChanged(
            "secret recovery marker disappeared during inspection"
        ) from None
    if identity is None:
        raise _ReadOnlyInspectionChanged("secret recovery marker appeared during inspection")
    _validate_secret_metadata(named)
    if _read_only_identity(named) != identity:
        raise _ReadOnlyInspectionChanged("secret recovery marker changed during inspection")


def _encrypted_file_inspection_result(status: str, *, healthy: bool = False) -> DoctorCheck:
    return DoctorCheck(
        name="secret_store",
        status="OK" if healthy else ("DEGRADED" if status == "missing" else "BLOCKED"),
        detail=f"backend=encrypted_file state={status}",
    )


def inspect_encrypted_file_secret_store_read_only(state_dir: Path) -> DoctorCheck:
    """Inspect encrypted-file health without bootstrap, flock, repair, or key reads."""

    directory_chain: _ReadOnlyDirectoryChain | None = None
    try:
        directory_chain = _open_secret_directory_read_only(_absolute_path(state_dir) / "secrets")
        if directory_chain is None:
            return _encrypted_file_inspection_result("missing")
        root_descriptor = directory_chain.root_descriptor

        marker_identity: tuple[int, int, int, int, int, int, int, int] | None = None
        try:
            marker_identity = _validate_secret_metadata_without_read(
                root_descriptor,
                LinuxEncryptedFileSecretStore._poison_name,
                expected_size=len(LinuxEncryptedFileSecretStore._poison_payload),
            )
        except FileNotFoundError:
            pass

        state_payload, state_identity = _read_secret_diagnostic_file(
            root_descriptor,
            LinuxEncryptedFileSecretStore._state_name,
            LinuxEncryptedFileSecretStore._state_file_size,
        )
        state_slots = tuple(
            LinuxEncryptedFileSecretStore._decode_state_slot(
                slot_index,
                state_payload[
                    slot_index
                    * LinuxEncryptedFileSecretStore._state_slot_size : (slot_index + 1)
                    * LinuxEncryptedFileSecretStore._state_slot_size
                ],
            )
            for slot_index in range(LinuxEncryptedFileSecretStore._state_slot_count)
        )
        state = LinuxEncryptedFileSecretStore._select_store_state_slots(
            state_slots[0], state_slots[1]
        )

        guard_payload, guard_identity = _read_secret_diagnostic_file(
            root_descriptor,
            LinuxEncryptedFileSecretStore._completion_guard_name,
            LinuxEncryptedFileSecretStore._completion_guard_file_size,
        )
        guard_slots = tuple(
            LinuxEncryptedFileSecretStore._decode_completion_guard_slot(
                slot_index,
                guard_payload[
                    slot_index
                    * LinuxEncryptedFileSecretStore._completion_guard_slot_size : (slot_index + 1)
                    * LinuxEncryptedFileSecretStore._completion_guard_slot_size
                ],
            )
            for slot_index in range(LinuxEncryptedFileSecretStore._completion_guard_slot_count)
        )
        guard = LinuxEncryptedFileSecretStore._select_completion_guard_slots(
            guard_slots[0], guard_slots[1]
        )
        master_key_identity = _validate_secret_metadata_without_read(
            root_descriptor,
            ".master-key",
            expected_size=32,
        )
        _revalidate_secret_metadata_identity(
            root_descriptor,
            LinuxEncryptedFileSecretStore._state_name,
            state_identity,
        )
        _revalidate_secret_metadata_identity(
            root_descriptor,
            LinuxEncryptedFileSecretStore._completion_guard_name,
            guard_identity,
        )
        _revalidate_secret_metadata_identity(
            root_descriptor,
            ".master-key",
            master_key_identity,
        )
        _revalidate_optional_secret_metadata_identity(
            root_descriptor,
            LinuxEncryptedFileSecretStore._poison_name,
            marker_identity,
        )
        _revalidate_secret_directory_read_only(directory_chain)

        if marker_identity is not None:
            return _encrypted_file_inspection_result("manual_recovery")
        if state.slot_index < 0:
            return _encrypted_file_inspection_result("state_corrupt")
        if guard.slot_index < 0:
            return _encrypted_file_inspection_result("completion_guard_corrupt")
        if state.state is _StoreHealth.MUTATING:
            guard_reason = LinuxEncryptedFileSecretStore._completion_guard_block_reason(
                state, guard
            )
            return _encrypted_file_inspection_result(
                "mutating_finalizing"
                if guard_reason == "completion_guard_finalizing"
                else "mutating"
            )
        if state.state is _StoreHealth.POISONED:
            return _encrypted_file_inspection_result("poisoned")
        guard_reason = LinuxEncryptedFileSecretStore._completion_guard_block_reason(state, guard)
        if guard_reason is not None:
            return _encrypted_file_inspection_result(guard_reason)
        return _encrypted_file_inspection_result("healthy", healthy=True)
    except _ReadOnlyInspectionChanged:
        return _encrypted_file_inspection_result("concurrent_change")
    except FileNotFoundError:
        return _encrypted_file_inspection_result("blocked_missing_component")
    except (OSError, SecureStoreUnavailableError, ValueError):
        return _encrypted_file_inspection_result("blocked_unsafe_or_corrupt")
    finally:
        if directory_chain is not None:
            _close_read_only_directory_chain(
                directory_chain.descriptors,
                primary_error=None,
            )
