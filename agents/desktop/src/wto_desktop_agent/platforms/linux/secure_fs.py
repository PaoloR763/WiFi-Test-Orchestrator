from __future__ import annotations

import ctypes
import errno
import os
import secrets
import stat
from dataclasses import dataclass
from typing import Any, Final

_RENAME_NOREPLACE: Final = 1
_RENAME_EXCHANGE: Final = 2
_QUARANTINE_ATTEMPTS: Final = 16
_QUARANTINE_TOKEN_BYTES: Final = 32


class SecureFilesystemError(RuntimeError):
    """Base error for descriptor-anchored POSIX filesystem operations."""


class SecureFilesystemUnavailableError(SecureFilesystemError):
    """Raised when the kernel or C runtime lacks a required safe primitive."""


class EntryIdentityMismatchError(SecureFilesystemError):
    """Raised when a name no longer refers to the validated filesystem object."""


@dataclass(frozen=True, slots=True)
class FileIdentity:
    """Stable metadata for one regular file below a borrowed directory fd.

    ``dir_fd`` remains owned by the caller.  Keeping its device and inode in
    the identity makes accidental fd reuse fail closed before a mutation.
    Callers must keep the descriptor open until the identity is consumed.
    """

    dir_fd: int
    directory_dev: int
    directory_ino: int
    relative_name: str
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
        ) == _file_metadata_identity(metadata)

    def matches_with_size(self, metadata: os.stat_result) -> bool:
        return self.matches(metadata) and self.st_size == int(metadata.st_size)


@dataclass(frozen=True, slots=True)
class QuarantinePlan:
    """One locally generated, descriptor-relative logical quarantine name."""

    prefix: str
    relative_name: str


@dataclass(frozen=True, slots=True)
class QuarantinedObject:
    logical_delete_completed: bool
    physical_delete_pending: bool
    directory_synced: bool
    restored: bool
    manual_recovery_required: bool
    original_name: str
    quarantine_name: str | None
    st_dev: int
    st_ino: int
    st_uid: int
    file_type: int
    mode: int
    st_nlink: int
    st_size: int
    issues: tuple[str, ...]

    @property
    def logical_deletion_confirmed(self) -> bool:
        return (
            self.logical_delete_completed
            and self.physical_delete_pending
            and self.directory_synced
            and not self.manual_recovery_required
            and not self.issues
            and self.quarantine_name is not None
        )


class SecureQuarantineError(SecureFilesystemError):
    def __init__(self, message: str, result: QuarantinedObject) -> None:
        super().__init__(message)
        self.result = result


def plan_quarantine_name(quarantine_prefix: str) -> QuarantinePlan:
    """Generate an exact quarantine name for a caller's durable intent.

    The caller may persist the returned relative name before mutation, but it
    cannot use this API to supply a path or escape the descriptor-anchored
    directory.  A planned name is attempted exactly once so recovery always
    refers to the same immutable intent.
    """

    _require_posix()
    _validate_quarantine_prefix(quarantine_prefix)
    return QuarantinePlan(
        prefix=quarantine_prefix,
        relative_name=(f"{quarantine_prefix}{secrets.token_hex(_QUARANTINE_TOKEN_BYTES)}"),
    )


def capture_file_identity(
    dir_fd: int,
    relative_name: str,
    file_fd: int,
    *,
    expected_uid: int | None = None,
    expected_mode: int | None = None,
) -> FileIdentity:
    """Capture and bind exact regular-file metadata to its owning directory fd."""

    _require_posix()
    _validate_descriptor(dir_fd, "directory")
    _validate_descriptor(file_fd, "file")
    _validate_component(relative_name, "file name")
    directory_metadata = os.fstat(dir_fd)
    if not stat.S_ISDIR(directory_metadata.st_mode):
        raise SecureFilesystemError("secure filesystem anchor is not a directory")
    metadata = os.fstat(file_fd)
    _validate_regular_file(metadata, expected_uid=expected_uid, expected_mode=expected_mode)
    named_metadata = os.stat(relative_name, dir_fd=dir_fd, follow_symlinks=False)
    if _file_metadata_identity(metadata) != _file_metadata_identity(named_metadata):
        raise EntryIdentityMismatchError(
            "file descriptor and descriptor-anchored name have different identities"
        )
    return FileIdentity(
        dir_fd=dir_fd,
        directory_dev=int(directory_metadata.st_dev),
        directory_ino=int(directory_metadata.st_ino),
        relative_name=relative_name,
        st_dev=int(metadata.st_dev),
        st_ino=int(metadata.st_ino),
        st_uid=int(metadata.st_uid),
        file_type=stat.S_IFMT(metadata.st_mode),
        mode=stat.S_IMODE(metadata.st_mode),
        st_nlink=int(metadata.st_nlink),
        st_size=int(metadata.st_size),
    )


def rename_noreplace(
    source_dir_fd: int,
    source_name: str,
    destination_dir_fd: int,
    destination_name: str,
) -> None:
    """Atomically rename one descriptor-relative name without overwriting."""

    _require_posix()
    _validate_descriptor(source_dir_fd, "source directory")
    _validate_descriptor(destination_dir_fd, "destination directory")
    _validate_component(source_name, "source name")
    _validate_component(destination_name, "destination name")
    _renameat2(
        source_dir_fd,
        source_name,
        destination_dir_fd,
        destination_name,
        flag=_RENAME_NOREPLACE,
        operation="RENAME_NOREPLACE",
    )


def rename_exchange(
    source_dir_fd: int,
    source_name: str,
    destination_dir_fd: int,
    destination_name: str,
) -> None:
    """Atomically exchange two descriptor-relative names or fail closed."""

    _require_posix()
    _validate_descriptor(source_dir_fd, "source directory")
    _validate_descriptor(destination_dir_fd, "destination directory")
    _validate_component(source_name, "source name")
    _validate_component(destination_name, "destination name")
    _renameat2(
        source_dir_fd,
        source_name,
        destination_dir_fd,
        destination_name,
        flag=_RENAME_EXCHANGE,
        operation="RENAME_EXCHANGE",
    )


def logical_quarantine(
    expected: FileIdentity,
    *,
    quarantine_prefix: str,
    plan: QuarantinePlan | None = None,
    primary_error: BaseException | None = None,
) -> QuarantinedObject:
    """Remove an active name without physically deleting any filesystem object.

    The online service only moves the descriptor-anchored name to an
    unpredictable quarantine, validates the observed inode, and fsyncs the
    directory. Physical purge is deliberately an offline maintenance concern:
    Linux has no descriptor-only regular-file unlink primitive that can defeat
    a hostile process with the same UID racing a mutable directory entry.
    """

    _require_posix()
    _validate_quarantine_prefix(quarantine_prefix)
    if plan is not None:
        _validate_quarantine_plan(plan, quarantine_prefix)
    issues: list[str] = []
    operation_error: BaseException | None = None
    quarantine_name: str | None = None
    quarantined = False
    logical_delete_completed = False
    physical_delete_pending = False
    directory_synced = False
    restored = False
    identity_match: bool | None = None

    try:
        _validate_identity_anchor(expected)
    except BaseException as error:
        operation_error = error
        issues.append(_issue("identity_anchor_validation_failed", error))

    if operation_error is None:
        try:
            quarantine_name = _move_to_quarantine(
                expected,
                quarantine_prefix,
                plan=plan,
            )
            quarantined = True
        except BaseException as error:
            operation_error = error
            issues.append(_issue("quarantine_rename_failed", error))

    quarantine_fd: int | None = None
    if operation_error is None and quarantine_name is not None:
        try:
            quarantine_fd = os.open(
                quarantine_name,
                _read_no_follow_flags(),
                dir_fd=expected.dir_fd,
            )
            observed = os.fstat(quarantine_fd)
            identity_match = expected.matches(observed)
            if not identity_match:
                raise EntryIdentityMismatchError(
                    "quarantined entry does not match the validated file identity"
                )
            os.fsync(expected.dir_fd)
            directory_synced = True
            logical_delete_completed = True
            physical_delete_pending = True
        except BaseException as error:
            operation_error = error
            issue_name = (
                "entry_identity_mismatch"
                if isinstance(error, EntryIdentityMismatchError)
                else "quarantine_validation_failed"
            )
            issues.append(_issue(issue_name, error))
        finally:
            if quarantine_fd is not None:
                try:
                    os.close(quarantine_fd)
                except BaseException as close_error:
                    if operation_error is None:
                        operation_error = close_error
                    issues.append(_issue("quarantine_descriptor_close_failed", close_error))

    should_restore = quarantined and identity_match is not True
    if should_restore and quarantine_name is not None:
        try:
            rename_noreplace(
                expected.dir_fd,
                quarantine_name,
                expected.dir_fd,
                expected.relative_name,
            )
            restored = True
            quarantine_name = None
        except BaseException as restore_error:
            issues.append(_issue("quarantine_restore_failed", restore_error))
            if operation_error is None:
                operation_error = restore_error
        try:
            os.fsync(expected.dir_fd)
        except BaseException as sync_error:
            issues.append(_issue("recovery_directory_fsync_failed", sync_error))
            if operation_error is None:
                operation_error = sync_error
    elif quarantined and quarantine_name is not None and not directory_synced:
        try:
            os.fsync(expected.dir_fd)
        except BaseException as sync_error:
            issues.append(_issue("recovery_directory_fsync_failed", sync_error))
            if operation_error is None:
                operation_error = sync_error

    manual_recovery_required = bool(
        operation_error is not None
        or (quarantined and not logical_delete_completed)
        or identity_match is False
        or (logical_delete_completed and not directory_synced)
    )
    result = QuarantinedObject(
        logical_delete_completed=logical_delete_completed,
        physical_delete_pending=physical_delete_pending,
        directory_synced=directory_synced,
        restored=restored,
        manual_recovery_required=manual_recovery_required,
        original_name=expected.relative_name,
        quarantine_name=quarantine_name,
        st_dev=expected.st_dev,
        st_ino=expected.st_ino,
        st_uid=expected.st_uid,
        file_type=expected.file_type,
        mode=expected.mode,
        st_nlink=expected.st_nlink,
        st_size=expected.st_size,
        issues=tuple(issues),
    )
    if operation_error is None:
        if primary_error is not None and result.physical_delete_pending:
            primary_error.add_note(_physical_delete_pending_note(result))
        return result
    if primary_error is not None:
        for issue in result.issues:
            primary_error.add_note(f"secure filesystem quarantine also failed: {issue}")
        if result.manual_recovery_required:
            primary_error.add_note(_manual_recovery_note(result))
        return result
    failure = SecureQuarantineError("secure logical quarantine failed", result)
    for issue in result.issues[1:]:
        failure.add_note(f"additional secure filesystem failure: {issue}")
    if result.manual_recovery_required:
        failure.add_note(_manual_recovery_note(result))
    raise failure from operation_error


def close_descriptor(
    descriptor: int,
    *,
    primary_error: BaseException | None = None,
    context: str = "descriptor",
) -> None:
    """Close once, attaching a close failure to an existing primary error."""

    try:
        os.close(descriptor)
    except BaseException as close_error:
        if primary_error is None:
            raise
        primary_error.add_note(f"secondary {context} close failure: {close_error!r}")


def _move_to_quarantine(
    expected: FileIdentity,
    prefix: str,
    *,
    plan: QuarantinePlan | None,
) -> str:
    if plan is not None:
        rename_noreplace(
            expected.dir_fd,
            expected.relative_name,
            expected.dir_fd,
            plan.relative_name,
        )
        return plan.relative_name
    last_collision: BaseException | None = None
    for _ in range(_QUARANTINE_ATTEMPTS):
        quarantine_name = f"{prefix}{secrets.token_hex(_QUARANTINE_TOKEN_BYTES)}"
        try:
            rename_noreplace(
                expected.dir_fd,
                expected.relative_name,
                expected.dir_fd,
                quarantine_name,
            )
            return quarantine_name
        except FileExistsError as error:
            last_collision = error
    allocation_error = SecureFilesystemError("secure quarantine name allocation failed")
    if last_collision is not None:
        raise allocation_error from last_collision
    raise allocation_error


def _validate_quarantine_plan(plan: QuarantinePlan, prefix: str) -> None:
    if plan.prefix != prefix:
        raise ValueError("secure quarantine plan prefix does not match the operation")
    _validate_component(plan.relative_name, "quarantine plan name")
    if not plan.relative_name.startswith(prefix):
        raise ValueError("secure quarantine plan name has an invalid prefix")
    token = plan.relative_name[len(prefix) :]
    if len(token) != _QUARANTINE_TOKEN_BYTES * 2 or any(
        character not in "0123456789abcdef" for character in token
    ):
        raise ValueError("secure quarantine plan token is invalid")


def _validate_identity_anchor(expected: FileIdentity) -> None:
    _validate_descriptor(expected.dir_fd, "directory")
    _validate_component(expected.relative_name, "file name")
    if expected.st_nlink != 1:
        raise SecureFilesystemError("secure quarantine requires exactly one hard link")
    if expected.file_type != stat.S_IFREG:
        raise SecureFilesystemError("secure quarantine requires a regular file")
    directory_metadata = os.fstat(expected.dir_fd)
    if not stat.S_ISDIR(directory_metadata.st_mode):
        raise SecureFilesystemError("secure filesystem anchor is not a directory")
    if (int(directory_metadata.st_dev), int(directory_metadata.st_ino)) != (
        expected.directory_dev,
        expected.directory_ino,
    ):
        raise EntryIdentityMismatchError("secure filesystem directory anchor changed")


def _validate_regular_file(
    metadata: os.stat_result,
    *,
    expected_uid: int | None,
    expected_mode: int | None,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise SecureFilesystemError("secure filesystem entry is not a regular file")
    if int(metadata.st_nlink) != 1:
        raise SecureFilesystemError("secure filesystem entry must have exactly one hard link")
    if expected_uid is not None and int(metadata.st_uid) != expected_uid:
        raise SecureFilesystemError("secure filesystem entry owner is invalid")
    if expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise SecureFilesystemError("secure filesystem entry mode is invalid")


def _file_metadata_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_uid),
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        int(metadata.st_nlink),
    )


def _resolve_renameat2() -> Any | None:
    try:
        library = ctypes.CDLL(None, use_errno=True)
    except (OSError, TypeError):
        return None
    renameat2 = getattr(library, "renameat2", None)
    if renameat2 is None:
        return None
    try:
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
    except (AttributeError, TypeError):
        return None
    return renameat2


def _renameat2(
    source_dir_fd: int,
    source_name: str,
    destination_dir_fd: int,
    destination_name: str,
    *,
    flag: int,
    operation: str,
) -> None:
    renameat2 = _resolve_renameat2()
    if renameat2 is None:
        raise SecureFilesystemUnavailableError(
            f"safe filesystem mutation requires renameat2({operation})"
        )
    ctypes.set_errno(0)
    result = int(
        renameat2(
            source_dir_fd,
            os.fsencode(source_name),
            destination_dir_fd,
            os.fsencode(destination_name),
            flag,
        )
    )
    if result == 0:
        return
    error_number = ctypes.get_errno() or errno.EIO
    if error_number in _unsupported_rename_errors():
        raise SecureFilesystemUnavailableError(
            f"safe filesystem mutation requires renameat2({operation})"
        )
    raise OSError(error_number, os.strerror(error_number), destination_name)


def _unsupported_rename_errors() -> frozenset[int]:
    return frozenset(
        {
            errno.ENOSYS,
            errno.EINVAL,
            getattr(errno, "EOPNOTSUPP", errno.ENOSYS),
            getattr(errno, "ENOTSUP", errno.ENOSYS),
        }
    )


def _read_no_follow_flags() -> int:
    return os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))


def _validate_quarantine_prefix(prefix: str) -> None:
    _validate_component(prefix, "quarantine prefix")
    if not prefix.startswith("."):
        raise ValueError("quarantine prefix must be an internal dot name")
    if len(os.fsencode(prefix)) + (_QUARANTINE_TOKEN_BYTES * 2) > 240:
        raise ValueError("quarantine prefix is too long")


def _validate_component(name: str, label: str) -> None:
    if not isinstance(name, str) or name in {"", ".", ".."}:
        raise ValueError(f"{label} is invalid")
    if "/" in name or "\x00" in name:
        raise ValueError(f"{label} must be one POSIX path component")


def _validate_descriptor(descriptor: int, label: str) -> None:
    if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 0:
        raise ValueError(f"{label} descriptor is invalid")


def _require_posix() -> None:
    if os.name != "posix":
        raise SecureFilesystemUnavailableError(
            "descriptor-anchored secure filesystem operations require POSIX"
        )


def _issue(name: str, error: BaseException) -> str:
    return f"{name}:{type(error).__name__}"


def _manual_recovery_note(result: QuarantinedObject) -> str:
    location = result.quarantine_name or "original descriptor-anchored entry"
    return f"manual filesystem recovery may be required for {location}"


def _physical_delete_pending_note(result: QuarantinedObject) -> str:
    location = result.quarantine_name or "descriptor-anchored quarantine"
    return f"logical quarantine completed; offline physical deletion pending for {location}"
