from __future__ import annotations

import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import cast

_O_DIRECTORY = int(getattr(os, "O_DIRECTORY", 0))
_O_NOFOLLOW = int(getattr(os, "O_NOFOLLOW", 0))
_O_CLOEXEC = int(getattr(os, "O_CLOEXEC", 0))
_FCHMOD = cast(Callable[[int, int], None] | None, getattr(os, "fchmod", None))
_FCHOWN = cast(Callable[[int, int, int], None] | None, getattr(os, "fchown", None))
_GETEUID = cast(Callable[[], int] | None, getattr(os, "geteuid", None))
_CLOSE = os.close
_FSYNC = os.fsync


def _directory_flags() -> int:
    if _O_DIRECTORY == 0 or _O_NOFOLLOW == 0 or _O_CLOEXEC == 0:
        raise RuntimeError("secure Linux state-directory flags are unavailable")
    return os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC


def _effective_uid() -> int:
    if _GETEUID is None:
        raise RuntimeError("Linux ownership APIs are unavailable")
    return int(_GETEUID())


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_uid),
        int(metadata.st_gid),
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
    )


def _stable_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return _identity(metadata)[:5]


def _validate_directory(metadata: os.stat_result) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise PermissionError("Linux state path contains a non-directory")


def _close_descriptors(
    descriptors: list[int],
    *,
    primary_error: BaseException | None,
) -> None:
    close_error: OSError | None = None
    for descriptor in reversed(descriptors):
        try:
            _CLOSE(descriptor)
        except OSError as error:
            if primary_error is not None:
                primary_error.add_note(f"state directory descriptor close also failed: {error!r}")
            elif close_error is None:
                close_error = error
            else:
                close_error.add_note(f"another descriptor close also failed: {error!r}")
    if primary_error is None and close_error is not None:
        raise close_error


def _revalidate_component_chain(
    components: tuple[str, ...],
    expected: tuple[tuple[int, int, int, int, int, int], ...],
    flags: int,
) -> None:
    descriptors: list[int] = []
    primary_error: BaseException | None = None
    try:
        parent = os.open("/", flags)
        descriptors.append(parent)
        if _identity(os.fstat(parent)) != expected[0]:
            raise PermissionError("Linux state-directory root identity changed")
        for component, expected_identity in zip(components, expected[1:], strict=True):
            descriptor = os.open(component, flags, dir_fd=parent)
            descriptors.append(descriptor)
            metadata = os.fstat(descriptor)
            _validate_directory(metadata)
            if _identity(metadata) != expected_identity:
                raise PermissionError("Linux state-directory component identity changed")
            parent = descriptor
    except BaseException as error:
        primary_error = error
        raise
    finally:
        _close_descriptors(descriptors, primary_error=primary_error)


def prepare_linux_state_directory(
    path: Path,
    *,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
    created_owner: tuple[int, int] | None = None,
) -> None:
    """Create or migrate an owned Linux state directory through stable descriptors."""

    if os.name != "posix":
        raise RuntimeError("Linux state-directory preparation requires POSIX")
    if _FCHMOD is None:
        raise RuntimeError("descriptor-anchored chmod is unavailable")
    if not path.is_absolute() or path.anchor != "/":
        raise ValueError("Linux state_dir must be an absolute POSIX path")
    components = path.parts[1:]
    if not components:
        raise ValueError("Linux state_dir cannot be the filesystem root")
    if any(component in {"", ".", ".."} or "\x00" in component for component in components):
        raise ValueError("Linux state_dir contains an unsafe component")

    flags = _directory_flags()
    effective_uid = _effective_uid()
    owner_uid = effective_uid if expected_uid is None else expected_uid
    fchown = _FCHOWN
    if owner_uid < 0 or (expected_gid is not None and expected_gid < 0):
        raise ValueError("Linux state directory owner identifiers must be non-negative")
    if created_owner is not None:
        if effective_uid != 0 or fchown is None:
            raise PermissionError("only root can assign a newly created state-directory owner")
        if expected_gid is None or created_owner != (owner_uid, expected_gid):
            raise ValueError("new state-directory ownership must match the expected owner")
    descriptors: list[int] = []
    identities: list[tuple[int, int, int, int, int, int]] = []
    primary_error: BaseException | None = None
    try:
        parent = os.open("/", flags)
        descriptors.append(parent)
        root_metadata = os.fstat(parent)
        _validate_directory(root_metadata)
        identities.append(_identity(root_metadata))
        for index, component in enumerate(components):
            final = index == len(components) - 1
            created = False
            try:
                descriptor = os.open(component, flags, dir_fd=parent)
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=parent)
                created = True
                descriptor = os.open(component, flags, dir_fd=parent)
            descriptors.append(descriptor)
            metadata = os.fstat(descriptor)
            _validate_directory(metadata)
            if created and created_owner is not None:
                if fchown is None:
                    raise RuntimeError("descriptor-anchored chown is unavailable")
                fchown(descriptor, *created_owner)
                metadata = os.fstat(descriptor)

            if final:
                if int(metadata.st_uid) != owner_uid or (
                    expected_gid is not None and int(metadata.st_gid) != expected_gid
                ):
                    raise PermissionError(
                        "Linux state directory owner does not match the service account"
                    )
                descriptor_identity = _stable_identity(metadata)
                _FCHMOD(descriptor, 0o700)
                _FSYNC(descriptor)
                after = os.fstat(descriptor)
                _validate_directory(after)
                if _stable_identity(after) != descriptor_identity:
                    raise PermissionError("Linux state directory identity changed during migration")
                if stat.S_IMODE(after.st_mode) != 0o700:
                    raise PermissionError("Linux state directory mode migration was not durable")
                durable_identity = _identity(after)
                named = os.stat(component, dir_fd=parent, follow_symlinks=False)
                _validate_directory(named)
                if _identity(named) != durable_identity:
                    raise PermissionError(
                        "Linux state directory name no longer identifies its descriptor"
                    )
                identities.append(durable_identity)
                if created:
                    _FSYNC(parent)
            else:
                if created:
                    if int(metadata.st_uid) != owner_uid or (
                        expected_gid is not None and int(metadata.st_gid) != expected_gid
                    ):
                        raise PermissionError(
                            "new Linux state-directory component has an unexpected owner"
                        )
                    _FCHMOD(descriptor, 0o700)
                    _FSYNC(descriptor)
                    _FSYNC(parent)
                    metadata = os.fstat(descriptor)
                    _validate_directory(metadata)
                    if stat.S_IMODE(metadata.st_mode) != 0o700:
                        raise PermissionError("new Linux state-directory component mode is invalid")
                identities.append(_identity(metadata))
                parent = descriptor
        _revalidate_component_chain(components, tuple(identities), flags)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        _close_descriptors(descriptors, primary_error=primary_error)
