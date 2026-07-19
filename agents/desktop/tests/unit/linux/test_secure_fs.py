from __future__ import annotations

import inspect
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import fields, replace
from pathlib import Path

import pytest

from wto_desktop_agent.platforms.linux import secure_fs
from wto_desktop_agent.platforms.linux.secure_fs import (
    FileIdentity,
    QuarantinedObject,
    QuarantinePlan,
    SecureFilesystemUnavailableError,
    SecureQuarantineError,
    capture_file_identity,
    logical_quarantine,
    plan_quarantine_name,
    rename_exchange,
    rename_noreplace,
)

_REAL_CLOSE = os.close
_LINUX_ONLY = pytest.mark.skipif(
    sys.platform != "linux", reason="renameat2 and POSIX dir_fd semantics require Linux"
)


def test_secure_fs_api_is_import_safe_and_identity_is_complete() -> None:
    assert callable(capture_file_identity)
    assert callable(rename_noreplace)
    assert callable(logical_quarantine)
    assert callable(plan_quarantine_name)
    assert callable(rename_exchange)
    assert {field.name for field in fields(FileIdentity)} == {
        "dir_fd",
        "directory_dev",
        "directory_ino",
        "relative_name",
        "st_dev",
        "st_ino",
        "st_uid",
        "file_type",
        "mode",
        "st_nlink",
        "st_size",
    }
    assert {field.name for field in fields(QuarantinedObject)} >= {
        "logical_delete_completed",
        "physical_delete_pending",
        "directory_synced",
        "restored",
        "manual_recovery_required",
        "quarantine_name",
        "issues",
    }
    assert {field.name for field in fields(QuarantinePlan)} == {
        "prefix",
        "relative_name",
    }
    source = inspect.getsource(secure_fs)
    assert "os.unlink" not in source
    assert "Path.unlink" not in source
    assert "unlinkat" not in source


@contextmanager
def _opened_directory(path: Path) -> Iterator[int]:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    descriptor = os.open(
        path,
        os.O_RDONLY
        | int(getattr(os, "O_DIRECTORY", 0))
        | int(getattr(os, "O_CLOEXEC", 0))
        | int(getattr(os, "O_NOFOLLOW", 0)),
    )
    try:
        yield descriptor
    finally:
        _REAL_CLOSE(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("test write made no progress")
        remaining = remaining[written:]


def _create_entry(
    directory_descriptor: int,
    name: str,
    payload: bytes = b"validated object",
) -> FileIdentity:
    descriptor = os.open(
        name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | int(getattr(os, "O_CLOEXEC", 0))
        | int(getattr(os, "O_NOFOLLOW", 0)),
        0o600,
        dir_fd=directory_descriptor,
    )
    try:
        _write_all(descriptor, payload)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        return capture_file_identity(
            directory_descriptor,
            name,
            descriptor,
            expected_uid=os.geteuid(),
            expected_mode=0o600,
        )
    finally:
        _REAL_CLOSE(descriptor)


@_LINUX_ONLY
def test_planned_quarantine_uses_exact_validated_name_without_fallback(
    tmp_path: Path,
) -> None:
    with _opened_directory(tmp_path) as directory_descriptor:
        identity = _create_entry(directory_descriptor, "active", b"planned")
        plan = plan_quarantine_name(".planned-")
        result = logical_quarantine(
            identity,
            quarantine_prefix=".planned-",
            plan=plan,
        )

        assert result.quarantine_name == plan.relative_name
        assert not (tmp_path / "active").exists()
        quarantine = tmp_path / plan.relative_name
        assert quarantine.read_bytes() == b"planned"
        assert quarantine.stat().st_ino == identity.st_ino

        second = _create_entry(directory_descriptor, "second", b"second")
        with pytest.raises(SecureQuarantineError) as raised:
            logical_quarantine(
                second,
                quarantine_prefix=".planned-",
                plan=plan,
            )
        assert isinstance(raised.value.__cause__, FileExistsError)
        assert raised.value.result.manual_recovery_required
        assert not raised.value.result.logical_deletion_confirmed
        assert any("quarantine_rename_failed" in issue for issue in raised.value.result.issues)
        assert (tmp_path / "second").read_bytes() == b"second"
        assert quarantine.read_bytes() == b"planned"


@_LINUX_ONLY
def test_rename_noreplace_is_atomic_and_never_overwrites(tmp_path: Path) -> None:
    with _opened_directory(tmp_path) as directory_descriptor:
        _create_entry(directory_descriptor, "source", b"source")
        rename_noreplace(directory_descriptor, "source", directory_descriptor, "destination")
        assert not (tmp_path / "source").exists()
        assert (tmp_path / "destination").read_bytes() == b"source"

        _create_entry(directory_descriptor, "second-source", b"second")
        with pytest.raises(FileExistsError):
            rename_noreplace(
                directory_descriptor,
                "second-source",
                directory_descriptor,
                "destination",
            )
        assert (tmp_path / "second-source").read_bytes() == b"second"
        assert (tmp_path / "destination").read_bytes() == b"source"


@_LINUX_ONLY
def test_missing_renameat2_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with _opened_directory(tmp_path) as directory_descriptor:
        _create_entry(directory_descriptor, "source")
        monkeypatch.setattr(secure_fs, "_resolve_renameat2", lambda: None)

        with pytest.raises(SecureFilesystemUnavailableError, match="renameat2"):
            rename_noreplace(
                directory_descriptor,
                "source",
                directory_descriptor,
                "destination",
            )

        assert (tmp_path / "source").exists()
        assert not (tmp_path / "destination").exists()


@_LINUX_ONLY
def test_logical_quarantine_retains_validated_inode_and_fsyncs_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _opened_directory(tmp_path) as directory_descriptor:
        identity = _create_entry(directory_descriptor, "victim")
        real_fsync = os.fsync
        synced: list[int] = []

        def tracked_fsync(descriptor: int) -> None:
            synced.append(descriptor)
            real_fsync(descriptor)

        monkeypatch.setattr(secure_fs.os, "fsync", tracked_fsync)
        unlink_calls: list[tuple[object, ...]] = []
        monkeypatch.setattr(
            secure_fs.os,
            "unlink",
            lambda *args, **kwargs: unlink_calls.append((*args, kwargs)),
        )
        result = logical_quarantine(identity, quarantine_prefix=".wto-quarantine-")

        assert result.logical_deletion_confirmed
        assert result.physical_delete_pending
        assert result.quarantine_name is not None
        assert not (tmp_path / "victim").exists()
        quarantined = tmp_path / result.quarantine_name
        assert quarantined.stat().st_ino == identity.st_ino
        assert quarantined.read_bytes() == b"validated object"
        assert unlink_calls == []
        assert directory_descriptor in synced


@_LINUX_ONLY
def test_replacement_after_fstat_never_triggers_physical_deletion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _opened_directory(tmp_path) as directory_descriptor:
        identity = _create_entry(directory_descriptor, "victim", b"expected")
        monkeypatch.setattr(secure_fs.secrets, "token_hex", lambda _size: "race")
        real_fsync = os.fsync
        raced = False

        def race_after_validation(descriptor: int) -> None:
            nonlocal raced
            if descriptor == directory_descriptor and not raced:
                raced = True
                os.rename(
                    ".q-race",
                    "expected-moved-after-fstat",
                    src_dir_fd=directory_descriptor,
                    dst_dir_fd=directory_descriptor,
                )
                _create_entry(directory_descriptor, ".q-race", b"replacement")
            real_fsync(descriptor)

        monkeypatch.setattr(secure_fs.os, "fsync", race_after_validation)
        result = logical_quarantine(identity, quarantine_prefix=".q-")

        assert result.logical_deletion_confirmed
        assert not (tmp_path / "victim").exists()
        assert (tmp_path / "expected-moved-after-fstat").read_bytes() == b"expected"
        assert (tmp_path / ".q-race").read_bytes() == b"replacement"


@_LINUX_ONLY
def test_replaced_entry_is_restored_and_wrong_inode_is_never_unlinked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _opened_directory(tmp_path) as directory_descriptor:
        identity = _create_entry(directory_descriptor, "victim", b"original")
        os.rename(
            "victim",
            "original-preserved",
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        _create_entry(directory_descriptor, "victim", b"replacement")
        unlink_calls: list[str] = []

        def reject_unlink(name: str, *, dir_fd: int | None = None) -> None:
            del dir_fd
            unlink_calls.append(name)
            raise AssertionError("an identity mismatch must never be unlinked")

        monkeypatch.setattr(secure_fs.os, "unlink", reject_unlink)
        with pytest.raises(SecureQuarantineError) as raised:
            logical_quarantine(identity, quarantine_prefix=".wto-quarantine-")

        assert raised.value.result.restored
        assert raised.value.result.manual_recovery_required
        assert unlink_calls == []
        assert (tmp_path / "victim").read_bytes() == b"replacement"
        assert (tmp_path / "original-preserved").read_bytes() == b"original"
        assert not list(tmp_path.glob(".wto-quarantine-*"))


@_LINUX_ONLY
def test_symlink_replacement_is_not_followed_or_deleted(tmp_path: Path) -> None:
    with _opened_directory(tmp_path) as directory_descriptor:
        identity = _create_entry(directory_descriptor, "victim")
        os.rename(
            "victim",
            "original-preserved",
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        outside = tmp_path.parent / f"{tmp_path.name}-outside"
        outside.write_bytes(b"outside must survive")
        os.symlink(outside, "victim", dir_fd=directory_descriptor)

        with pytest.raises(SecureQuarantineError) as raised:
            logical_quarantine(identity, quarantine_prefix=".wto-quarantine-")

        assert raised.value.result.restored
        assert (tmp_path / "victim").is_symlink()
        assert outside.read_bytes() == b"outside must survive"
        assert (tmp_path / "original-preserved").exists()


@_LINUX_ONLY
def test_hardlink_added_after_validation_prevents_delete(tmp_path: Path) -> None:
    with _opened_directory(tmp_path) as directory_descriptor:
        identity = _create_entry(directory_descriptor, "victim")
        os.link(
            "victim",
            "alias",
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )

        with pytest.raises(SecureQuarantineError) as raised:
            logical_quarantine(identity, quarantine_prefix=".wto-quarantine-")

        assert raised.value.result.restored
        assert (tmp_path / "victim").exists()
        assert (tmp_path / "alias").exists()
        assert (tmp_path / "victim").stat().st_ino == (tmp_path / "alias").stat().st_ino
        assert (tmp_path / "victim").stat().st_nlink == 2


@_LINUX_ONLY
@pytest.mark.parametrize("changed_field", ["st_ino", "st_uid", "mode"])
def test_exact_inode_owner_and_mode_mismatch_prevents_delete(
    tmp_path: Path, changed_field: str
) -> None:
    with _opened_directory(tmp_path) as directory_descriptor:
        identity = _create_entry(directory_descriptor, "victim")
        changed_value = getattr(identity, changed_field) + 1
        mismatched = replace(identity, **{changed_field: changed_value})

        with pytest.raises(SecureQuarantineError) as raised:
            logical_quarantine(mismatched, quarantine_prefix=".wto-quarantine-")

        assert raised.value.result.restored
        assert (tmp_path / "victim").exists()


@_LINUX_ONLY
def test_quarantine_collision_uses_a_fresh_unpredictable_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _opened_directory(tmp_path) as directory_descriptor:
        identity = _create_entry(directory_descriptor, "victim")
        _create_entry(directory_descriptor, ".q-collision", b"collision survives")
        tokens = iter(("collision", "fresh"))
        monkeypatch.setattr(secure_fs.secrets, "token_hex", lambda _size: next(tokens))

        result = logical_quarantine(identity, quarantine_prefix=".q-")

        assert result.logical_deletion_confirmed
        assert (tmp_path / ".q-collision").read_bytes() == b"collision survives"
        assert (tmp_path / ".q-fresh").read_bytes() == b"validated object"


@_LINUX_ONLY
def test_restore_never_overwrites_original_and_leaves_quarantine_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _opened_directory(tmp_path) as directory_descriptor:
        identity = _create_entry(directory_descriptor, "victim", b"expected")
        monkeypatch.setattr(secure_fs.secrets, "token_hex", lambda _size: "race")
        real_open = os.open
        raced = False

        def racing_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal raced
            if path == ".q-race" and dir_fd == directory_descriptor and not raced:
                raced = True
                os.rename(
                    ".q-race",
                    "expected-moved",
                    src_dir_fd=directory_descriptor,
                    dst_dir_fd=directory_descriptor,
                )
                replacement = real_open(
                    ".q-race",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=directory_descriptor,
                )
                _write_all(replacement, b"replacement")
                _REAL_CLOSE(replacement)
                occupied = real_open(
                    "victim",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=directory_descriptor,
                )
                _write_all(occupied, b"occupied")
                _REAL_CLOSE(occupied)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(secure_fs.os, "open", racing_open)
        with pytest.raises(SecureQuarantineError) as raised:
            logical_quarantine(identity, quarantine_prefix=".q-")

        result = raised.value.result
        assert result.quarantine_name == ".q-race"
        assert not result.restored
        assert result.manual_recovery_required
        assert (tmp_path / "victim").read_bytes() == b"occupied"
        assert (tmp_path / ".q-race").read_bytes() == b"replacement"
        assert (tmp_path / "expected-moved").read_bytes() == b"expected"


@_LINUX_ONLY
def test_primary_error_survives_identity_failure_with_recovery_notes(tmp_path: Path) -> None:
    with _opened_directory(tmp_path) as directory_descriptor:
        identity = _create_entry(directory_descriptor, "victim", b"original")
        os.rename(
            "victim",
            "original-preserved",
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        _create_entry(directory_descriptor, "victim", b"replacement")
        primary = RuntimeError("primary write failure")

        result = logical_quarantine(
            identity,
            quarantine_prefix=".wto-quarantine-",
            primary_error=primary,
        )

        assert result.restored
        assert any("secure filesystem quarantine" in note for note in primary.__notes__)
        assert any("manual filesystem recovery" in note for note in primary.__notes__)
        assert str(primary) == "primary write failure"
        assert (tmp_path / "victim").read_bytes() == b"replacement"


@_LINUX_ONLY
def test_close_failure_is_attached_and_quarantine_descriptor_is_closed_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _opened_directory(tmp_path) as directory_descriptor:
        identity = _create_entry(directory_descriptor, "victim")
        close_calls: list[int] = []

        def close_then_fail(descriptor: int) -> None:
            close_calls.append(descriptor)
            _REAL_CLOSE(descriptor)
            raise OSError("controlled close failure")

        monkeypatch.setattr(secure_fs.os, "close", close_then_fail)
        primary = RuntimeError("primary operation failure")
        result = logical_quarantine(
            identity,
            quarantine_prefix=".wto-quarantine-",
            primary_error=primary,
        )

        assert result.logical_delete_completed
        assert result.physical_delete_pending
        assert result.directory_synced
        assert not result.logical_deletion_confirmed
        assert len(close_calls) == 1
        assert any("descriptor_close_failed" in note for note in primary.__notes__)
        assert not (tmp_path / "victim").exists()
        assert list(tmp_path.glob(".wto-quarantine-*"))


@_LINUX_ONLY
def test_directory_fsync_failure_is_visible_after_logical_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _opened_directory(tmp_path) as directory_descriptor:
        identity = _create_entry(directory_descriptor, "victim")
        real_fsync = os.fsync

        def fail_directory_fsync(descriptor: int) -> None:
            if descriptor == directory_descriptor:
                raise OSError("controlled directory fsync failure")
            real_fsync(descriptor)

        monkeypatch.setattr(secure_fs.os, "fsync", fail_directory_fsync)
        with pytest.raises(SecureQuarantineError) as raised:
            logical_quarantine(identity, quarantine_prefix=".wto-quarantine-")

        assert not raised.value.result.logical_delete_completed
        assert not raised.value.result.directory_synced
        assert raised.value.result.manual_recovery_required
        assert not (tmp_path / "victim").exists()
        assert list(tmp_path.glob(".wto-quarantine-*"))


@_LINUX_ONLY
def test_missing_entry_after_validation_is_not_reported_as_success(tmp_path: Path) -> None:
    with _opened_directory(tmp_path) as directory_descriptor:
        identity = _create_entry(directory_descriptor, "victim")
        os.rename(
            "victim",
            "moved-elsewhere",
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )

        with pytest.raises(SecureQuarantineError) as raised:
            logical_quarantine(identity, quarantine_prefix=".wto-quarantine-")

        assert not raised.value.result.logical_delete_completed
        assert raised.value.result.manual_recovery_required
        assert (tmp_path / "moved-elsewhere").exists()
        assert not (tmp_path / "victim").exists()
