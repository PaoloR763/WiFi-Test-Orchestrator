from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import wto_desktop_agent.cli as cli_module
import wto_desktop_agent.platforms.linux.state_directory as state_directory_module
from wto_desktop_agent.config import AgentSettings
from wto_desktop_agent.platforms.linux.state_directory import (
    prepare_linux_state_directory,
)

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux descriptor semantics")


def _settings(path: Path) -> AgentSettings:
    return AgentSettings(
        environment="test",
        server_url="http://testserver",
        state_dir=path,
        allow_in_memory_secret_store=True,
    )


@pytest.mark.parametrize("existing_mode", (None, 0o700, 0o755, 0o777))
def test_state_directory_is_created_or_migrated_to_0700(
    tmp_path: Path,
    existing_mode: int | None,
) -> None:
    parent = tmp_path / "existing-parent"
    parent.mkdir(mode=0o755)
    os.chmod(parent, 0o755)  # noqa: S103 - intentional legacy/parent fixture
    state = parent / "state"
    if existing_mode is not None:
        state.mkdir(mode=existing_mode)
        os.chmod(state, existing_mode)

    prepare_linux_state_directory(state)

    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert state.stat().st_uid == os.geteuid()
    assert stat.S_IMODE(parent.stat().st_mode) == 0o755


@pytest.mark.parametrize("kind", ("symlink", "file"))
def test_state_directory_rejects_symlink_or_file(tmp_path: Path, kind: str) -> None:
    state = tmp_path / "state"
    if kind == "symlink":
        target = tmp_path / "target"
        target.mkdir(mode=0o700)
        state.symlink_to(target, target_is_directory=True)
    else:
        state.write_text("not a directory", encoding="utf-8")

    with pytest.raises(OSError):
        prepare_linux_state_directory(state)


def test_state_directory_rejects_foreign_owner_before_chmod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o755)
    os.chmod(state, 0o755)  # noqa: S103 - intentional legacy fixture
    chmod_calls: list[tuple[int, int]] = []
    real_fchmod = os.fchmod

    def observed_fchmod(descriptor: int, mode: int) -> None:
        chmod_calls.append((descriptor, mode))
        real_fchmod(descriptor, mode)

    monkeypatch.setattr(state_directory_module, "_GETEUID", lambda: os.geteuid() + 1)
    monkeypatch.setattr(state_directory_module, "_FCHMOD", observed_fchmod)

    with pytest.raises(PermissionError, match="owner"):
        prepare_linux_state_directory(state)

    assert chmod_calls == []
    assert stat.S_IMODE(state.stat().st_mode) == 0o755


def test_state_directory_detects_name_replacement_after_descriptor_chmod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o755)
    os.chmod(state, 0o755)  # noqa: S103 - intentional legacy fixture
    retained = tmp_path / "retained"
    real_fchmod = os.fchmod
    replaced = False

    def replacing_fchmod(descriptor: int, mode: int) -> None:
        nonlocal replaced
        real_fchmod(descriptor, mode)
        if not replaced:
            replaced = True
            state.rename(retained)
            state.mkdir(mode=0o700)
            os.chmod(state, 0o700)

    monkeypatch.setattr(state_directory_module, "_FCHMOD", replacing_fchmod)

    with pytest.raises(PermissionError, match="name no longer identifies"):
        prepare_linux_state_directory(state)

    assert retained.is_dir()
    assert state.is_dir()
    assert retained.stat().st_ino != state.stat().st_ino


def test_state_directory_revalidates_every_parent_from_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    state = parent / "state"
    state.mkdir(mode=0o755)
    os.chmod(state, 0o755)  # noqa: S103 - intentional legacy fixture
    retained_parent = tmp_path / "retained-parent"
    real_fchmod = os.fchmod
    replaced = False

    def replacing_parent(descriptor: int, mode: int) -> None:
        nonlocal replaced
        real_fchmod(descriptor, mode)
        if not replaced:
            replaced = True
            parent.rename(retained_parent)
            parent.mkdir(mode=0o700)
            replacement_state = parent / "state"
            replacement_state.mkdir(mode=0o700)

    monkeypatch.setattr(state_directory_module, "_FCHMOD", replacing_parent)

    with pytest.raises(PermissionError, match="component identity changed"):
        prepare_linux_state_directory(state)

    assert (retained_parent / "state").is_dir()
    assert (parent / "state").is_dir()


def test_new_state_directory_fsyncs_inode_and_parent_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    parent_inode = tmp_path.stat().st_ino
    fsynced_inodes: list[int] = []
    real_fsync = os.fsync

    def observed_fsync(descriptor: int) -> None:
        fsynced_inodes.append(os.fstat(descriptor).st_ino)
        real_fsync(descriptor)

    monkeypatch.setattr(state_directory_module, "_FSYNC", observed_fsync)

    prepare_linux_state_directory(state)

    assert fsynced_inodes.count(state.stat().st_ino) == 1
    assert fsynced_inodes.count(parent_inode) == 1


def test_new_state_directory_parent_fsync_failure_is_visible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    parent_inode = tmp_path.stat().st_ino
    real_fsync = os.fsync

    def failing_parent_fsync(descriptor: int) -> None:
        if os.fstat(descriptor).st_ino == parent_inode:
            raise OSError("synthetic parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(state_directory_module, "_FSYNC", failing_parent_fsync)

    with pytest.raises(OSError, match="parent fsync"):
        prepare_linux_state_directory(state)

    assert state.is_dir()
    assert stat.S_IMODE(state.stat().st_mode) == 0o700


def test_state_directory_close_failure_remains_visible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    real_close = os.close
    failed = False

    def failing_close(descriptor: int) -> None:
        nonlocal failed
        real_close(descriptor)
        if not failed:
            failed = True
            raise OSError("synthetic state descriptor close failure")

    monkeypatch.setattr(state_directory_module, "_CLOSE", failing_close)

    with pytest.raises(OSError, match="descriptor close"):
        prepare_linux_state_directory(state)


def test_state_directory_rejects_relative_path(tmp_path: Path) -> None:
    del tmp_path
    with pytest.raises(ValueError, match="absolute"):
        prepare_linux_state_directory(Path("relative/state"))


def test_components_prepare_state_before_sqlite_and_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path / "state")
    events: list[str] = []

    def prepared(_path: Path) -> AgentSettings:
        events.append("prepared")
        return settings

    class FakeStore:
        def __init__(self, path: Path) -> None:
            assert events == ["prepared"]
            assert path == settings.database_path
            events.append("store")

        def initialize(self) -> None:
            events.append("initialized")

    def adapter(**_kwargs: object) -> SimpleNamespace:
        assert events == ["prepared", "store", "initialized"]
        events.append("adapter")
        return SimpleNamespace(platform_id="linux")

    monkeypatch.setattr(cli_module, "_load_prepared_settings", prepared)
    monkeypatch.setattr(cli_module, "SQLiteStore", FakeStore)
    monkeypatch.setattr(cli_module, "create_platform_adapter", adapter)
    monkeypatch.setattr(cli_module, "HttpAgentTransport", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cli_module, "IdentityManager", lambda *_args, **_kwargs: object())

    cli_module._components(tmp_path / "agent.toml")

    assert events == ["prepared", "store", "initialized", "adapter"]


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ("backup", "restore", "prune-artifacts"))
async def test_maintenance_prepares_state_before_opening_sqlite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    settings = _settings(tmp_path / "state")
    events: list[str] = []

    def prepared(_path: Path) -> AgentSettings:
        events.append("prepared")
        return settings

    class FakeStore:
        def __init__(self, path: Path) -> None:
            assert events == ["prepared"]
            assert path == settings.database_path
            events.append("store")

        def initialize(self) -> None:
            events.append("initialized")

        def create_verified_backup(self, _destination: Path) -> None:
            events.append("backup")

        def restore_verified_backup(self, _source: Path) -> int:
            events.append("restore")
            return 2

    class FakeStager:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            events.append("stager")

        async def prune_confirmed(self, **_kwargs: object) -> Any:
            events.append("prune")
            return SimpleNamespace(
                selected=0,
                files_deleted=0,
                rows_deleted=0,
                bytes_deleted=0,
                issues=(),
            )

    monkeypatch.setattr(cli_module, "_load_prepared_settings", prepared)
    monkeypatch.setattr(cli_module, "SQLiteStore", FakeStore)
    if operation == "prune-artifacts":
        import wto_desktop_agent.application.artifacts as artifacts_module

        monkeypatch.setattr(artifacts_module, "SQLiteArtifactStager", FakeStager)
    args = SimpleNamespace(
        command="maintenance",
        maintenance_command=operation,
        config=tmp_path / "agent.toml",
        destination=tmp_path / "backup.sqlite3",
        source=tmp_path / "source.sqlite3",
        confirm=True,
    )

    assert await cli_module._run(args) == 0

    expected = {
        "backup": ["prepared", "store", "backup"],
        "restore": ["prepared", "store", "restore"],
        "prune-artifacts": ["prepared", "store", "initialized", "stager", "prune"],
    }
    assert events == expected[operation]
