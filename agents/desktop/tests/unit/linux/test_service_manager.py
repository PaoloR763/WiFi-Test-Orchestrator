from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

from wto_desktop_agent.platforms.linux import service_manager, tooling
from wto_desktop_agent.platforms.linux.service_manager import LinuxServiceManager
from wto_desktop_agent.platforms.linux.tooling import (
    TrustedExecutableStatus,
    inspect_systemctl,
    inspect_trusted_system_executable,
)


def _status(path: Path | None, reason: str | None = None) -> TrustedExecutableStatus:
    return TrustedExecutableStatus("systemctl", path, reason)  # type: ignore[arg-type]


def test_productive_manager_uses_separated_argv_and_simulated_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "run" / "systemd" / "system"
    runtime.mkdir(parents=True)
    monkeypatch.setattr(service_manager, "_SYSTEMD_RUNTIME", runtime)
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout="LoadState=loaded\nActiveState=active\n",
            stderr="",
        )

    manager = LinuxServiceManager(
        "endpoint",
        tmp_path,
        systemctl_inspector=lambda: _status(Path("/usr/bin/systemctl")),
        runner=runner,
    )

    assert manager.status() == "active"
    assert calls == [
        [
            str(Path("/usr/bin/systemctl")),
            "show",
            "wto-agent.service",
            "--property=LoadState",
            "--property=ActiveState",
            "--no-pager",
        ]
    ]


def test_missing_trusted_systemctl_is_normalized_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "run" / "systemd" / "system"
    runtime.mkdir(parents=True)
    monkeypatch.setattr(service_manager, "_SYSTEMD_RUNTIME", runtime)
    executed = False

    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        nonlocal executed
        del argv
        executed = True
        raise AssertionError("unavailable systemctl must not execute")

    manager = LinuxServiceManager(
        "endpoint",
        tmp_path,
        systemctl_inspector=lambda: _status(None, "command_missing"),
        runner=runner,
    )

    assert manager.status() == "unavailable"
    assert manager.provider_available is False
    assert executed is False


def test_ambient_path_systemctl_is_never_selected_or_executed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    malicious = tmp_path / "systemctl"
    marker = tmp_path / "malicious-systemctl-executed"
    malicious.write_text(
        f"#!/bin/sh\nprintf executed > {marker}\n",
        encoding="utf-8",
    )
    malicious.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    runtime = tmp_path / "run" / "systemd" / "system"
    runtime.mkdir(parents=True)
    monkeypatch.setattr(service_manager, "_SYSTEMD_RUNTIME", runtime)
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        assert Path(argv[0]).resolve() != malicious.resolve()
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout="LoadState=loaded\nActiveState=active\n",
            stderr="",
        )

    manager = LinuxServiceManager("endpoint", tmp_path, runner=runner)
    status = inspect_systemctl()
    observed = manager.status()

    assert status.path is None or status.path != malicious.resolve()
    assert observed in {"active", "unavailable"}
    assert all(Path(argv[0]).resolve() != malicious.resolve() for argv in calls)
    assert not marker.exists()
    assert tooling.SYSTEMCTL_CANDIDATES == (
        Path("/usr/bin/systemctl"),
        Path("/bin/systemctl"),
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and symlink semantics required")
def test_usr_bin_systemctl_is_accepted_when_present() -> None:
    candidate = Path("/usr/bin/systemctl")
    if not candidate.exists():
        pytest.skip("/usr/bin/systemctl is absent")

    status = inspect_systemctl()

    assert status.ready is True
    assert status.path is not None
    assert status.path.is_relative_to(Path("/usr/bin").resolve())


def _fake_trusted_lstat(
    monkeypatch: pytest.MonkeyPatch,
    *,
    unsafe_path: Path | None = None,
    unsafe_uid: int | None = None,
    unsafe_mode: int = 0,
) -> None:
    real_lstat = Path.lstat

    def lstat(path: Path) -> os.stat_result:
        metadata = real_lstat(path)
        values = list(metadata)
        values[4] = tooling._ROOT_UID
        if not stat.S_ISLNK(metadata.st_mode):
            values[0] = metadata.st_mode & ~0o022
        if unsafe_path is not None and path == unsafe_path:
            if unsafe_uid is not None:
                values[4] = unsafe_uid
            values[0] |= unsafe_mode
        return os.stat_result(values)

    monkeypatch.setattr(tooling, "_lstat", lstat)


@pytest.mark.skipif(os.name != "posix", reason="POSIX executable mode semantics required")
@pytest.mark.parametrize("unsafe_mode", [0o020, 0o002])
def test_group_or_world_writable_systemctl_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe_mode: int
) -> None:
    root = tmp_path / "usr" / "bin"
    root.mkdir(parents=True)
    candidate = root / "systemctl"
    candidate.write_bytes(b"systemctl")
    candidate.chmod(0o755)
    _fake_trusted_lstat(monkeypatch, unsafe_path=candidate, unsafe_mode=unsafe_mode)

    status = inspect_trusted_system_executable(
        "systemctl", candidates=(candidate,), allowed_roots=(root,)
    )

    assert status.ready is False
    assert status.reason == "insecure_executable"


@pytest.mark.skipif(os.name != "posix", reason="POSIX owner semantics required")
def test_non_root_owned_systemctl_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "usr" / "bin"
    root.mkdir(parents=True)
    candidate = root / "systemctl"
    candidate.write_bytes(b"systemctl")
    candidate.chmod(0o755)
    _fake_trusted_lstat(monkeypatch, unsafe_path=candidate, unsafe_uid=tooling._ROOT_UID + 1)

    status = inspect_trusted_system_executable(
        "systemctl", candidates=(candidate,), allowed_roots=(root,)
    )

    assert status.ready is False
    assert status.reason == "insecure_executable"


@pytest.mark.skipif(os.name != "posix", reason="POSIX ancestor mode semantics required")
def test_writable_ancestor_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "usr" / "bin"
    root.mkdir(parents=True)
    candidate = root / "systemctl"
    candidate.write_bytes(b"systemctl")
    candidate.chmod(0o755)
    _fake_trusted_lstat(monkeypatch, unsafe_path=root.parent, unsafe_mode=0o020)

    status = inspect_trusted_system_executable(
        "systemctl", candidates=(candidate,), allowed_roots=(root,)
    )

    assert status.ready is False
    assert status.reason == "insecure_executable"


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink semantics required")
def test_systemctl_symlink_outside_allowlisted_roots_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "usr" / "bin"
    outside = tmp_path / "opt"
    root.mkdir(parents=True)
    outside.mkdir()
    target = outside / "systemctl"
    target.write_bytes(b"systemctl")
    target.chmod(0o755)
    candidate = root / "systemctl"
    candidate.symlink_to(target)
    _fake_trusted_lstat(monkeypatch)

    status = inspect_trusted_system_executable(
        "systemctl", candidates=(candidate,), allowed_roots=(root,)
    )

    assert status.ready is False
    assert status.reason == "insecure_executable"


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink semantics required")
def test_systemctl_symlink_within_allowlisted_root_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "usr" / "bin"
    root.mkdir(parents=True)
    target = root / "systemctl.real"
    target.write_bytes(b"systemctl")
    target.chmod(0o755)
    candidate = root / "systemctl"
    candidate.symlink_to(target.name)
    _fake_trusted_lstat(monkeypatch)

    status = inspect_trusted_system_executable(
        "systemctl", candidates=(candidate,), allowed_roots=(root,)
    )

    assert status.ready is True
    assert status.path == target
