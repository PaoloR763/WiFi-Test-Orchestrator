from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from wto_desktop_agent.platforms.common import ExecutableIdentity
from wto_desktop_agent.platforms.linux import adapter, tooling


def _identity() -> ExecutableIdentity:
    return ExecutableIdentity(1, 2, 0, 0, stat.S_IFREG, 0o755, 1, 10, 11, 12)


def _tool_status(
    name: str,
    *,
    path: Path | None,
    secure: bool,
    self_check: bool = False,
    reason: str | None = None,
) -> tooling.ToolStatus:
    return tooling.ToolStatus(
        name=name,
        path=path,
        installed=path is not None or reason != "command_missing",
        self_check=self_check,
        access="allowed" if path is not None and secure else "denied",
        secure=secure,
        reason=reason,
        identity=_identity() if path is not None and secure else None,
    )


def test_closed_catalog_ignores_ambient_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    malicious = tmp_path / "iw"
    monkeypatch.setenv("PATH", str(tmp_path))
    observed: dict[str, object] = {}

    def inspect(
        name: str, *, candidates: tuple[Path, ...], allowed_roots: tuple[Path, ...]
    ) -> tooling.TrustedExecutableStatus:
        observed.update(name=name, candidates=candidates, roots=allowed_roots)
        return tooling.TrustedExecutableStatus(name, None, "command_missing")

    monkeypatch.setattr(tooling, "inspect_trusted_system_executable", inspect)

    result = tooling.inspect_tool("iw")

    assert result.path is None
    assert observed == {
        "name": "iw",
        "candidates": tooling.TRUSTED_TOOL_CANDIDATES["iw"],
        "roots": tooling.TRUSTED_EXECUTABLE_ROOTS,
    }
    assert malicious not in tooling.TRUSTED_TOOL_CANDIDATES["iw"]
    with pytest.raises(ValueError, match="closed Linux executable catalog"):
        tooling.inspect_tool("not-allowlisted")


def test_insecure_getcap_is_never_invoked(monkeypatch: pytest.MonkeyPatch) -> None:
    dumpcap = _tool_status("dumpcap", path=Path("/usr/bin/dumpcap"), secure=True, self_check=True)
    getcap = _tool_status("getcap", path=None, secure=False, reason="insecure_executable")
    monkeypatch.setattr(tooling, "probe_tool", lambda *_args, **_kwargs: dumpcap)

    def forbidden(*_args: object, **_kwargs: object) -> tooling._ProbeResult:
        raise AssertionError("insecure getcap must not execute")

    monkeypatch.setattr(tooling, "_fixed_probe", forbidden)

    result = tooling.probe_dumpcap(dumpcap=dumpcap, getcap=getcap)

    assert result.ready is False
    assert result.reason == "capability_inspector_unavailable"


def test_insecure_iw_is_never_invoked(monkeypatch: pytest.MonkeyPatch) -> None:
    iw = _tool_status("iw", path=None, secure=False, reason="insecure_executable")

    def forbidden(*_args: object, **_kwargs: object) -> tooling._ProbeResult:
        raise AssertionError("insecure iw must not execute")

    monkeypatch.setattr(tooling, "_fixed_probe", forbidden)

    assert tooling.monitor_capable_interfaces(frozenset({"wlan0"}), iw=iw) == frozenset()


def test_probe_preserves_the_exact_inspected_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    inspected = _tool_status("iw", path=Path("/usr/bin/iw"), secure=True)
    observed: list[tooling.ToolStatus] = []

    def probe(
        executable: tooling.TrustedExecutableStatus | tooling.ToolStatus,
        arguments: list[str],
        **_kwargs: object,
    ) -> tooling._ProbeResult:
        assert isinstance(executable, tooling.ToolStatus)
        observed.append(executable)
        assert arguments == ["--version"]
        return tooling._ProbeResult(True, "iw 6.9\n", raw_output=b"iw 6.9\n")

    monkeypatch.setattr(tooling, "_fixed_probe", probe)

    result = tooling.probe_tool("iw", ["--version"], inspected=inspected)

    assert observed == [inspected]
    assert result.identity is inspected.identity
    assert result.path == inspected.path
    assert result.version == "iw 6.9"


def test_adapter_reuses_one_catalog_identity_for_readiness_and_every_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    names = (
        "ip",
        "iw",
        "ethtool",
        "nmcli",
        "dumpcap",
        "flent",
        "netperf",
        "tcpreplay",
        "getcap",
    )
    statuses = {
        name: _tool_status(name, path=(tmp_path / "trusted" / name), secure=True) for name in names
    }
    monkeypatch.setattr(adapter, "inspect_tool", statuses.__getitem__)
    settings = cast(
        Any,
        SimpleNamespace(effective_artifacts_dir=tmp_path / "artifacts"),
    )

    commands, _tools, _readiness, inspected = adapter._commands(settings)

    assert inspected == statuses
    assert commands
    for spec in commands.values():
        logical_name = spec.executable.name
        assert spec.executable == statuses[logical_name].path
        assert spec.executable_identity == statuses[logical_name].identity


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


@pytest.mark.skipif(os.name != "posix", reason="POSIX executable trust semantics")
@pytest.mark.parametrize(
    ("target", "unsafe_mode", "unsafe_uid"),
    [
        ("file", 0o020, None),
        ("file", 0o002, None),
        ("file", stat.S_ISUID, None),
        ("file", stat.S_ISGID, None),
        ("file", 0, tooling._ROOT_UID + 1),
        ("parent", 0o020, None),
        ("parent", 0o002, None),
    ],
)
def test_catalog_rejects_insecure_target_or_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    unsafe_mode: int,
    unsafe_uid: int | None,
) -> None:
    root = tmp_path / "trusted root" / "bin"
    root.mkdir(parents=True)
    candidate = root / "iw"
    candidate.write_bytes(b"trusted")
    candidate.chmod(0o755)
    unsafe_path = candidate if target == "file" else root.parent
    _fake_trusted_lstat(
        monkeypatch,
        unsafe_path=unsafe_path,
        unsafe_uid=unsafe_uid,
        unsafe_mode=unsafe_mode,
    )

    status = tooling.inspect_trusted_system_executable(
        "iw", candidates=(candidate,), allowed_roots=(root,)
    )

    assert status.ready is False
    assert status.reason == "insecure_executable"


@pytest.mark.skipif(os.name != "posix", reason="POSIX merged-usr symlink semantics")
def test_catalog_accepts_trusted_merged_usr_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    usr_bin = tmp_path / "usr" / "bin"
    usr_bin.mkdir(parents=True)
    candidate = usr_bin / "iw"
    candidate.write_bytes(b"trusted")
    candidate.chmod(0o755)
    alias = tmp_path / "bin"
    alias.symlink_to(Path("usr") / "bin", target_is_directory=True)
    _fake_trusted_lstat(monkeypatch)

    status = tooling.inspect_trusted_system_executable(
        "iw", candidates=(alias / "iw",), allowed_roots=(alias,)
    )

    assert status.ready is True
    assert status.path == candidate
    assert status.identity is not None


@pytest.mark.skipif(os.name != "posix", reason="POSIX executable symlink semantics")
def test_catalog_rejects_symlink_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "usr" / "bin"
    outside = tmp_path / "opt"
    root.mkdir(parents=True)
    outside.mkdir()
    target = outside / "iw"
    target.write_bytes(b"untrusted target")
    target.chmod(0o755)
    candidate = root / "iw"
    candidate.symlink_to(target)
    _fake_trusted_lstat(monkeypatch)

    status = tooling.inspect_trusted_system_executable(
        "iw", candidates=(candidate,), allowed_roots=(root,)
    )

    assert status.ready is False
    assert status.reason == "insecure_executable"


@pytest.mark.skipif(os.name != "posix", reason="POSIX executable identity semantics")
def test_replacement_after_inspection_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "usr" / "bin"
    root.mkdir(parents=True)
    candidate = root / "iw"
    candidate.write_bytes(b"first")
    candidate.chmod(0o755)
    _fake_trusted_lstat(monkeypatch)
    status = tooling.inspect_trusted_system_executable(
        "iw", candidates=(candidate,), allowed_roots=(root,)
    )
    assert status.ready

    candidate.unlink()
    candidate.write_bytes(b"second")
    candidate.chmod(0o755)

    with pytest.raises(PermissionError, match="identity or permissions changed"):
        tooling.revalidate_trusted_executable(status)


@pytest.mark.skipif(os.name != "posix", reason="POSIX probe pipes and executable semantics")
def test_trusted_probe_closes_environment_cwd_and_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "trusted tools"
    root.mkdir()
    candidate = root / "probe with spaces"
    candidate.write_text(
        "#!/bin/sh\n"
        "if IFS= read -r value; then exit 9; fi\n"
        'printf \'%s|%s\' "$PWD" "$PATH"\n',
        encoding="utf-8",
    )
    candidate.chmod(0o755)
    _fake_trusted_lstat(monkeypatch)
    status = tooling.inspect_trusted_system_executable(
        "probe", candidates=(candidate,), allowed_roots=(root,)
    )

    result = tooling._fixed_probe(status, [])

    assert result.ok is True
    assert result.output == "/|/usr/sbin:/usr/bin:/sbin:/bin"


@pytest.mark.skipif(os.name != "posix", reason="POSIX probe pipes and executable semantics")
def test_trusted_probe_enforces_output_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "bin"
    root.mkdir()
    candidate = root / "noisy"
    candidate.write_text(
        '#!/bin/sh\ni=0; while [ "$i" -lt 1000 ]; do printf x; i=$((i + 1)); done\n',
        encoding="utf-8",
    )
    candidate.chmod(0o755)
    _fake_trusted_lstat(monkeypatch)
    status = tooling.inspect_trusted_system_executable(
        "noisy", candidates=(candidate,), allowed_roots=(root,)
    )

    result = tooling._fixed_probe(status, [], max_output_bytes=64)

    assert result.ok is False
    assert result.reason == "technical_self_check_output_limit"
