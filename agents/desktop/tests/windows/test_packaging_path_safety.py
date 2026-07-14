from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.windows,
    pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows"),
]

ROOT = Path(__file__).resolve().parents[4]
WINDOWS_SCRIPTS = ROOT / "scripts" / "windows"
SYSTEM_ROOT = os.environ.get("SystemRoot")
POWERSHELL = (
    Path(SYSTEM_ROOT) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if SYSTEM_ROOT
    else Path("powershell.exe")
)
SYSTEM_VOLUME_ROOT = Path(SYSTEM_ROOT).anchor if SYSTEM_ROOT else os.sep
OTHER_VOLUME_ROOT = "D:" + os.sep


def _run_script(script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(POWERSHELL),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(WINDOWS_SCRIPTS / script),
            *arguments,
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )


def _layout(work_root: Path) -> tuple[Path, Path]:
    install_root = work_root / "install"
    data_root = work_root / "data"
    (data_root / "state").mkdir(parents=True)
    return install_root, data_root


def _uninstall(
    work_root: Path, install_root: str, data_root: str
) -> subprocess.CompletedProcess[str]:
    return _run_script(
        "uninstall-agent.ps1",
        "-InstallRoot",
        install_root,
        "-DataRoot",
        data_root,
        "-TestMode",
        "-WorkRoot",
        str(work_root),
    )


@pytest.mark.parametrize(
    "unsafe_install",
    [
        SYSTEM_VOLUME_ROOT,
        OTHER_VOLUME_ROOT,
        "relative\\agent",
        "install\\..\\sibling",
    ],
)
def test_testmode_rejects_roots_relative_paths_and_traversal(
    tmp_path: Path, unsafe_install: str
) -> None:
    install_root, data_root = _layout(tmp_path)
    del install_root

    result = _uninstall(tmp_path, unsafe_install, str(data_root))

    assert result.returncode != 0, result.stdout


@pytest.mark.parametrize("variable", ["ProgramFiles", "ProgramData", "SystemRoot"])
def test_testmode_rejects_protected_windows_directories(tmp_path: Path, variable: str) -> None:
    _, data_root = _layout(tmp_path)

    result = _uninstall(tmp_path, os.environ[variable], str(data_root))

    assert result.returncode != 0, result.stdout


def test_testmode_rejects_sibling_and_equal_layout_roots(tmp_path: Path) -> None:
    install_root, data_root = _layout(tmp_path)
    sibling = tmp_path.parent / f"{tmp_path.name}-sibling"

    sibling_result = _uninstall(tmp_path, str(sibling), str(data_root))
    equal_result = _uninstall(tmp_path, str(install_root), str(install_root))

    assert sibling_result.returncode != 0
    assert equal_result.returncode != 0


@pytest.mark.parametrize("variable", ["ProgramFiles", "ProgramData"])
def test_production_rejects_root_overrides(tmp_path: Path, variable: str) -> None:
    _, data_root = _layout(tmp_path)

    result = _run_script(
        "uninstall-agent.ps1",
        "-InstallRoot",
        os.environ[variable],
        "-DataRoot",
        str(data_root),
    )

    assert result.returncode != 0


def test_rollback_rejects_external_backup_and_previous_version_traversal(tmp_path: Path) -> None:
    install_root, data_root = _layout(tmp_path)
    executable = install_root / "versions" / "1.0.0" / "wto-agent.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"test executable")
    valid_backup = data_root / "state" / "agent.sqlite3.test-backup"
    valid_backup.write_bytes(b"test backup")
    external_backup = tmp_path / "agent.sqlite3.test-backup"
    external_backup.write_bytes(b"external backup")
    common = (
        "-InstallRoot",
        str(install_root),
        "-DataRoot",
        str(data_root),
        "-ConfirmRollback",
        "-TestMode",
        "-WorkRoot",
        str(tmp_path),
    )

    external_result = _run_script(
        "rollback-agent.ps1",
        "-PreviousVersion",
        "1.0.0",
        "-DatabaseBackup",
        str(external_backup),
        *common,
    )
    traversal_result = _run_script(
        "rollback-agent.ps1",
        "-PreviousVersion",
        "..\\1.0.0",
        "-DatabaseBackup",
        str(valid_backup),
        *common,
    )

    assert external_result.returncode != 0
    assert traversal_result.returncode != 0


def test_testmode_safe_temporary_layout_still_uninstalls_only_install_root(
    tmp_path: Path,
) -> None:
    install_root, data_root = _layout(tmp_path)
    install_root.mkdir()
    (install_root / "sentinel.txt").write_text("remove me", encoding="utf-8")
    (data_root / "sentinel.txt").write_text("preserve me", encoding="utf-8")

    result = _uninstall(tmp_path, str(install_root), str(data_root))

    assert result.returncode == 0, result.stderr
    assert not install_root.exists()
    assert (data_root / "sentinel.txt").read_text(encoding="utf-8") == "preserve me"


def test_reparse_point_root_is_rejected_when_junction_creation_is_available(
    tmp_path: Path,
) -> None:
    real_install = tmp_path / "real-install"
    install_link = tmp_path / "install-link"
    _, data_root = _layout(tmp_path)
    real_install.mkdir()
    environment = dict(os.environ)
    environment["WTO_TEST_LINK"] = str(install_link)
    environment["WTO_TEST_TARGET"] = str(real_install)
    creation = subprocess.run(
        [
            str(POWERSHELL),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "New-Item -ItemType Junction -Path $env:WTO_TEST_LINK "
            "-Target $env:WTO_TEST_TARGET | Out-Null",
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        env=environment,
    )
    if creation.returncode != 0:
        pytest.skip(f"junction creation unavailable: {creation.stderr}")
    try:
        result = _uninstall(tmp_path, str(install_link), str(data_root))
        assert result.returncode != 0
        assert real_install.exists()
    finally:
        os.rmdir(install_link)


def test_remove_approved_tree_rejects_path_outside_layout(tmp_path: Path) -> None:
    install_root, data_root = _layout(tmp_path)
    install_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    command = (
        f". '{WINDOWS_SCRIPTS / 'path-safety.ps1'}'; "
        "$layout = Resolve-WtoPathLayout -InstallRoot $args[0] -DataRoot $args[1] "
        "-TestMode -WorkRoot $args[2]; "
        "Remove-WtoApprovedTree -Path $args[3] -Layout $layout -Kind InstallRoot"
    )

    result = subprocess.run(
        [
            str(POWERSHELL),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
            str(install_root),
            str(data_root),
            str(tmp_path),
            str(outside),
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )

    assert result.returncode != 0
    assert outside.is_dir()


def test_recursive_remove_has_immediate_approved_path_guard() -> None:
    occurrences: list[tuple[Path, int]] = []
    for script in WINDOWS_SCRIPTS.glob("*.ps1"):
        lines = script.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if re.search(r"\bRemove-Item\b.*-Recurse\b", line, re.IGNORECASE):
                occurrences.append((script, index))
                previous = next(
                    (candidate for candidate in reversed(lines[:index]) if candidate.strip()), ""
                )
                assert "Assert-WtoApprovedRemovalTarget" in previous
                assert "-LiteralPath" in line
    assert len(occurrences) == 1
    assert occurrences[0][0] == WINDOWS_SCRIPTS / "path-safety.ps1"


def test_all_parameterized_packaging_scripts_resolve_the_safe_layout() -> None:
    for name in (
        "install-agent.ps1",
        "uninstall-agent.ps1",
        "upgrade-agent.ps1",
        "rollback-agent.ps1",
        "test-packaging.ps1",
    ):
        content = (WINDOWS_SCRIPTS / name).read_text(encoding="utf-8")
        assert "Resolve-WtoPathLayout" in content
        assert "Invoke-Expression" not in content
