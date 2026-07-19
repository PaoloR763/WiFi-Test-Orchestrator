from __future__ import annotations

import hashlib
import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[5]
PACKAGING = ROOT / "agents" / "desktop" / "packaging" / "linux"
SCRIPTS = ROOT / "scripts" / "linux"


def test_static_systemd_and_deb_validator_passes() -> None:
    module = runpy.run_path(str(SCRIPTS / "validate_packaging.py"))
    module["validate_units"]()
    module["validate_scripts"]()
    module["validate_control"]()
    module["validate_conffiles"]()


@pytest.mark.parametrize(
    "content",
    (
        b"etc/wto-agent/wto-agent.toml\n/etc/wto-agent/capture-node.toml\n",
        b"/etc/wto-agent/wto-agent.toml \n/etc/wto-agent/capture-node.toml\n",
        b"/etc//wto-agent/wto-agent.toml\n/etc/wto-agent/capture-node.toml\n",
        b"/etc/./wto-agent.toml\n/etc/wto-agent/capture-node.toml\n",
        b"/etc/wto-agent/../wto-agent.toml\n/etc/wto-agent/capture-node.toml\n",
        b"/etc/wto-agent/wto-agent.toml/\n/etc/wto-agent/capture-node.toml\n",
        b"/etc/wto-agent/wto-agent.toml\x00\n/etc/wto-agent/capture-node.toml\n",
        b"/etc/wto-agent/wto-agent.toml\r\n/etc/wto-agent/capture-node.toml\r\n",
        b"/etc/wto-agent/wto-agent.toml\n/etc/wto-agent/wto-agent.toml\n",
        b"/etc/wto-agent/wto-agent.toml\n/etc/wto-agent/extra.toml\n",
    ),
)
def test_conffiles_validator_rejects_noncanonical_or_unexpected_entries(
    tmp_path: Path,
    content: bytes,
) -> None:
    path = tmp_path / "conffiles"
    path.write_bytes(content)
    module = runpy.run_path(str(SCRIPTS / "validate_packaging.py"))

    with pytest.raises(AssertionError):
        module["validate_conffiles"](path)


def test_conffiles_contains_each_canonical_configuration_once() -> None:
    raw = (PACKAGING / "debian" / "conffiles").read_bytes()
    assert raw == (b"/etc/wto-agent/wto-agent.toml\n" b"/etc/wto-agent/capture-node.toml\n")
    assert raw.count(b"\n") == 2
    assert b"\r" not in raw
    lines = raw.decode("utf-8").splitlines()

    assert lines == [
        "/etc/wto-agent/wto-agent.toml",
        "/etc/wto-agent/capture-node.toml",
    ]


def test_endpoint_and_capture_units_have_separate_users_and_privileges() -> None:
    endpoint = (PACKAGING / "systemd" / "wto-agent.service").read_text(encoding="utf-8")
    capture = (PACKAGING / "systemd" / "wto-agent-capture.service").read_text(encoding="utf-8")

    assert "User=wto-agent" in endpoint
    assert "Group=wto-agent" in endpoint
    assert "CapabilityBoundingSet=\n" in endpoint
    assert "AmbientCapabilities=\n" in endpoint
    assert "AF_PACKET" not in endpoint
    assert "User=wto-capture" in capture
    assert "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW" in capture
    assert "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW" in capture
    assert "CAP_SYS_ADMIN" not in endpoint + capture
    for directive in (
        "NoNewPrivileges=yes",
        "PrivateTmp=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "RestrictNamespaces=yes",
        "LockPersonality=yes",
        "MemoryDenyWriteExecute=yes",
        "TimeoutStartSec=",
        "TimeoutStopSec=",
        "Restart=on-failure",
    ):
        assert directive in endpoint
        assert directive in capture
    assert "ProtectControlGroups=yes" in endpoint
    assert "Delegate=" not in endpoint
    assert "ProtectControlGroups=no" in capture
    assert "Delegate=yes" in capture
    assert "KillMode=control-group" in capture


def test_package_lifecycle_is_noninteractive_integrity_checked_and_preserves_data() -> None:
    build = (SCRIPTS / "build-deb.sh").read_text(encoding="utf-8")
    install = (SCRIPTS / "install-agent.sh").read_text(encoding="utf-8")
    upgrade = (SCRIPTS / "upgrade-agent.sh").read_text(encoding="utf-8")
    rollback = (SCRIPTS / "rollback-agent.sh").read_text(encoding="utf-8")
    uninstall = (SCRIPTS / "uninstall-agent.sh").read_text(encoding="utf-8")
    postrm = (PACKAGING / "debian" / "postrm").read_text(encoding="utf-8")

    assert "dpkg-deb --build --root-owner-group" in build
    assert "SOURCE_DATE_EPOCH" in build
    assert "sha256sum" in build + install
    assert "curl" not in build + install + upgrade
    assert "wget" not in build + install + upgrade
    assert "maintenance backup" in upgrade
    assert '"$SYSTEMCTL" stop' in upgrade
    assert "--property=ActiveState --value" in upgrade
    assert "active|inactive|failed" in upgrade
    assert "not-found" in upgrade
    assert "require_unit_inactive wto-agent.service" in upgrade
    assert "require_unit_inactive wto-agent-capture.service" in upgrade
    assert "systemctl stop wto-agent.service wto-agent-capture.service || true" not in upgrade
    assert "--confirm-rollback" in rollback
    assert "maintenance restore" in rollback
    assert '"$SYSTEMCTL" stop' in rollback
    assert "--property=ActiveState --value" in rollback
    assert "active|inactive|failed" in rollback
    assert "not-found" in rollback
    assert "require_unit_inactive wto-agent.service" in rollback
    assert "require_unit_inactive wto-agent-capture.service" in rollback
    assert "systemctl stop wto-agent.service wto-agent-capture.service || true" not in rollback
    assert "dpkg --remove" in uninstall
    assert "dpkg --purge" in uninstall
    assert "remove|purge|disappear)" in postrm
    assert (
        "upgrade|failed-upgrade|abort-install|abort-upgrade|abort-remove|abort-deconfigure)"
        in postrm
    )
    assert 'if [ "$ACTION" = purge ]' in postrm
    assert "--force-confdef" in install
    assert "--force-confold" in install
    assert "STAGED_PACKAGE" in install
    assert 'dpkg --force-confdef --force-confold --install -- "$STAGED_PACKAGE"' in install
    assert "/usr/sbin/runuser --user wto-agent" in upgrade
    assert "/usr/sbin/runuser --user wto-capture" in upgrade
    assert '/usr/sbin/runuser --user "$SERVICE_USER"' in rollback
    assert "rm -rf -- /var/lib/wto-agent" not in uninstall

    control = (PACKAGING / "debian" / "control.in").read_text(encoding="utf-8")
    postinst = (PACKAGING / "debian" / "postinst").read_text(encoding="utf-8")
    wrapper = (PACKAGING / "bin" / "wto-agent").read_text(encoding="utf-8")
    assert "python3-pydantic" not in control
    assert "python3-venv" in control
    assert "--no-index" in postinst
    assert "--find-links" in postinst
    assert "--no-deps" in postinst
    assert "pydantic.__version__" in postinst
    assert "prepare_linux_state_directory" in postinst
    assert "expected_uid=uid" in postinst
    assert "expected_gid=gid" in postinst
    assert "created_owner=(uid, gid)" in postinst
    assert "install -d -m 0700 -o wto-agent" not in postinst
    assert "install -d -m 0700 -o wto-capture" not in postinst
    assert "/usr/lib/wto-agent/venv/bin/python" in wrapper
    assert "PYTHONPATH=/usr/lib/wto-agent" not in wrapper

    runtime_test = (SCRIPTS / "test-deb-runtime.sh").read_text(encoding="utf-8")
    assert "chmod 0755 /var/lib/wto-agent /var/lib/wto-agent-capture" in runtime_test
    assert "upgrade-sentinel" in runtime_test
    assert "stat -c %a /var/lib/wto-agent" in runtime_test


def _script_with_test_systemctl(source: Path, destination: Path, systemctl: Path) -> Path:
    text = source.read_text(encoding="utf-8")
    text = text.replace("/usr/bin/systemctl", systemctl.as_posix())
    text = text.replace('if [ "$(id -u)" -ne 0 ]', "if false")
    destination.write_text(text, encoding="utf-8")
    destination.chmod(0o700)
    return destination


ROOT_POSIX = pytest.mark.skipif(
    os.name != "posix" or getattr(os, "geteuid", lambda: 1)() != 0,
    reason="root POSIX package lifecycle semantics",
)


def _package_lifecycle_fixture(tmp_path: Path) -> tuple[Path, dict[str, str], Path]:
    manager = tmp_path / "systemd-manager"
    manager.mkdir()
    state_directory = tmp_path / "package-state"
    endpoint_state = tmp_path / "endpoint.state"
    capture_state = tmp_path / "capture.state"
    log = tmp_path / "systemctl.log"
    fake_systemctl = tmp_path / "systemctl"
    fake_systemctl.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >> "$FAKE_SYSTEMCTL_LOG"\n'
        'case "$2" in wto-agent.service) STATE=$FAKE_ENDPOINT_STATE ;; '
        "wto-agent-capture.service) STATE=$FAKE_CAPTURE_STATE ;; *) STATE= ;; esac\n"
        'if [ "$1" = show ] && [ "$3" = "--property=LoadState" ]; '
        'then printf "loaded\\n"; exit 0; fi\n'
        'if [ "$1" = show ] && [ "$3" = "--property=ActiveState" ]; '
        'then cat "$STATE"; exit 0; fi\n'
        'if [ "$1" = stop ]; then\n'
        '    if [ "$2" = wto-agent.service ] && [ -n "${FAKE_RUNTIME_DIR:-}" ]; '
        'then rm -rf -- "$FAKE_RUNTIME_DIR"; fi\n'
        '    if [ "$2" = wto-agent-capture.service ] && '
        '[ -e "${FAKE_FAIL_CAPTURE_STOP_ONCE:-/nonexistent}" ]; then\n'
        '        rm -- "$FAKE_FAIL_CAPTURE_STOP_ONCE"\n'
        "        exit 19\n"
        "    fi\n"
        '    printf "inactive\\n" > "$STATE"\n'
        "    exit 0\n"
        "fi\n"
        'if [ "$1" = start ]; then\n'
        '    if [ "$2" = wto-agent-capture.service ] && '
        '[ -e "${FAKE_FAIL_CAPTURE_ONCE:-/nonexistent}" ]; then\n'
        '        rm -- "$FAKE_FAIL_CAPTURE_ONCE"\n'
        "        exit 17\n"
        "    fi\n"
        '    printf "active\\n" > "$STATE"\n'
        "    exit 0\n"
        "fi\n"
        'if [ "$1" = daemon-reload ]; then exit 0; fi\n'
        "exit 91\n",
        encoding="utf-8",
    )
    fake_systemctl.chmod(0o700)
    source = PACKAGING / "bin" / "wto-agent-package-lifecycle"
    helper = tmp_path / "package-lifecycle"
    helper.write_text(
        source.read_text(encoding="utf-8")
        .replace("/run/wto-agent-package-maintainer", state_directory.as_posix())
        .replace("/run/systemd/system", manager.as_posix())
        .replace("/usr/bin/systemctl", fake_systemctl.as_posix()),
        encoding="utf-8",
    )
    helper.chmod(0o700)
    environment = {
        **os.environ,
        "FAKE_SYSTEMCTL_LOG": str(log),
        "FAKE_ENDPOINT_STATE": str(endpoint_state),
        "FAKE_CAPTURE_STATE": str(capture_state),
    }
    return helper, environment, state_directory


@ROOT_POSIX
def test_package_lifecycle_state_survives_service_runtime_removal(
    tmp_path: Path,
) -> None:
    helper, environment, state_directory = _package_lifecycle_fixture(tmp_path)
    Path(environment["FAKE_ENDPOINT_STATE"]).write_text("active\n", encoding="utf-8")
    Path(environment["FAKE_CAPTURE_STATE"]).write_text("inactive\n", encoding="utf-8")
    service_runtime = tmp_path / "service-runtime"
    service_runtime.mkdir()
    environment["FAKE_RUNTIME_DIR"] = str(service_runtime)

    subprocess.run(
        ["/bin/sh", str(helper), "quiesce", "upgrade"],
        check=True,
        env=environment,
    )

    state_file = state_directory / "upgrade-state"
    assert not service_runtime.exists()
    assert state_file.is_file()
    assert "endpoint=active" in state_file.read_text(encoding="utf-8")
    subprocess.run(
        ["/bin/sh", str(helper), "resume", "upgrade"],
        check=True,
        env=environment,
    )
    assert Path(environment["FAKE_ENDPOINT_STATE"]).read_text(encoding="utf-8") == "active\n"
    assert not state_file.exists()
    subprocess.run(
        ["/bin/sh", str(helper), "resume", "any"],
        check=True,
        env=environment,
    )


@ROOT_POSIX
def test_package_lifecycle_resume_keeps_state_until_every_start_succeeds(
    tmp_path: Path,
) -> None:
    helper, environment, state_directory = _package_lifecycle_fixture(tmp_path)
    Path(environment["FAKE_ENDPOINT_STATE"]).write_text("active\n", encoding="utf-8")
    Path(environment["FAKE_CAPTURE_STATE"]).write_text("active\n", encoding="utf-8")
    subprocess.run(
        ["/bin/sh", str(helper), "quiesce", "upgrade"],
        check=True,
        env=environment,
    )
    fail_once = tmp_path / "fail-capture-once"
    fail_once.touch()
    environment["FAKE_FAIL_CAPTURE_ONCE"] = str(fail_once)

    first = subprocess.run(
        ["/bin/sh", str(helper), "resume", "upgrade"],
        check=False,
        env=environment,
    )

    assert first.returncode == 17
    assert (state_directory / "upgrade-state").is_file()
    subprocess.run(
        ["/bin/sh", str(helper), "resume", "upgrade"],
        check=True,
        env=environment,
    )
    assert not (state_directory / "upgrade-state").exists()
    calls = Path(environment["FAKE_SYSTEMCTL_LOG"]).read_text(encoding="utf-8")
    assert calls.count("start wto-agent.service\n") == 1
    assert calls.count("start wto-agent-capture.service\n") == 2


@ROOT_POSIX
def test_failed_upgrade_fallback_aborts_and_abort_upgrade_resumes_state(
    tmp_path: Path,
) -> None:
    helper, environment, state_directory = _package_lifecycle_fixture(tmp_path)
    endpoint_state = Path(environment["FAKE_ENDPOINT_STATE"])
    capture_state = Path(environment["FAKE_CAPTURE_STATE"])
    endpoint_state.write_text("active\n", encoding="utf-8")
    capture_state.write_text("active\n", encoding="utf-8")
    fail_capture_stop = tmp_path / "fail-capture-stop-once"
    fail_capture_stop.touch()
    environment["FAKE_FAIL_CAPTURE_STOP_ONCE"] = str(fail_capture_stop)
    old_prerm = tmp_path / "old-prerm"
    old_prerm.write_text(
        (PACKAGING / "debian" / "prerm")
        .read_text(encoding="utf-8")
        .replace("/usr/lib/wto-agent/package-lifecycle", helper.as_posix()),
        encoding="utf-8",
    )
    new_prerm = tmp_path / "new-prerm"
    new_prerm.write_text(old_prerm.read_text(encoding="utf-8"), encoding="utf-8")
    postinst = tmp_path / "postinst"
    postinst.write_text(
        (PACKAGING / "debian" / "postinst")
        .read_text(encoding="utf-8")
        .replace("/usr/lib/wto-agent/package-lifecycle", helper.as_posix()),
        encoding="utf-8",
    )

    old_failed = subprocess.run(
        ["/bin/sh", str(old_prerm), "upgrade"],
        check=False,
        env=environment,
        capture_output=True,
        text=True,
    )
    fallback_failed = subprocess.run(
        ["/bin/sh", str(new_prerm), "failed-upgrade"],
        check=False,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert old_failed.returncode == 19
    assert fallback_failed.returncode == 5
    state_file = state_directory / "upgrade-state"
    assert "endpoint=active" in state_file.read_text(encoding="utf-8")
    assert "capture=active" in state_file.read_text(encoding="utf-8")
    assert endpoint_state.read_text(encoding="utf-8") == "inactive\n"
    assert capture_state.read_text(encoding="utf-8") == "active\n"
    recovered = subprocess.run(
        ["/bin/sh", str(postinst), "abort-upgrade"],
        check=False,
        env=environment,
    )
    assert recovered.returncode == 0
    assert endpoint_state.read_text(encoding="utf-8") == "active\n"
    assert capture_state.read_text(encoding="utf-8") == "active\n"
    assert not state_file.exists()


@ROOT_POSIX
def test_installer_uses_verified_staging_after_source_name_is_swapped(
    tmp_path: Path,
) -> None:
    original = b"verified package fixture"
    source = tmp_path / "candidate.deb"
    source.write_bytes(original)
    expected = hashlib.sha256(original).hexdigest()
    captured = tmp_path / "installed.deb"
    log = tmp_path / "dpkg.log"
    marker = tmp_path / "swapped"
    fake_sha = tmp_path / "sha256sum"
    fake_sha.write_text(
        "#!/bin/sh\n"
        'if [ ! -e "$SWAP_MARKER" ]; then\n'
        '    mv -- "$UNTRUSTED_SOURCE" "$UNTRUSTED_SOURCE.before"\n'
        '    printf evil > "$UNTRUSTED_SOURCE"\n'
        '    touch "$SWAP_MARKER"\n'
        "fi\n"
        'exec /usr/bin/sha256sum "$@"\n',
        encoding="utf-8",
    )
    fake_sha.chmod(0o700)
    fake_dpkg_deb = tmp_path / "dpkg-deb"
    fake_dpkg_deb.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_dpkg_deb.chmod(0o700)
    fake_dpkg = tmp_path / "dpkg"
    fake_dpkg.write_text(
        "#!/bin/sh\n"
        "LAST=\n"
        'for VALUE in "$@"; do LAST=$VALUE; done\n'
        'cp -- "$LAST" "$CAPTURED_PACKAGE"\n'
        'printf "%s\\n" "$*" > "$DPKG_LOG"\n'
        "if IFS= read -r INPUT; then exit 88; fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    fake_dpkg.chmod(0o700)
    installer = tmp_path / "install-agent.sh"
    text = (SCRIPTS / "install-agent.sh").read_text(encoding="utf-8")
    text = text.replace(
        "/run/wto-agent-package-installer.XXXXXX",
        f"{tmp_path.as_posix()}/installer.XXXXXX",
    )
    text = text.replace("/usr/bin/dpkg-deb", fake_dpkg_deb.as_posix())
    text = text.replace("/usr/bin/dpkg", fake_dpkg.as_posix())
    text = text.replace("/usr/bin/sha256sum", fake_sha.as_posix())
    text = text.replace("/usr/bin/python3", Path(sys.executable).as_posix())
    installer.write_text(text, encoding="utf-8")
    installer.chmod(0o700)

    completed = subprocess.run(
        ["/bin/sh", str(installer), str(source), expected],
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "UNTRUSTED_SOURCE": str(source),
            "SWAP_MARKER": str(marker),
            "CAPTURED_PACKAGE": str(captured),
            "DPKG_LOG": str(log),
        },
    )

    assert completed.returncode == 0, completed.stderr
    assert source.read_bytes() == b"evil"
    assert captured.read_bytes() == original
    arguments = log.read_text(encoding="utf-8")
    assert "--force-confdef --force-confold --install" in arguments
    assert str(source) not in arguments


@pytest.mark.skipif(os.name != "posix", reason="POSIX packaging script semantics")
@pytest.mark.parametrize("operation", ("upgrade", "rollback"))
def test_lifecycle_aborts_before_mutation_when_service_stop_fails(
    tmp_path: Path,
    operation: str,
) -> None:
    log = tmp_path / "systemctl.log"
    fake_systemctl = tmp_path / "systemctl"
    fake_systemctl.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >> "$FAKE_SYSTEMCTL_LOG"\n'
        'if [ "$1" = "show" ] && [ "$3" = "--property=LoadState" ]; '
        'then printf "loaded\\n"; exit 0; fi\n'
        'if [ "$1" = "show" ] && [ "$3" = "--property=ActiveState" ]; then\n'
        '    if [ "$2" = "wto-agent.service" ]; then printf "active\\n"; '
        'else printf "inactive\\n"; fi\n'
        "    exit 0\n"
        "fi\n"
        'if [ "$1" = "stop" ]; then exit 1; fi\n'
        "exit 0\n",
        encoding="utf-8",
    )
    fake_systemctl.chmod(0o700)
    script = _script_with_test_systemctl(
        SCRIPTS / f"{operation}-agent.sh",
        tmp_path / f"{operation}-agent.sh",
        fake_systemctl,
    )
    install = tmp_path / "install-agent.sh"
    install.write_text("#!/bin/sh\nprintf reached > install-called\n", encoding="utf-8")
    install.chmod(0o700)
    arguments = ["/bin/sh", str(script), str(tmp_path / "agent.deb"), "a" * 64]
    if operation == "rollback":
        backup = tmp_path / "rollback.bak"
        backup.write_bytes(b"verified fixture")
        script.write_text(
            script.read_text(encoding="utf-8").replace(
                "/var/lib/wto-agent/*.bak",
                f"{tmp_path.as_posix()}/*.bak",
            ),
            encoding="utf-8",
        )
        arguments.extend([str(backup), "--confirm-rollback"])
    environment = {**os.environ, "FAKE_SYSTEMCTL_LOG": str(log)}

    completed = subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        cwd=tmp_path,
    )

    assert completed.returncode == 5
    assert "failed to stop wto-agent.service" in completed.stderr
    assert not (tmp_path / "install-called").exists()
    expected_calls = [
        "show wto-agent.service --property=LoadState --value",
        "show wto-agent.service --property=ActiveState --value",
        "show wto-agent-capture.service --property=LoadState --value",
        "show wto-agent-capture.service --property=ActiveState --value",
        "stop wto-agent.service",
    ]
    if operation == "upgrade":
        expected_calls.append("start wto-agent.service")
    assert log.read_text(encoding="utf-8").splitlines() == expected_calls


@pytest.mark.skipif(os.name != "posix", reason="POSIX packaging script semantics")
@pytest.mark.parametrize("operation", ("upgrade", "rollback"))
def test_lifecycle_rejects_deactivating_state_before_mutation(
    tmp_path: Path,
    operation: str,
) -> None:
    log = tmp_path / "systemctl.log"
    fake_systemctl = tmp_path / "systemctl"
    fake_systemctl.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >> "$FAKE_SYSTEMCTL_LOG"\n'
        'if [ "$1" = "show" ] && [ "$3" = "--property=LoadState" ]; '
        'then printf "loaded\\n"; exit 0; fi\n'
        'if [ "$1" = "show" ] && [ "$3" = "--property=ActiveState" ]; '
        'then printf "deactivating\\n"; exit 0; fi\n'
        "exit 91\n",
        encoding="utf-8",
    )
    fake_systemctl.chmod(0o700)
    script = _script_with_test_systemctl(
        SCRIPTS / f"{operation}-agent.sh",
        tmp_path / f"{operation}-agent.sh",
        fake_systemctl,
    )
    install = tmp_path / "install-agent.sh"
    install.write_text("#!/bin/sh\nprintf reached > install-called\n", encoding="utf-8")
    install.chmod(0o700)
    arguments = ["/bin/sh", str(script), str(tmp_path / "agent.deb"), "a" * 64]
    if operation == "rollback":
        backup = tmp_path / "rollback.bak"
        backup.write_bytes(b"verified fixture")
        script.write_text(
            script.read_text(encoding="utf-8").replace(
                "/var/lib/wto-agent/*.bak",
                f"{tmp_path.as_posix()}/*.bak",
            ),
            encoding="utf-8",
        )
        arguments.extend([str(backup), "--confirm-rollback"])

    completed = subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "FAKE_SYSTEMCTL_LOG": str(log)},
        cwd=tmp_path,
    )

    assert completed.returncode == 5
    assert "unsafe ActiveState 'deactivating' for wto-agent.service" in completed.stderr
    assert not (tmp_path / "install-called").exists()
    calls = log.read_text(encoding="utf-8").splitlines()
    assert calls == [
        "show wto-agent.service --property=LoadState --value",
        "show wto-agent.service --property=ActiveState --value",
    ]
    assert all(not call.startswith(("stop ", "start ")) for call in calls)


@ROOT_POSIX
def test_upgrade_restores_endpoint_when_capture_stop_fails(tmp_path: Path) -> None:
    log = tmp_path / "systemctl.log"
    fake_systemctl = tmp_path / "systemctl"
    fake_systemctl.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >> "$FAKE_SYSTEMCTL_LOG"\n'
        'if [ "$1" = show ] && [ "$3" = "--property=LoadState" ]; '
        'then printf "loaded\\n"; exit 0; fi\n'
        'if [ "$1" = show ] && [ "$3" = "--property=ActiveState" ]; '
        'then printf "active\\n"; exit 0; fi\n'
        'if [ "$1" = stop ] && [ "$2" = wto-agent-capture.service ]; then exit 1; fi\n'
        "exit 0\n",
        encoding="utf-8",
    )
    fake_systemctl.chmod(0o700)
    script = _script_with_test_systemctl(
        SCRIPTS / "upgrade-agent.sh",
        tmp_path / "upgrade-agent.sh",
        fake_systemctl,
    )
    install = tmp_path / "install-agent.sh"
    install.write_text("#!/bin/sh\nprintf reached > install-called\n", encoding="utf-8")
    install.chmod(0o700)

    completed = subprocess.run(
        ["/bin/sh", str(script), str(tmp_path / "agent.deb"), "a" * 64],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "FAKE_SYSTEMCTL_LOG": str(log)},
        cwd=tmp_path,
    )

    assert completed.returncode == 5
    assert "failed to stop wto-agent-capture.service" in completed.stderr
    assert not (tmp_path / "install-called").exists()
    calls = log.read_text(encoding="utf-8").splitlines()
    assert "start wto-agent.service" in calls
    assert "start wto-agent-capture.service" in calls


def _relocate_agent_state_paths(text: str, tmp_path: Path) -> str:
    return text.replace(
        "/var/lib/wto-agent-capture",
        (tmp_path / "capture-state").as_posix(),
    ).replace(
        "/var/lib/wto-agent",
        (tmp_path / "endpoint-state").as_posix(),
    )


@ROOT_POSIX
def test_upgrade_runs_each_backup_as_its_service_account(tmp_path: Path) -> None:
    fake_systemctl = tmp_path / "systemctl"
    fake_systemctl.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = show ] && [ "$3" = "--property=LoadState" ]; '
        'then printf "loaded\\n"; exit 0; fi\n'
        'if [ "$1" = show ] && [ "$3" = "--property=ActiveState" ]; '
        'then printf "inactive\\n"; exit 0; fi\n'
        "exit 0\n",
        encoding="utf-8",
    )
    fake_systemctl.chmod(0o700)
    runuser_log = tmp_path / "runuser.log"
    fake_runuser = tmp_path / "runuser"
    fake_runuser.write_text(
        '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$RUNUSER_LOG"\n',
        encoding="utf-8",
    )
    fake_runuser.chmod(0o700)
    text = (SCRIPTS / "upgrade-agent.sh").read_text(encoding="utf-8")
    text = _relocate_agent_state_paths(text, tmp_path)
    text = text.replace("/usr/bin/systemctl", fake_systemctl.as_posix())
    text = text.replace("/usr/sbin/runuser", fake_runuser.as_posix())
    text = text.replace('if [ "$(id -u)" -ne 0 ]', "if false")
    script = tmp_path / "upgrade-agent.sh"
    script.write_text(text, encoding="utf-8")
    script.chmod(0o700)
    install = tmp_path / "install-agent.sh"
    install.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    install.chmod(0o700)
    endpoint = tmp_path / "endpoint-state"
    capture = tmp_path / "capture-state"
    endpoint.mkdir()
    capture.mkdir()
    (endpoint / "agent.sqlite3").write_bytes(b"endpoint")
    (capture / "agent.sqlite3").write_bytes(b"capture")

    subprocess.run(
        [
            "/bin/sh",
            str(script),
            str(tmp_path / "agent.deb"),
            "a" * 64,
            str(endpoint / "custom.bak"),
        ],
        check=True,
        env={**os.environ, "RUNUSER_LOG": str(runuser_log)},
        cwd=tmp_path,
    )

    calls = runuser_log.read_text(encoding="utf-8").splitlines()
    assert calls[0].startswith("--user wto-agent -- /usr/bin/wto-agent ")
    assert "maintenance backup" in calls[0]
    assert calls[1].startswith("--user wto-capture -- /usr/bin/wto-agent ")
    assert "maintenance backup" in calls[1]


@ROOT_POSIX
@pytest.mark.parametrize(
    ("role", "expected_user"),
    (("endpoint", "wto-agent"), ("capture", "wto-capture")),
)
def test_rollback_runs_restore_as_service_account(
    tmp_path: Path,
    role: str,
    expected_user: str,
) -> None:
    fake_systemctl = tmp_path / "systemctl"
    fake_systemctl.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = show ] && [ "$3" = "--property=LoadState" ]; '
        'then printf "loaded\\n"; exit 0; fi\n'
        'if [ "$1" = show ] && [ "$3" = "--property=ActiveState" ]; '
        'then printf "inactive\\n"; exit 0; fi\n'
        "exit 0\n",
        encoding="utf-8",
    )
    fake_systemctl.chmod(0o700)
    runuser_log = tmp_path / "runuser.log"
    fake_runuser = tmp_path / "runuser"
    fake_runuser.write_text(
        '#!/bin/sh\nprintf \'%s\\n\' "$*" > "$RUNUSER_LOG"\n',
        encoding="utf-8",
    )
    fake_runuser.chmod(0o700)
    text = (SCRIPTS / "rollback-agent.sh").read_text(encoding="utf-8")
    text = _relocate_agent_state_paths(text, tmp_path)
    text = text.replace("/usr/bin/systemctl", fake_systemctl.as_posix())
    text = text.replace("/usr/sbin/runuser", fake_runuser.as_posix())
    text = text.replace('if [ "$(id -u)" -ne 0 ]', "if false")
    script = tmp_path / "rollback-agent.sh"
    script.write_text(text, encoding="utf-8")
    script.chmod(0o700)
    install = tmp_path / "install-agent.sh"
    install.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    install.chmod(0o700)
    state = tmp_path / f"{role}-state"
    state.mkdir()
    backup = state / "rollback.bak"
    backup.write_bytes(b"verified")

    subprocess.run(
        [
            "/bin/sh",
            str(script),
            str(tmp_path / "agent.deb"),
            "a" * 64,
            str(backup),
            "--confirm-rollback",
        ],
        check=True,
        env={**os.environ, "RUNUSER_LOG": str(runuser_log)},
        cwd=tmp_path,
    )

    call = runuser_log.read_text(encoding="utf-8")
    assert call.startswith(f"--user {expected_user} -- /usr/bin/wto-agent ")
    assert "maintenance restore" in call


def test_package_does_not_install_or_run_optional_tools() -> None:
    all_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [*PACKAGING.rglob("*"), *SCRIPTS.glob("*")]
        if path.is_file() and not path.name.startswith("Dockerfile.")
    )
    for command in (
        "apt install",
        "apt-get install",
        "dnf install",
        "yum install",
        "chmod 777",
        "tcpreplay --",
        "dumpcap -i",
    ):
        assert command not in all_text


def test_doctor_uses_only_allowlisted_service_identities() -> None:
    doctor = (SCRIPTS / "doctor.sh").read_text(encoding="utf-8")

    assert "endpoint)" in doctor
    assert "capture)" in doctor
    assert "SERVICE_USER=wto-agent" in doctor
    assert "SERVICE_USER=wto-capture" in doctor
    assert 'runuser --user "$SERVICE_USER" -- /usr/bin/wto-agent' in doctor
    assert "CONFIG=/etc/wto-agent/wto-agent.toml" in doctor
    assert "CONFIG=/etc/wto-agent/capture-node.toml" in doctor
    assert 'exit "$STATUS"' in doctor
    assert 'if [ "$(id -u)" -ne 0 ]' in doctor
    assert 'echo "role must be endpoint or capture"' in doctor
    assert "CONFIG=${1" not in doctor
    assert "eval " not in doctor
