from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
PACKAGING = ROOT / "agents" / "desktop" / "packaging" / "linux"
SCRIPTS = ROOT / "scripts" / "linux"
EXPECTED_CONFFILES = frozenset(
    {
        "/etc/wto-agent/wto-agent.toml",
        "/etc/wto-agent/capture-node.toml",
    }
)


def parse_unit(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    section = ""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if "=" not in line:
            raise AssertionError(f"invalid unit line in {path.name}: {line}")
        key, value = line.split("=", 1)
        result[f"{section}.{key}"] = value
    return result


def validate_units() -> None:
    endpoint = parse_unit(PACKAGING / "systemd" / "wto-agent.service")
    capture = parse_unit(PACKAGING / "systemd" / "wto-agent-capture.service")
    required = {
        "Service.User",
        "Service.Group",
        "Service.NoNewPrivileges",
        "Service.PrivateTmp",
        "Service.ProtectSystem",
        "Service.ProtectHome",
        "Service.ProtectKernelTunables",
        "Service.ProtectKernelModules",
        "Service.ProtectControlGroups",
        "Service.RestrictNamespaces",
        "Service.RestrictAddressFamilies",
        "Service.LockPersonality",
        "Service.MemoryDenyWriteExecute",
        "Service.CapabilityBoundingSet",
        "Service.AmbientCapabilities",
        "Service.ReadWritePaths",
        "Service.Restart",
        "Service.TimeoutStartSec",
        "Service.TimeoutStopSec",
        "Service.RuntimeDirectory",
        "Service.StateDirectory",
        "Service.LogsDirectory",
    }
    for name, unit in (("endpoint", endpoint), ("capture", capture)):
        missing = required - unit.keys()
        if missing:
            raise AssertionError(f"{name} unit misses {sorted(missing)}")
        for key in (
            "Service.NoNewPrivileges",
            "Service.PrivateTmp",
            "Service.ProtectKernelTunables",
            "Service.ProtectKernelModules",
            "Service.RestrictNamespaces",
            "Service.LockPersonality",
            "Service.MemoryDenyWriteExecute",
        ):
            if unit[key] != "yes":
                raise AssertionError(f"{name} unit does not enable {key}")
    if endpoint["Service.ProtectControlGroups"] != "yes":
        raise AssertionError("endpoint unit must not receive cgroup delegation")
    if "Service.Delegate" in endpoint:
        raise AssertionError("endpoint unit must not declare Delegate")
    if capture["Service.ProtectControlGroups"] != "no":
        raise AssertionError(
            "capture unit must expose only its delegated cgroup subtree"
        )
    if capture.get("Service.Delegate") != "yes":
        raise AssertionError("capture unit requires a delegated cgroup subtree")
    if capture.get("Service.KillMode") != "control-group":
        raise AssertionError("capture unit must retain systemd control-group cleanup")
    if (
        endpoint["Service.User"] != "wto-agent"
        or endpoint["Service.Group"] != "wto-agent"
    ):
        raise AssertionError("endpoint unit has an unexpected account")
    if (
        endpoint["Service.CapabilityBoundingSet"]
        or endpoint["Service.AmbientCapabilities"]
    ):
        raise AssertionError("endpoint unit must have an empty capability set")
    expected = {"CAP_NET_ADMIN", "CAP_NET_RAW"}
    if set(capture["Service.CapabilityBoundingSet"].split()) != expected:
        raise AssertionError("capture unit capability bounding set is not minimal")
    if set(capture["Service.AmbientCapabilities"].split()) != expected:
        raise AssertionError("capture unit ambient capability set is not minimal")
    if "CAP_SYS_ADMIN" in " ".join([*endpoint.values(), *capture.values()]):
        raise AssertionError("CAP_SYS_ADMIN is forbidden")


def validate_scripts() -> None:
    files = [
        *(
            path
            for path in PACKAGING.rglob("*")
            if not path.name.startswith("Dockerfile.")
        ),
        *SCRIPTS.glob("*.sh"),
    ]
    text = "\n".join(
        path.read_text(encoding="utf-8") for path in files if path.is_file()
    )
    for pattern in (r"chmod\s+777", r"chmod\s+[ugo+]*s", r"\bcurl\b", r"\bwget\b"):
        if re.search(pattern, text):
            raise AssertionError(f"forbidden packaging pattern: {pattern}")
    if "tcpreplay " in text or ("dumpcap" + " -i") in text:
        raise AssertionError("packaging must not run capture or replay")
    postrm = (PACKAGING / "debian" / "postrm").read_text(encoding="utf-8")
    if (
        "remove|purge|disappear)" not in postrm
        or 'if [ "$ACTION" = purge ]' not in postrm
    ):
        raise AssertionError("state deletion must require explicit package purge")
    if (
        "upgrade|failed-upgrade|abort-install|abort-upgrade|abort-remove|abort-deconfigure)"
        not in postrm
    ):
        raise AssertionError(
            "upgrade and abort actions must preserve the private runtime"
        )
    lifecycle = (PACKAGING / "bin" / "wto-agent-package-lifecycle").read_text(
        encoding="utf-8"
    )
    for required in (
        "/run/wto-agent-package-maintainer",
        "--property=ActiveState --value",
        "active|inactive|failed",
        "sync -f",
    ):
        if required not in lifecycle:
            raise AssertionError(f"package lifecycle helper misses {required}")
    installer = (SCRIPTS / "install-agent.sh").read_text(encoding="utf-8")
    for required in ("--force-confdef", "--force-confold", "STAGED_PACKAGE"):
        if required not in installer:
            raise AssertionError(f"package installer misses {required}")
    capture_config = (PACKAGING / "config" / "capture-node.toml").read_text(
        encoding="utf-8"
    )
    for disabled in ("capture_enabled = false", "tcpreplay_enabled = false"):
        if disabled not in capture_config:
            raise AssertionError("specialized capabilities must ship disabled")


def validate_control() -> None:
    control = (PACKAGING / "debian" / "control.in").read_text(encoding="utf-8")
    if "python3 (>= 3.12)" not in control:
        raise AssertionError("DEB must require the supported Python baseline")
    if "Architecture: @ARCH@" not in control:
        raise AssertionError("wheelhouse DEB must use the build architecture")
    if "python3-pydantic" in control:
        raise AssertionError("DEB must not use the distribution Pydantic runtime")
    if "python3-venv" not in control:
        raise AssertionError("DEB must provision a private virtual environment")


def validate_conffiles(path: Path | None = None) -> None:
    source = path or PACKAGING / "debian" / "conffiles"
    raw = source.read_bytes()
    if b"\x00" in raw:
        raise AssertionError("DEB conffiles must not contain NUL")
    if b"\r" in raw:
        raise AssertionError("DEB conffiles must use exact LF line endings")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise AssertionError("DEB conffiles must be UTF-8") from error
    lines = text.splitlines()
    if not lines or any(not line for line in lines):
        raise AssertionError("DEB conffiles must contain only non-empty paths")
    for value in lines:
        if value != value.strip():
            raise AssertionError(
                "DEB conffiles paths must not contain peripheral whitespace"
            )
        if not value.startswith("/") or value.startswith("//"):
            raise AssertionError("DEB conffiles paths must be absolute POSIX paths")
        if "\\" in value or "//" in value or value.endswith("/"):
            raise AssertionError("DEB conffiles paths must use exact POSIX spelling")
        components = value.split("/")[1:]
        if any(component in {"", ".", ".."} for component in components):
            raise AssertionError("DEB conffiles paths contain an unsafe component")
        if PurePosixPath(value).as_posix() != value:
            raise AssertionError("DEB conffiles paths must be lexically canonical")
    if len(lines) != len(set(lines)):
        raise AssertionError("DEB conffiles must not contain duplicate paths")
    if frozenset(lines) != EXPECTED_CONFFILES:
        raise AssertionError(
            "DEB conffiles does not contain the exact expected path set"
        )


def main() -> None:
    validate_units()
    validate_scripts()
    validate_control()
    validate_conffiles()
    print("Linux systemd and DEB static validation passed.")


if __name__ == "__main__":
    main()
