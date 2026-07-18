from __future__ import annotations

import os
import re
import selectors
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wto_desktop_agent.platforms.common import ExecutableIdentity
from wto_desktop_agent.platforms.linux.parsers import (
    parse_iw_dev,
    parse_iw_phy_monitor_support,
)

_ROOT_UID = 0
TRUSTED_EXECUTABLE_ROOTS = (
    Path("/usr/local/sbin"),
    Path("/usr/local/bin"),
    Path("/usr/sbin"),
    Path("/usr/bin"),
    Path("/sbin"),
    Path("/bin"),
)
TRUSTED_TOOL_NAMES = frozenset(
    {
        "dumpcap",
        "ethtool",
        "flent",
        "getcap",
        "ip",
        "iw",
        "netperf",
        "nmcli",
        "tcpreplay",
    }
)
TRUSTED_TOOL_CANDIDATES = {
    name: tuple(root / name for root in TRUSTED_EXECUTABLE_ROOTS) for name in TRUSTED_TOOL_NAMES
}
SYSTEMCTL_CANDIDATES = (Path("/usr/bin/systemctl"), Path("/bin/systemctl"))
SYSTEMCTL_ALLOWED_ROOTS = (Path("/usr/bin"), Path("/bin"))
_PROBE_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}
_PROBE_OUTPUT_LIMIT = 1_048_576


@dataclass(frozen=True)
class ToolStatus:
    name: str
    path: Path | None
    installed: bool
    self_check: bool
    access: str
    secure: bool
    version: str | None = None
    reason: str | None = None
    file_capabilities: frozenset[str] = frozenset()
    identity: ExecutableIdentity | None = None

    @property
    def ready(self) -> bool:
        return self.installed and self.self_check and self.access == "allowed" and self.secure


TrustedExecutableFailure = Literal[
    "command_missing",
    "insecure_executable",
    "permission_denied",
]
TrustedExecutableState = Literal["available", "missing", "insecure", "permission_denied"]


@dataclass(frozen=True)
class TrustedExecutableStatus:
    """Result of validating a fixed system executable without executing it."""

    name: str
    path: Path | None
    reason: TrustedExecutableFailure | None
    identity: ExecutableIdentity | None = None
    state: TrustedExecutableState | None = None

    def __post_init__(self) -> None:
        if self.state is not None:
            return
        if self.path is not None and self.reason is None:
            state: TrustedExecutableState = "available"
        elif self.reason == "permission_denied":
            state = "permission_denied"
        elif self.reason == "insecure_executable":
            state = "insecure"
        else:
            state = "missing"
        object.__setattr__(self, "state", state)

    @property
    def ready(self) -> bool:
        return self.path is not None and self.reason is None


def _lstat(path: Path) -> os.stat_result:
    return path.lstat()


def _trusted_component(metadata: os.stat_result, *, symlink: bool = False) -> bool:
    if metadata.st_uid != _ROOT_UID:
        return False
    if symlink:
        # POSIX symlink mode bits are not access-control bits and are commonly 0777.
        return True
    return not bool(stat.S_IMODE(metadata.st_mode) & 0o022)


def _path_parts(path: Path) -> list[str]:
    if not path.is_absolute() or path.anchor != "/":
        raise ValueError("trusted executable paths must be absolute POSIX paths")
    return [part for part in path.parts if part != "/"]


def _walk_trusted_path(path: Path) -> Path:
    """Resolve a path while validating every directory and symlink traversed."""

    pending = _path_parts(path)
    resolved = Path("/")
    followed_links = 0
    root_metadata = _lstat(resolved)
    if not stat.S_ISDIR(root_metadata.st_mode) or not _trusted_component(root_metadata):
        raise PermissionError("filesystem root is not trusted")

    while pending:
        component = pending.pop(0)
        if component in {"", ".", ".."}:
            raise PermissionError("trusted executable path contains an unsafe component")
        candidate = resolved / component
        metadata = _lstat(candidate)
        if stat.S_ISLNK(metadata.st_mode):
            if not _trusted_component(metadata, symlink=True):
                raise PermissionError("trusted executable symlink is not root-owned")
            followed_links += 1
            if followed_links > 40:
                raise OSError("too many symbolic links")
            target = Path(os.readlink(candidate))
            if target.is_absolute():
                resolved = Path("/")
                pending = [*_path_parts(target), *pending]
            else:
                target_parts = list(target.parts)
                if any(part in {"", ".", ".."} for part in target_parts):
                    raise PermissionError("trusted executable symlink target is unsafe")
                pending = [*target_parts, *pending]
            continue
        if pending:
            if not stat.S_ISDIR(metadata.st_mode) or not _trusted_component(metadata):
                raise PermissionError("trusted executable ancestor is unsafe")
        resolved = candidate
    return resolved


def inspect_trusted_system_executable(
    name: str,
    *,
    candidates: tuple[Path, ...],
    allowed_roots: tuple[Path, ...],
) -> TrustedExecutableStatus:
    """Select a root-owned executable from a closed path allowlist.

    This helper deliberately does not inspect PATH or any configuration source.
    Candidate and root arguments are supplied only by local code constants; the
    parameterized form keeps the filesystem state machine unit-testable.
    """

    canonical_roots: set[Path] = set()
    for root in allowed_roots:
        try:
            canonical_root = _walk_trusted_path(root)
            metadata = _lstat(canonical_root)
        except (OSError, PermissionError, ValueError):
            continue
        if stat.S_ISDIR(metadata.st_mode) and _trusted_component(metadata):
            canonical_roots.add(canonical_root)

    saw_candidate = False
    saw_denied = False
    for candidate in candidates:
        if not candidate.is_absolute() or not any(
            candidate == root or candidate.is_relative_to(root) for root in allowed_roots
        ):
            continue
        try:
            lexical_metadata = _lstat(candidate)
            saw_candidate = True
            canonical = _walk_trusted_path(candidate)
            metadata = _lstat(canonical)
        except FileNotFoundError:
            continue
        except PermissionError:
            saw_candidate = True
            continue
        except OSError:
            saw_candidate = True
            continue
        if not any(canonical.is_relative_to(root) for root in canonical_roots):
            continue
        if not stat.S_ISREG(metadata.st_mode) or not _trusted_component(metadata):
            continue
        if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
            continue
        if not bool(stat.S_IMODE(metadata.st_mode) & 0o111) or not os.access(canonical, os.X_OK):
            saw_denied = True
            continue
        # Ensure a non-symlink lexical candidate did not change identity while
        # the component walk was performed. Root-owned immutable ancestors make
        # a symlink race unavailable to an unprivileged caller.
        if not stat.S_ISLNK(lexical_metadata.st_mode) and (
            lexical_metadata.st_dev != metadata.st_dev or lexical_metadata.st_ino != metadata.st_ino
        ):
            continue
        return TrustedExecutableStatus(
            name=name,
            path=canonical,
            reason=None,
            identity=ExecutableIdentity.from_stat(metadata),
            state="available",
        )

    reason: TrustedExecutableFailure
    if saw_denied:
        reason = "permission_denied"
    elif saw_candidate:
        reason = "insecure_executable"
    else:
        reason = "command_missing"
    state: TrustedExecutableState = (
        "permission_denied"
        if reason == "permission_denied"
        else "insecure" if reason == "insecure_executable" else "missing"
    )
    return TrustedExecutableStatus(name=name, path=None, reason=reason, state=state)


def inspect_systemctl() -> TrustedExecutableStatus:
    return inspect_trusted_system_executable(
        "systemctl",
        candidates=SYSTEMCTL_CANDIDATES,
        allowed_roots=SYSTEMCTL_ALLOWED_ROOTS,
    )


def revalidate_trusted_executable(status: TrustedExecutableStatus | ToolStatus) -> Path:
    """Revalidate a previously inspected executable without resolving through PATH."""

    path = status.path
    identity = status.identity
    if path is None or identity is None:
        raise PermissionError("trusted executable identity is unavailable")
    try:
        canonical = _walk_trusted_path(path)
        metadata = _lstat(canonical)
    except (OSError, PermissionError, ValueError) as error:
        raise PermissionError("trusted executable path is no longer valid") from error
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        canonical != path
        or not stat.S_ISREG(metadata.st_mode)
        or not _trusted_component(metadata)
        or bool(metadata.st_mode & (stat.S_ISUID | stat.S_ISGID))
        or not bool(mode & 0o111)
        or not os.access(canonical, os.X_OK)
        or ExecutableIdentity.from_stat(metadata) != identity
    ):
        raise PermissionError("trusted executable identity or permissions changed")
    return canonical


def inspect_tool(name: str) -> ToolStatus:
    """Inspect installation, trust and execute access without running the tool."""

    try:
        candidates = TRUSTED_TOOL_CANDIDATES[name]
    except KeyError as error:
        raise ValueError("tool is not present in the closed Linux executable catalog") from error
    inspected = inspect_trusted_system_executable(
        name,
        candidates=candidates,
        allowed_roots=TRUSTED_EXECUTABLE_ROOTS,
    )
    installed = inspected.reason != "command_missing"
    access = "allowed" if inspected.ready else ("denied" if installed else "missing")
    return ToolStatus(
        name=name,
        path=inspected.path,
        installed=installed,
        self_check=False,
        access=access,
        secure=inspected.ready,
        reason="installed" if inspected.ready else inspected.reason,
        identity=inspected.identity,
    )


@dataclass(frozen=True)
class _ProbeResult:
    ok: bool
    output: str
    reason: str | None = None
    raw_output: bytes = b""


def _stop_probe(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _fixed_probe(
    executable: TrustedExecutableStatus | ToolStatus,
    arguments: list[str],
    *,
    timeout: float = 3.0,
    max_output_bytes: int = _PROBE_OUTPUT_LIMIT,
) -> _ProbeResult:
    """Execute a trusted fixed probe with bounded time, output and environment."""

    if timeout <= 0 or max_output_bytes <= 0:
        raise ValueError("probe limits must be positive")
    try:
        path = revalidate_trusted_executable(executable)
    except PermissionError:
        return _ProbeResult(False, "", "insecure_executable")
    try:
        process = subprocess.Popen(  # noqa: S603 - closed catalog and revalidated absolute path
            [str(path), *arguments],
            cwd="/",
            env=dict(_PROBE_ENVIRONMENT),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
            close_fds=True,
        )
    except OSError:
        return _ProbeResult(False, "", "technical_self_check_failed")
    stream = process.stdout
    if stream is None:
        _stop_probe(process)
        return _ProbeResult(False, "", "technical_self_check_failed")
    selector = selectors.DefaultSelector()
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop_probe(process)
                return _ProbeResult(False, "", "technical_self_check_timeout")
            events = selector.select(remaining)
            if not events:
                _stop_probe(process)
                return _ProbeResult(False, "", "technical_self_check_timeout")
            for key, _ in events:
                chunk = os.read(key.fd, 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(chunk) > max_output_bytes:
                    _stop_probe(process)
                    return _ProbeResult(False, "", "technical_self_check_output_limit")
                output.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _stop_probe(process)
            return _ProbeResult(False, "", "technical_self_check_timeout")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _stop_probe(process)
            return _ProbeResult(False, "", "technical_self_check_timeout")
    except (OSError, ValueError):
        _stop_probe(process)
        return _ProbeResult(False, "", "technical_self_check_failed")
    finally:
        selector.close()
        stream.close()
    decoded = bytes(output).decode("utf-8", errors="replace")
    return _ProbeResult(
        return_code == 0,
        decoded,
        None if return_code == 0 else "technical_self_check_failed",
        bytes(output),
    )


def probe_tool(
    name: str,
    version_arguments: list[str],
    *,
    inspected: ToolStatus | None = None,
) -> ToolStatus:
    inspected = inspect_tool(name) if inspected is None else inspected
    if inspected.name != name:
        raise ValueError("inspected tool does not match the requested catalog entry")
    path = inspected.path
    if path is None or inspected.access != "allowed" or not inspected.secure:
        return inspected
    probe = _fixed_probe(inspected, version_arguments)
    version = probe.output.splitlines()[0][:64] if probe.output else None
    return ToolStatus(
        name=name,
        path=path,
        installed=True,
        self_check=probe.ok,
        access=inspected.access,
        secure=inspected.secure,
        version=version,
        reason=None if probe.ok else probe.reason,
        identity=inspected.identity,
    )


def probe_dumpcap(
    *,
    dumpcap: ToolStatus | None = None,
    getcap: ToolStatus | None = None,
) -> ToolStatus:
    status = probe_tool("dumpcap", ["--version"], inspected=dumpcap)
    if not status.installed or status.path is None or not status.self_check or not status.secure:
        return status
    capabilities: frozenset[str] = frozenset()
    getcap = inspect_tool("getcap") if getcap is None else getcap
    if getcap.path is None or getcap.access != "allowed" or not getcap.secure:
        return ToolStatus(
            name=status.name,
            path=status.path,
            installed=True,
            self_check=False,
            access="denied",
            secure=False,
            version=status.version,
            reason="capability_inspector_unavailable",
            identity=status.identity,
        )
    capability_probe = _fixed_probe(getcap, [str(status.path)])
    if not capability_probe.ok:
        return ToolStatus(
            name=status.name,
            path=status.path,
            installed=True,
            self_check=False,
            access="denied",
            secure=False,
            version=status.version,
            reason=capability_probe.reason or "capability_inspector_failed",
            identity=status.identity,
        )
    try:
        capabilities = parse_file_capabilities(capability_probe.output)
    except ValueError:
        return ToolStatus(
            name=status.name,
            path=status.path,
            installed=True,
            self_check=False,
            access="denied",
            secure=False,
            version=status.version,
            reason="insecure_capability_configuration",
            identity=status.identity,
        )
    allowed_capabilities = {"cap_net_admin", "cap_net_raw"}
    if not capabilities.issubset(allowed_capabilities):
        return ToolStatus(
            status.name,
            status.path,
            True,
            False,
            "denied",
            False,
            version=status.version,
            reason="insecure_capability_configuration",
            file_capabilities=capabilities,
            identity=status.identity,
        )
    access_probe = _fixed_probe(status, ["-D", "-M"])
    allowed = access_probe.ok
    access = "allowed" if allowed else "denied"
    reason = (
        "capabilities_absent_but_access_allowed"
        if allowed and not capabilities
        else (
            None if allowed else "capabilities_absent" if not capabilities else "permission_denied"
        )
    )
    return ToolStatus(
        status.name,
        status.path,
        True,
        allowed,
        access,
        status.secure,
        version=status.version,
        reason=reason if allowed else reason or access_probe.reason,
        file_capabilities=capabilities,
        identity=status.identity,
    )


def parse_file_capabilities(output: str) -> frozenset[str]:
    """Parse getcap output and reject unknown or malformed capability text."""

    if not output.strip():
        return frozenset()
    capabilities = frozenset(re.findall(r"\bcap_[a-z0-9_]+\b", output.casefold()))
    if not capabilities or "=" not in output:
        raise ValueError("malformed getcap output")
    return capabilities


def effective_capabilities() -> frozenset[str]:
    try:
        lines = Path("/proc/self/status").read_text(encoding="ascii").splitlines()
        value = next(line.split()[1] for line in lines if line.startswith("CapEff:"))
        mask = int(value, 16)
    except (OSError, StopIteration, ValueError):
        return frozenset()
    result = set()
    if mask & (1 << 12):
        result.add("cap_net_admin")
    if mask & (1 << 13):
        result.add("cap_net_raw")
    return frozenset(result)


def monitor_capable_interfaces(
    allowed_interfaces: frozenset[str],
    *,
    iw: ToolStatus | None = None,
) -> frozenset[str]:
    iw = inspect_tool("iw") if iw is None else iw
    if not allowed_interfaces or iw.path is None or iw.access != "allowed" or not iw.secure:
        return frozenset()
    if not _fixed_probe(iw, ["--version"]).ok:
        return frozenset()
    try:
        devices = _fixed_probe(iw, ["dev"], max_output_bytes=4_194_304)
        if not devices.ok:
            return frozenset()
        inventory = parse_iw_dev(devices.raw_output)
    except (OSError, ValueError):
        return frozenset()
    capable: set[str] = set()
    for item in inventory:
        name = str(item["name"])
        phy = item.get("wiphy")
        if name not in allowed_interfaces or not isinstance(phy, str):
            continue
        try:
            result = _fixed_probe(
                iw,
                ["phy", phy, "info"],
                max_output_bytes=4_194_304,
            )
            if result.ok and parse_iw_phy_monitor_support(result.raw_output):
                capable.add(name)
        except (OSError, ValueError):
            continue
    return frozenset(capable)
