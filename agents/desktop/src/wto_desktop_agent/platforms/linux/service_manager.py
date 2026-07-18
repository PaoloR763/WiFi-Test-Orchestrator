from __future__ import annotations

import asyncio
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from wto_desktop_agent.domain.models import DoctorCheck
from wto_desktop_agent.platforms.linux.journal_state import inspect_capture_journals
from wto_desktop_agent.platforms.linux.tooling import (
    TrustedExecutableStatus,
    inspect_systemctl,
)

_SYSTEMD_RUNTIME = Path("/run/systemd/system")


class SystemdUnavailableError(RuntimeError):
    pass


def _run_systemctl(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - trusted fixed executable and separated local argv
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


class LinuxServiceManager:
    def __init__(
        self,
        role: str,
        state_dir: Path,
        *,
        status_ttl_seconds: float = 5.0,
        monotonic: Callable[[], float] = time.monotonic,
        systemctl_inspector: Callable[[], TrustedExecutableStatus] = inspect_systemctl,
        runner: Callable[[list[str]], subprocess.CompletedProcess[str]] = _run_systemctl,
    ) -> None:
        if status_ttl_seconds <= 0:
            raise ValueError("systemd status TTL must be positive")
        self.unit = (
            "wto-agent-capture.service"
            if role in {"capture_node", "lab_node"}
            else "wto-agent.service"
        )
        self.state_dir = state_dir
        self._systemctl_inspector = systemctl_inspector
        self._runner = runner
        systemctl = self._systemctl_inspector()
        self._systemctl = systemctl.path
        self._systemctl_reason = systemctl.reason
        self._status_ttl_seconds = status_ttl_seconds
        self._monotonic = monotonic
        self._status_lock = threading.Lock()
        self._cached_status: tuple[float, str] | None = None

    def install(self, executable: Path, config_path: Path) -> None:
        del executable, config_path
        raise RuntimeError("Linux service installation is owned by the signed DEB workflow")

    def uninstall(self) -> None:
        raise RuntimeError("Linux service removal is owned by the DEB workflow")

    def purge_identity(self, *, confirmed: bool, timeout_seconds: float = 30.0) -> None:
        del timeout_seconds
        if not confirmed:
            raise PermissionError("explicit identity purge confirmation is required")
        raise RuntimeError("use the package purge workflow while the service is stopped")

    def _run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        systemctl = self._systemctl_inspector()
        self._systemctl = systemctl.path
        self._systemctl_reason = systemctl.reason
        if self._systemctl is None or not _SYSTEMD_RUNTIME.is_dir():
            reason = self._systemctl_reason or "systemd_runtime_unavailable"
            raise SystemdUnavailableError(f"systemd provider unavailable: {reason}")
        return self._runner([str(self._systemctl), *arguments])

    @property
    def provider_available(self) -> bool:
        systemctl = self._systemctl_inspector()
        self._systemctl = systemctl.path
        self._systemctl_reason = systemctl.reason
        return self._systemctl is not None and _SYSTEMD_RUNTIME.is_dir()

    def control(self, action: Literal["start", "stop", "pause", "resume"]) -> None:
        if action in {"pause", "resume"}:
            raise RuntimeError("systemd adapter does not map pause/resume to signals")
        try:
            result = self._run(action, self.unit)
            if result.returncode != 0:
                raise RuntimeError(f"systemd {action} failed")
        finally:
            self.invalidate_status()

    def _query_status(self) -> str:
        if not _SYSTEMD_RUNTIME.is_dir():
            return "unavailable"
        try:
            status = self._run(
                "show",
                self.unit,
                "--property=LoadState",
                "--property=ActiveState",
                "--no-pager",
            )
        except SystemdUnavailableError:
            return "unavailable"
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            return "unknown"
        if status.returncode != 0:
            return "unknown"
        values = {}
        for line in status.stdout.splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"LoadState", "ActiveState"}:
                values[key] = value.strip()
        if values.get("LoadState") == "not-found":
            return "not_installed"
        if values.get("LoadState") != "loaded":
            return "unknown"
        value = values.get("ActiveState", "unknown")
        return (
            value
            if value in {"active", "inactive", "failed", "activating", "deactivating"}
            else "unknown"
        )

    def status(self) -> str:
        now = self._monotonic()
        cached = self._cached_status
        if cached is not None and cached[0] > now:
            return cached[1]
        with self._status_lock:
            now = self._monotonic()
            cached = self._cached_status
            if cached is not None and cached[0] > now:
                return cached[1]
            value = self._query_status()
            self._cached_status = (now + self._status_ttl_seconds, value)
            return value

    async def status_async(self) -> str:
        now = self._monotonic()
        cached = self._cached_status
        if cached is not None and cached[0] > now:
            return cached[1]
        return await asyncio.to_thread(self.status)

    def invalidate_status(self) -> None:
        with self._status_lock:
            self._cached_status = None

    def doctor(self) -> DoctorCheck:
        journals = inspect_capture_journals(self.state_dir)
        if journals.status in {"BLOCKED", "DEGRADED"}:
            return DoctorCheck(
                name="capture_interface_recovery",
                status=journals.status,
                detail=journals.detail,
            )
        state = self.status()
        if state == "active":
            return DoctorCheck(
                name="service_manager",
                status="OK",
                detail=f"systemd unit {self.unit} is active",
            )
        return DoctorCheck(
            name="service_manager",
            status="DEGRADED",
            detail=f"systemd unit {self.unit} state: {state}",
        )
