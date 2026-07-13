from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from wto_desktop_agent.ports.platform import CommandRequest, ProcessRunner
from wto_desktop_agent.ports.plugins import CancellationToken

NPCAP_PARAMETERS = r"SYSTEM\CurrentControlSet\Services\npcap\Parameters"
NPCAP_SERVICE = "npcap"
_NPF_GUID = re.compile(r"\\Device\\NPF_\{(?P<guid>[0-9A-Fa-f-]{36})\}", re.IGNORECASE)


@dataclass(frozen=True)
class CaptureDevice:
    name: str
    guid: str | None
    loopback: bool


@dataclass(frozen=True)
class NpcapStatus:
    installed: bool
    service_status: str
    admin_only: bool | None
    dot11_support: bool | None
    version: str | None
    dumpcap_path: Path | None
    dumpcap_version: str | None


def parse_dumpcap_devices(raw: bytes) -> list[CaptureDevice]:
    if len(raw) > 1_048_576:
        raise ValueError("dumpcap enumeration exceeds limit")
    text = raw.decode("utf-8", errors="strict")
    result: list[CaptureDevice] = []
    for line in text.splitlines():
        if "NPF_Loopback" in line:
            result.append(CaptureDevice(name="NPF_Loopback", guid=None, loopback=True))
            continue
        match = _NPF_GUID.search(line)
        if match:
            result.append(
                CaptureDevice(name=match.group(0), guid=match.group("guid").lower(), loopback=False)
            )
    return result


def map_capture_devices(
    devices: list[CaptureDevice], interface_guids: set[str]
) -> dict[str, CaptureDevice | None]:
    normalized = {guid.strip("{}").lower() for guid in interface_guids}
    result: dict[str, CaptureDevice | None] = {}
    for guid in normalized:
        matches = [device for device in devices if device.guid == guid]
        result[guid] = matches[0] if len(matches) == 1 else None
    return result


class NpcapDetector:
    def __init__(self) -> None:
        self.status = self._detect()

    def _detect(self) -> NpcapStatus:
        import winreg

        admin_only: bool | None = None
        dot11_support: bool | None = None
        installed = False
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NPCAP_PARAMETERS) as key:
                installed = True
                admin_only = bool(winreg.QueryValueEx(key, "AdminOnly")[0])
                dot11_support = bool(winreg.QueryValueEx(key, "Dot11Support")[0])
        except FileNotFoundError:
            pass
        service_status = self._service_status()
        dumpcap = self._dumpcap_path()
        return NpcapStatus(
            installed=installed,
            service_status=service_status,
            admin_only=admin_only,
            dot11_support=dot11_support,
            version=self._file_version(self._npcap_version_file()),
            dumpcap_path=dumpcap,
            dumpcap_version=self._file_version(dumpcap),
        )

    def _service_status(self) -> str:
        import pywintypes
        import win32service

        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        service = None
        try:
            try:
                service = win32service.OpenService(
                    scm, NPCAP_SERVICE, win32service.SERVICE_QUERY_STATUS
                )
            except pywintypes.error as error:
                return "not_installed" if error.winerror == 1060 else "unknown"
            state = int(win32service.QueryServiceStatus(service)[1])
            return "running" if state == win32service.SERVICE_RUNNING else "stopped"
        finally:
            if service is not None:
                win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(scm)

    @staticmethod
    def _npcap_version_file() -> Path | None:
        import os

        program_files = os.environ.get("ProgramFiles")
        if not program_files:
            return None
        candidate = Path(program_files) / "Npcap" / "NPFInstall.exe"
        return candidate.resolve() if candidate.is_file() else None

    @staticmethod
    def _dumpcap_path() -> Path | None:
        import os

        program_files = os.environ.get("ProgramFiles")
        if not program_files:
            return None
        candidate = Path(program_files) / "Wireshark" / "dumpcap.exe"
        return candidate.resolve() if candidate.is_file() else None

    @staticmethod
    def _file_version(path: Path | None) -> str | None:
        import win32api

        if path is None:
            return None
        try:
            info = win32api.GetFileVersionInfo(str(path), "\\")
            ms, ls = int(info["FileVersionMS"]), int(info["FileVersionLS"])
            return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
        except Exception:
            return None

    async def enumerate_devices(self, runner: ProcessRunner) -> list[CaptureDevice]:
        if self.status.dumpcap_path is None:
            return []
        result = await runner.run(
            CommandRequest(
                command_id="windows.dumpcap.enumerate",
                arguments={},
                timeout_seconds=10.0,
            ),
            CancellationToken(),
        )
        if result.return_code != 0:
            raise PermissionError("dumpcap interface enumeration failed")
        return parse_dumpcap_devices(result.stdout)

    def capability_overrides(self) -> dict[str, dict[str, object]]:
        detected = (
            self.status.installed
            and self.status.service_status == "running"
            and self.status.dumpcap_path is not None
        )
        permission = "required" if self.status.admin_only else "conditional"
        return {
            "capture.ip": {
                "technical_support": {
                    "status": "conditional" if detected else "unknown",
                    "reason": None if detected else {"code": "provider_unavailable"},
                },
                "implementation_status": {
                    "status": "planned",
                    "reason": {"code": "not_implemented"},
                },
                "permission_requirement": {
                    "status": permission,
                    "permissions": ["npcap.capture"],
                    "reason": (
                        {"code": "permission_missing", "detail": "Npcap AdminOnly is enabled"}
                        if self.status.admin_only
                        else None
                    ),
                },
                "user_interaction": {
                    "status": "required",
                    "reason": {"code": "user_interaction_required"},
                },
                "background_execution": {"status": "bounded", "reason": None},
                "provider": {
                    "status": "available" if detected else "unavailable",
                    "implementations": (
                        [
                            {
                                "provider_id": "wireshark-dumpcap",
                                "provider_version": _semver(self.status.dumpcap_version),
                                "method": "detection-only",
                            }
                        ]
                        if detected
                        else []
                    ),
                    "reason": None if detected else {"code": "provider_unavailable"},
                },
                "limitations": {
                    "status": "unknown",
                    "reason": {"code": "not_implemented"},
                },
            },
            "capture.ieee80211.monitor": {
                "technical_support": {"status": "unknown", "reason": {"code": "unknown"}},
                "implementation_status": {
                    "status": "excluded",
                    "reason": {"code": "policy_denied"},
                },
                "permission_requirement": {
                    "status": "restricted",
                    "permissions": [],
                    "reason": {"code": "policy_denied"},
                },
                "user_interaction": {
                    "status": "not_applicable",
                    "reason": {"code": "not_applicable"},
                },
                "background_execution": {
                    "status": "not_applicable",
                    "reason": {"code": "not_applicable"},
                },
                "provider": {
                    "status": "not_applicable",
                    "implementations": [],
                    "reason": {"code": "not_applicable"},
                },
                "limitations": {
                    "status": "not_applicable",
                    "reason": {"code": "not_applicable"},
                },
            },
        }


def _semver(value: str | None) -> str:
    if value is None:
        return "0.0.0"
    parts = value.split(".")[:3]
    while len(parts) < 3:
        parts.append("0")
    return ".".join(str(int(part)) for part in parts)
