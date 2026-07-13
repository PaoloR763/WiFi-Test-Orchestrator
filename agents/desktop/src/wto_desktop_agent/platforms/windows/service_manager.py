from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Literal

from wto_desktop_agent.domain.models import DoctorCheck
from wto_desktop_agent.platforms.windows.acl import (
    SERVICE_ACCOUNT,
    SERVICE_NAME,
    apply_directory_acl,
    lookup_service_sid,
)

PURGE_CONTROL_CODE = 128


def service_image_path(executable: Path, config_path: Path) -> str:
    executable = executable.resolve(strict=True)
    config_path = config_path.resolve(strict=True)
    if not executable.is_absolute() or not config_path.is_absolute():
        raise ValueError("service executable and configuration must be absolute")
    if '"' in str(executable) or '"' in str(config_path):
        raise ValueError("service paths cannot contain quote characters")
    return f'"{executable}" --config "{config_path}" service run'


class WindowsServiceManager:
    def __init__(
        self,
        state_dir: Path,
        *,
        program_files_root: Path | None = None,
        program_data_root: Path | None = None,
    ) -> None:
        if program_files_root is None:
            program_files_value = os.environ.get("ProgramFiles")
            if not program_files_value:
                raise RuntimeError("canonical Program Files root is unavailable")
            program_files_root = Path(program_files_value)
        if program_data_root is None:
            program_data_value = os.environ.get("ProgramData")
            if not program_data_value:
                raise RuntimeError("canonical ProgramData root is unavailable")
            program_data_root = Path(program_data_value)
        self.state_dir = state_dir.resolve()
        self.program_files_root = program_files_root.resolve()
        self.program_data_root = program_data_root.resolve()

    @staticmethod
    def _require_descendant(path: Path, root: Path, label: str) -> None:
        if not path.is_relative_to(root) or path == root:
            raise ValueError(f"service {label} must be below the canonical {root.name} root")

    def install(self, executable: Path, config_path: Path) -> None:
        import pywintypes
        import win32service

        executable = executable.resolve(strict=True)
        config_path = config_path.resolve(strict=True)
        self._require_descendant(executable, self.program_files_root, "executable")
        self._require_descendant(config_path, self.program_data_root, "configuration")
        data_root = config_path.parent.parent
        if self.state_dir != (data_root / "state").resolve():
            raise ValueError("configured state_dir must be the service ProgramData state directory")
        image_path = service_image_path(executable, config_path)
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CREATE_SERVICE)
        service = None
        try:
            try:
                service = win32service.CreateService(
                    scm,
                    SERVICE_NAME,
                    "WiFi Test Orchestrator Agent",
                    win32service.SERVICE_ALL_ACCESS,
                    win32service.SERVICE_WIN32_OWN_PROCESS,
                    win32service.SERVICE_AUTO_START,
                    win32service.SERVICE_ERROR_NORMAL,
                    image_path,
                    None,
                    0,
                    None,
                    SERVICE_ACCOUNT,
                    None,
                )
            except pywintypes.error as error:
                if error.winerror != 1073:
                    raise
                service = win32service.OpenService(
                    scm, SERVICE_NAME, win32service.SERVICE_ALL_ACCESS
                )
                existing = win32service.QueryServiceConfig(service)
                if str(existing[3]) != image_path:
                    win32service.ChangeServiceConfig(
                        service,
                        win32service.SERVICE_NO_CHANGE,
                        win32service.SERVICE_NO_CHANGE,
                        win32service.SERVICE_NO_CHANGE,
                        image_path,
                        None,
                        0,
                        None,
                        None,
                        None,
                        None,
                    )
            assert service is not None
            win32service.ChangeServiceConfig(
                service,
                win32service.SERVICE_NO_CHANGE,
                win32service.SERVICE_AUTO_START,
                win32service.SERVICE_ERROR_NORMAL,
                image_path,
                None,
                0,
                None,
                SERVICE_ACCOUNT,
                None,
                None,
            )
            win32service.ChangeServiceConfig2(
                service, win32service.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, True
            )
            win32service.ChangeServiceConfig2(
                service,
                win32service.SERVICE_CONFIG_FAILURE_ACTIONS,
                {
                    "ResetPeriod": 86_400,
                    "RebootMsg": "",
                    "Command": "",
                    "Actions": [
                        (win32service.SC_ACTION_RESTART, 30_000),
                        (win32service.SC_ACTION_RESTART, 60_000),
                        (win32service.SC_ACTION_NONE, 0),
                    ],
                },
            )
            service_sid_type = getattr(win32service, "SERVICE_CONFIG_SERVICE_SID_INFO", 5)
            unrestricted = getattr(win32service, "SERVICE_SID_TYPE_UNRESTRICTED", 1)
            win32service.ChangeServiceConfig2(service, service_sid_type, unrestricted)
            configured = win32service.QueryServiceConfig(service)
            if str(configured[3]) != image_path:
                raise RuntimeError("service ImagePath validation failed")
            if str(configured[7]).casefold() != SERVICE_ACCOUNT.casefold():
                raise RuntimeError("service account validation failed")
            service_sid = lookup_service_sid()
            apply_directory_acl(executable.parent, service_sid, writable=False)
            apply_directory_acl(config_path.parent, service_sid, writable=False)
            for name in ("state", "logs", "artifacts"):
                apply_directory_acl(data_root / name, service_sid, writable=True)
        finally:
            if service is not None:
                win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(scm)

    def uninstall(self) -> None:
        import pywintypes
        import win32service

        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        service = None
        try:
            try:
                service = win32service.OpenService(
                    scm, SERVICE_NAME, win32service.DELETE | win32service.SERVICE_STOP
                )
            except pywintypes.error as error:
                if error.winerror == 1060:
                    return
                raise
            try:
                win32service.ControlService(service, win32service.SERVICE_CONTROL_STOP)
            except pywintypes.error as error:
                if error.winerror not in {1062, 1061}:
                    raise
            win32service.DeleteService(service)
        finally:
            if service is not None:
                win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(scm)

    def control(self, action: Literal["start", "stop", "pause", "resume"]) -> None:
        import win32service

        access = win32service.SERVICE_QUERY_STATUS
        if action == "start":
            access |= win32service.SERVICE_START
        elif action == "stop":
            access |= win32service.SERVICE_STOP
        else:
            access |= win32service.SERVICE_PAUSE_CONTINUE
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        service = None
        try:
            service = win32service.OpenService(scm, SERVICE_NAME, access)
            if action == "start":
                win32service.StartService(service, None)
            else:
                code = {
                    "stop": win32service.SERVICE_CONTROL_STOP,
                    "pause": win32service.SERVICE_CONTROL_PAUSE,
                    "resume": win32service.SERVICE_CONTROL_CONTINUE,
                }[action]
                win32service.ControlService(service, code)
        finally:
            if service is not None:
                win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(scm)

    def purge_identity(self, *, confirmed: bool, timeout_seconds: float = 30.0) -> None:
        import win32service

        if not confirmed:
            raise PermissionError("explicit identity purge confirmation is required")
        status_path = self.state_dir / "purge-status.json"
        status_path.unlink(missing_ok=True)
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        service = None
        try:
            service = win32service.OpenService(
                scm,
                SERVICE_NAME,
                win32service.SERVICE_USER_DEFINED_CONTROL | win32service.SERVICE_QUERY_STATUS,
            )
            win32service.ControlService(service, PURGE_CONTROL_CODE)
        finally:
            if service is not None:
                win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(scm)
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if status_path.is_file():
                result = json.loads(status_path.read_text(encoding="utf-8"))
                if result == {"schema_version": "1.0.0", "status": "purged"}:
                    return
                raise RuntimeError("service-owned identity purge failed")
            time.sleep(0.2)
        raise TimeoutError("service-owned identity purge timed out")

    def status(self) -> str:
        import pywintypes
        import win32service

        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        service = None
        try:
            try:
                service = win32service.OpenService(
                    scm, SERVICE_NAME, win32service.SERVICE_QUERY_STATUS
                )
            except pywintypes.error as error:
                if error.winerror == 1060:
                    return "not_installed"
                raise
            state = int(win32service.QueryServiceStatus(service)[1])
            return {
                win32service.SERVICE_STOPPED: "stopped",
                win32service.SERVICE_START_PENDING: "start_pending",
                win32service.SERVICE_STOP_PENDING: "stop_pending",
                win32service.SERVICE_RUNNING: "running",
                win32service.SERVICE_CONTINUE_PENDING: "continue_pending",
                win32service.SERVICE_PAUSE_PENDING: "pause_pending",
                win32service.SERVICE_PAUSED: "paused",
            }.get(state, "unknown")
        finally:
            if service is not None:
                win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(scm)

    def doctor(self) -> DoctorCheck:
        try:
            state = self.status()
        except Exception:
            return DoctorCheck(
                name="service_manager",
                status="BLOCKED",
                detail="Windows Service Control Manager query failed",
            )
        if state == "running":
            return DoctorCheck(
                name="service_manager", status="OK", detail="Windows service is running"
            )
        return DoctorCheck(
            name="service_manager",
            status="DEGRADED",
            detail=f"Windows service state: {state}",
        )
