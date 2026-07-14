from __future__ import annotations

import os
import platform
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from wto_desktop_agent.config import AgentSettings
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.platforms.common import CommandSpec
from wto_desktop_agent.platforms.windows.capability_manifest import (
    background_continuous_override,
)
from wto_desktop_agent.platforms.windows.inventory import WindowsInventoryCollector
from wto_desktop_agent.platforms.windows.ip_helper import IpHelperClient
from wto_desktop_agent.platforms.windows.native_wifi.client import NativeWifiClient
from wto_desktop_agent.platforms.windows.network_controller import WindowsNetworkController
from wto_desktop_agent.platforms.windows.npcap import NpcapDetector
from wto_desktop_agent.platforms.windows.powershell import verify_inventory_script
from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner
from wto_desktop_agent.platforms.windows.secret_store import (
    WindowsCredentialManagerStore,
)
from wto_desktop_agent.platforms.windows.service_manager import WindowsServiceManager


class _NoArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _trusted_environment() -> dict[str, str]:
    allowed = (
        "SystemRoot",
        "WINDIR",
        "PATH",
        "PSModulePath",
        "TEMP",
        "TMP",
        "WTO_INVENTORY_DIAGNOSTICS",
    )
    return {name: os.environ[name] for name in allowed if name in os.environ}


class WindowsPlatformAdapter:
    def __init__(self, settings: AgentSettings, store: SQLiteStore) -> None:
        system_root = os.environ.get("SystemRoot")
        if not system_root:
            raise RuntimeError("SystemRoot is unavailable")
        system32 = Path(system_root) / "System32"
        powershell = system32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        netsh = system32 / "netsh.exe"
        script = verify_inventory_script()
        self._capture_detector = NpcapDetector()
        inventory_environment = _trusted_environment()
        inventory_environment["WTO_INVENTORY_OUTER_TIMEOUT_MILLISECONDS"] = str(
            int(settings.windows_inventory_timeout_seconds * 1000)
        )
        commands = {
            "windows.powershell.network_inventory": CommandSpec(
                command_id="windows.powershell.network_inventory",
                executable=powershell.resolve(),
                argument_model=_NoArguments,
                build_argv=lambda _: [
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(script),
                ],
                cwd=script.parent,
                environment=inventory_environment,
                max_output_bytes=4_194_304,
            ),
            "windows.netsh.wlan_show_interfaces": CommandSpec(
                command_id="windows.netsh.wlan_show_interfaces",
                executable=netsh.resolve(),
                argument_model=_NoArguments,
                build_argv=lambda _: ["wlan", "show", "interfaces"],
                cwd=system32.resolve(),
                environment=_trusted_environment(),
                max_output_bytes=1_048_576,
            ),
        }
        if self._capture_detector.status.dumpcap_path is not None:
            dumpcap = self._capture_detector.status.dumpcap_path
            commands["windows.dumpcap.version"] = CommandSpec(
                command_id="windows.dumpcap.version",
                executable=dumpcap,
                argument_model=_NoArguments,
                build_argv=lambda _: ["--version"],
                cwd=dumpcap.parent,
                environment=_trusted_environment(),
                max_output_bytes=262_144,
            )
            commands["windows.dumpcap.enumerate"] = CommandSpec(
                command_id="windows.dumpcap.enumerate",
                executable=dumpcap,
                argument_model=_NoArguments,
                build_argv=lambda _: ["-D", "-M"],
                cwd=dumpcap.parent,
                environment=_trusted_environment(),
                max_output_bytes=1_048_576,
            )
        self._process = WindowsProcessRunner(commands)
        native_wifi = NativeWifiClient()
        self._wifi = WindowsInventoryCollector(
            native_wifi,
            IpHelperClient(),
            self._process,
            inventory_timeout_seconds=settings.windows_inventory_timeout_seconds,
            scan_cooldown_seconds=settings.wifi_scan_cooldown_seconds,
            scan_timeout_seconds=settings.wifi_scan_timeout_seconds,
        )
        self._network = WindowsNetworkController(
            native_wifi,
            self._wifi,
            store,
            allowed_interface_guids=settings.allowed_interface_guids,
            allowed_profiles=settings.allowed_wifi_profiles,
            enabled=settings.allow_local_wifi_control,
        )
        self._secrets = WindowsCredentialManagerStore()
        self._services = WindowsServiceManager(settings.state_dir)

    @property
    def platform_id(self) -> str:
        return "windows"

    @property
    def platform_version(self) -> str:
        return platform.version()[:64]

    @property
    def default_state_dir(self) -> Path:
        return (
            Path(os.environ.get("PROGRAMDATA", str(Path.home()))) / "WiFiTestOrchestrator" / "agent"
        )

    @property
    def wifi_collector(self) -> WindowsInventoryCollector:
        return self._wifi

    @property
    def network_controller(self) -> WindowsNetworkController:
        return self._network

    @property
    def process_runner(self) -> WindowsProcessRunner:
        return self._process

    @property
    def secret_store(self) -> WindowsCredentialManagerStore:
        return self._secrets

    @property
    def service_manager(self) -> WindowsServiceManager:
        return self._services

    def capability_overrides(self) -> dict[str, dict[str, object]]:
        result = self._wifi.capability_overrides()
        result.update(self._network.capability_overrides())
        result.update(self._capture_detector.capability_overrides())
        service_state = self._services.status()
        result["execution.background.continuous"] = background_continuous_override(service_state)
        return result
