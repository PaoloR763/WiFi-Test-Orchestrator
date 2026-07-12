from __future__ import annotations

import os
import platform
from pathlib import Path

from wto_desktop_agent.platforms.common import (
    DeferredServiceManager,
    UnsupportedNetworkController,
    UnsupportedWifiCollector,
)
from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner
from wto_desktop_agent.platforms.windows.secret_store import (
    WindowsCredentialManagerStore,
)


class WindowsPlatformAdapter:
    def __init__(self) -> None:
        self._wifi = UnsupportedWifiCollector()
        self._network = UnsupportedNetworkController()
        self._process = WindowsProcessRunner()
        self._secrets = WindowsCredentialManagerStore()
        self._services = DeferredServiceManager()

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
    def wifi_collector(self) -> UnsupportedWifiCollector:
        return self._wifi

    @property
    def network_controller(self) -> UnsupportedNetworkController:
        return self._network

    @property
    def process_runner(self) -> WindowsProcessRunner:
        return self._process

    @property
    def secret_store(self) -> WindowsCredentialManagerStore:
        return self._secrets

    @property
    def service_manager(self) -> DeferredServiceManager:
        return self._services
