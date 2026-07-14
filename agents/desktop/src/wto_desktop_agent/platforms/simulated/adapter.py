from __future__ import annotations

from pathlib import Path
from tempfile import gettempdir

from wto_desktop_agent.platforms.common import (
    AllowlistedProcessRunner,
    DeferredServiceManager,
    InMemorySecretStore,
    UnsupportedNetworkController,
    UnsupportedWifiCollector,
)


class SimulatedPlatformAdapter:
    def __init__(self) -> None:
        self._wifi = UnsupportedWifiCollector()
        self._network = UnsupportedNetworkController()
        self._process = AllowlistedProcessRunner({})
        self._secrets = InMemorySecretStore()
        self._services = DeferredServiceManager()

    @property
    def platform_id(self) -> str:
        return "simulated"

    @property
    def platform_version(self) -> str:
        return "1"

    @property
    def default_state_dir(self) -> Path:
        return Path(gettempdir()) / "wto-desktop-agent"

    @property
    def wifi_collector(self) -> UnsupportedWifiCollector:
        return self._wifi

    @property
    def network_controller(self) -> UnsupportedNetworkController:
        return self._network

    @property
    def process_runner(self) -> AllowlistedProcessRunner:
        return self._process

    @property
    def secret_store(self) -> InMemorySecretStore:
        return self._secrets

    @property
    def service_manager(self) -> DeferredServiceManager:
        return self._services

    def capability_overrides(self) -> dict[str, dict[str, object]]:
        return {}
