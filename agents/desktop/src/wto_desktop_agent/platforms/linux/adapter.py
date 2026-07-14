from __future__ import annotations

import os
import platform
from collections.abc import Callable
from pathlib import Path
from typing import cast

from wto_desktop_agent.domain.errors import SecureStoreUnavailableError
from wto_desktop_agent.domain.models import DoctorCheck
from wto_desktop_agent.platforms.common import (
    DeferredServiceManager,
    LinuxProcessRunner,
    UnsupportedNetworkController,
    UnsupportedWifiCollector,
)
from wto_desktop_agent.ports.platform import SecretStore

_GET_EFFECTIVE_USER_ID = cast(
    Callable[[], int] | None,
    getattr(os, "geteuid", None),
)


class UnavailableLinuxSecretStore:
    @property
    def secure(self) -> bool:
        return False

    def put(self, key: str, value: str) -> None:
        raise SecureStoreUnavailableError("Linux Secret Service is unavailable")

    def get(self, key: str) -> str | None:
        raise SecureStoreUnavailableError("Linux Secret Service is unavailable")

    def delete(self, key: str) -> None:
        raise SecureStoreUnavailableError("Linux Secret Service is unavailable")

    def doctor(self) -> DoctorCheck:
        return DoctorCheck(
            name="secret_store",
            status="BLOCKED",
            detail=(
                "Linux Secret Service is unavailable; headless sessions need an unlocked service"
            ),
        )


class LinuxPlatformAdapter:
    def __init__(self) -> None:
        self._wifi = UnsupportedWifiCollector()
        self._network = UnsupportedNetworkController()
        self._process = LinuxProcessRunner({})
        self._services = DeferredServiceManager()
        self._secrets: SecretStore
        try:
            from wto_desktop_agent.platforms.linux.secret_store import (
                LinuxSecretServiceStore,
            )

            self._secrets = LinuxSecretServiceStore()
        except SecureStoreUnavailableError:
            self._secrets = UnavailableLinuxSecretStore()

    @property
    def platform_id(self) -> str:
        return "linux"

    @property
    def platform_version(self) -> str:
        return platform.release()[:64]

    @property
    def default_state_dir(self) -> Path:
        if _GET_EFFECTIVE_USER_ID is not None and _GET_EFFECTIVE_USER_ID() == 0:
            return Path("/var/lib/wto-agent")
        return Path.home() / ".local" / "state" / "wto-agent"

    @property
    def wifi_collector(self) -> UnsupportedWifiCollector:
        return self._wifi

    @property
    def network_controller(self) -> UnsupportedNetworkController:
        return self._network

    @property
    def process_runner(self) -> LinuxProcessRunner:
        return self._process

    @property
    def secret_store(self) -> SecretStore:
        return self._secrets

    @property
    def service_manager(self) -> DeferredServiceManager:
        return self._services

    def capability_overrides(self) -> dict[str, dict[str, object]]:
        return {}
