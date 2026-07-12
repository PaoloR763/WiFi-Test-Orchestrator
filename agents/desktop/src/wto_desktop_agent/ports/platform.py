from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from wto_desktop_agent.domain.models import DoctorCheck


class WifiCollector(Protocol):
    def capability_overrides(self) -> dict[str, dict[str, object]]: ...


class NetworkController(Protocol):
    def capability_overrides(self) -> dict[str, dict[str, object]]: ...


@dataclass(frozen=True)
class CommandRequest:
    command_id: str
    arguments: Mapping[str, object]
    timeout_seconds: float


@dataclass(frozen=True)
class ProcessResult:
    return_code: int
    stdout: bytes
    stderr: bytes


class ProcessRunner(Protocol):
    async def run(
        self, request: CommandRequest, cancellation: CancellationToken
    ) -> ProcessResult: ...


class SecretStore(Protocol):
    @property
    def secure(self) -> bool: ...

    def put(self, key: str, value: str) -> None: ...

    def get(self, key: str) -> str | None: ...

    def delete(self, key: str) -> None: ...

    def doctor(self) -> DoctorCheck: ...


class ServiceManager(Protocol):
    def doctor(self) -> DoctorCheck: ...


class PlatformAdapter(Protocol):
    @property
    def platform_id(self) -> str: ...

    @property
    def platform_version(self) -> str: ...

    @property
    def default_state_dir(self) -> Path: ...

    @property
    def wifi_collector(self) -> WifiCollector: ...

    @property
    def network_controller(self) -> NetworkController: ...

    @property
    def process_runner(self) -> ProcessRunner: ...

    @property
    def secret_store(self) -> SecretStore: ...

    @property
    def service_manager(self) -> ServiceManager: ...


from wto_desktop_agent.ports.plugins import CancellationToken  # noqa: E402
