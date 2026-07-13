from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from wto_desktop_agent.domain.models import DoctorCheck
from wto_desktop_agent.domain.telemetry import InventorySnapshot, WifiScanSnapshot


class WifiCollector(Protocol):
    async def collect_inventory(self) -> InventorySnapshot: ...

    async def scan(
        self, interface_guid: str, cancellation: CancellationToken
    ) -> WifiScanSnapshot: ...

    def capability_overrides(self) -> dict[str, dict[str, object]]: ...


class NetworkController(Protocol):
    def list_profiles(self, interface_guid: str, *, confirmed: bool) -> list[str]: ...

    async def connect(
        self,
        *,
        interface_guid: str,
        profile_name: str,
        idempotency_key: str,
        confirmed: bool,
        timeout_seconds: float,
        cancellation: CancellationToken,
    ) -> dict[str, object]: ...

    async def disconnect(
        self,
        *,
        interface_guid: str,
        idempotency_key: str,
        confirmed: bool,
        timeout_seconds: float,
        cancellation: CancellationToken,
    ) -> dict[str, object]: ...

    async def request_scan(
        self,
        *,
        interface_guid: str,
        idempotency_key: str,
        confirmed: bool,
        cancellation: CancellationToken,
    ) -> WifiScanSnapshot: ...

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
    def install(self, executable: Path, config_path: Path) -> None: ...

    def uninstall(self) -> None: ...

    def purge_identity(self, *, confirmed: bool, timeout_seconds: float = 30.0) -> None: ...

    def control(self, action: Literal["start", "stop", "pause", "resume"]) -> None: ...

    def status(self) -> str: ...

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

    def capability_overrides(self) -> dict[str, dict[str, object]]: ...


from wto_desktop_agent.ports.plugins import CancellationToken  # noqa: E402
