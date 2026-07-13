from __future__ import annotations

import asyncio
import hashlib
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from pydantic import BaseModel

from wto_desktop_agent.domain.errors import PluginUnavailableError
from wto_desktop_agent.domain.models import DoctorCheck
from wto_desktop_agent.domain.telemetry import (
    InventorySnapshot,
    ObservationReason,
    WifiScanSnapshot,
)
from wto_desktop_agent.ports.platform import CommandRequest, ProcessResult, SecretStore
from wto_desktop_agent.ports.plugins import CancellationToken

_KILL_PROCESS_GROUP = cast(
    Callable[[int, int], None] | None,
    getattr(os, "killpg", None),
)


class UnsupportedWifiCollector:
    async def collect_inventory(self) -> InventorySnapshot:
        now = __import__("datetime").datetime.now(__import__("datetime").UTC)
        return InventorySnapshot(
            snapshot_id=str(uuid4()),
            started_at=now,
            finished_at=now,
            interfaces=[],
            source_errors={
                "wifi": ObservationReason(code="not_implemented", detail="collector unavailable")
            },
        )

    async def scan(self, interface_guid: str, cancellation: CancellationToken) -> WifiScanSnapshot:
        now = __import__("datetime").datetime.now(__import__("datetime").UTC)
        return WifiScanSnapshot(
            interface_guid=interface_guid,
            started_at=now,
            finished_at=now,
            entries=[],
            reason=ObservationReason(code="not_implemented"),
        )

    def capability_overrides(self) -> dict[str, dict[str, object]]:
        return {}


class UnsupportedNetworkController:
    def list_profiles(self, interface_guid: str, *, confirmed: bool) -> list[str]:
        del interface_guid, confirmed
        return []

    async def connect(self, **_: object) -> dict[str, object]:
        raise PluginUnavailableError("network control is unavailable")

    async def disconnect(self, **_: object) -> dict[str, object]:
        raise PluginUnavailableError("network control is unavailable")

    async def request_scan(self, **_: object) -> WifiScanSnapshot:
        raise PluginUnavailableError("network control is unavailable")

    def capability_overrides(self) -> dict[str, dict[str, object]]:
        return {}


class DeferredServiceManager:
    def install(self, executable: Path, config_path: Path) -> None:
        raise RuntimeError("service installation is unavailable")

    def uninstall(self) -> None:
        raise RuntimeError("service uninstallation is unavailable")

    def purge_identity(self, *, confirmed: bool, timeout_seconds: float = 30.0) -> None:
        del confirmed, timeout_seconds
        raise RuntimeError("service identity purge is unavailable")

    def control(self, action: str) -> None:
        raise RuntimeError(f"service control is unavailable: {action}")

    def status(self) -> str:
        return "not_installed"

    def doctor(self) -> DoctorCheck:
        return DoctorCheck(
            name="service_manager",
            status="DEGRADED",
            detail="Service installation is intentionally deferred in Phase 05",
        )


class InMemorySecretStore(SecretStore):
    def __init__(self) -> None:
        self._values: dict[str, str] = {}

    @property
    def secure(self) -> bool:
        return False

    def put(self, key: str, value: str) -> None:
        self._values[key] = value

    def get(self, key: str) -> str | None:
        return self._values.get(key)

    def delete(self, key: str) -> None:
        self._values.pop(key, None)

    def doctor(self) -> DoctorCheck:
        return DoctorCheck(
            name="secret_store",
            status="DEGRADED",
            detail="Explicit in-memory development/test store; credentials do not survive restart",
        )


@dataclass(frozen=True)
class CommandSpec:
    command_id: str
    executable: Path
    argument_model: type[BaseModel]
    build_argv: Callable[[BaseModel], list[str]]
    cwd: Path
    environment: Mapping[str, str]
    max_output_bytes: int = 1_048_576
    expected_sha256: str | None = None


class AllowlistedProcessRunner:
    def __init__(self, commands: Mapping[str, CommandSpec]) -> None:
        self._commands = dict(commands)

    def after_start(self, process: asyncio.subprocess.Process) -> None:
        return None

    async def start_process(
        self, spec: CommandSpec, argv: list[str], environment: dict[str, str]
    ) -> asyncio.subprocess.Process:
        return await asyncio.create_subprocess_exec(
            str(spec.executable),
            *argv,
            cwd=spec.cwd,
            env=environment,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def terminate(self, process: asyncio.subprocess.Process) -> None:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except TimeoutError:
            process.kill()
            await process.wait()

    async def run(self, request: CommandRequest, cancellation: CancellationToken) -> ProcessResult:
        try:
            spec = self._commands[request.command_id]
        except KeyError as error:
            raise PluginUnavailableError("command_id is not locally allowlisted") from error
        parameters = spec.argument_model.model_validate(dict(request.arguments))
        argv = spec.build_argv(parameters)
        if not spec.executable.is_absolute():
            raise ValueError("allowlisted executable must use an absolute path")
        if not spec.cwd.is_absolute():
            raise ValueError("allowlisted working directory must use an absolute path")
        resolved = spec.executable.resolve(strict=True)
        if resolved != spec.executable or not resolved.is_file():
            raise ValueError("allowlisted executable path changed during resolution")
        if spec.expected_sha256 is not None:
            actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
            if actual != spec.expected_sha256:
                raise PluginUnavailableError("allowlisted executable integrity mismatch")
        before = resolved.stat()
        fingerprint = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        environment = {str(key): str(value) for key, value in spec.environment.items()}
        process = await self.start_process(spec, argv, environment)
        self.after_start(process)
        after = resolved.stat()
        if fingerprint != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            await self.terminate(process)
            raise PluginUnavailableError("allowlisted executable changed during process creation")
        stdout_task = asyncio.create_task(self._read_limited(process.stdout, spec.max_output_bytes))
        stderr_task = asyncio.create_task(self._read_limited(process.stderr, spec.max_output_bytes))
        process_task = asyncio.create_task(process.wait())
        cancelled = asyncio.create_task(cancellation.wait())
        combined = asyncio.gather(process_task, stdout_task, stderr_task)
        try:
            wait_set: set[asyncio.Future[Any]] = {combined, cancelled}
            done, _ = await asyncio.wait(
                wait_set,
                timeout=request.timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancelled in done:
                await self.terminate(process)
                raise asyncio.CancelledError
            if combined not in done:
                await self.terminate(process)
                raise TimeoutError("allowlisted process timed out")
            _, stdout, stderr = await combined
            return ProcessResult(int(process.returncode or 0), stdout, stderr)
        except Exception:
            if process.returncode is None:
                await self.terminate(process)
            raise
        finally:
            cancelled.cancel()
            if not combined.done():
                combined.cancel()
            for task in (stdout_task, stderr_task, process_task):
                if not task.done():
                    task.cancel()

    async def _read_limited(self, stream: asyncio.StreamReader | None, limit: int) -> bytes:
        if stream is None:
            return b""
        result = bytearray()
        while chunk := await stream.read(65_536):
            result.extend(chunk)
            if len(result) > limit:
                raise RuntimeError("allowlisted process output limit exceeded")
        return bytes(result)


class LinuxProcessRunner(AllowlistedProcessRunner):
    async def start_process(
        self, spec: CommandSpec, argv: list[str], environment: dict[str, str]
    ) -> asyncio.subprocess.Process:
        return await asyncio.create_subprocess_exec(
            str(spec.executable),
            *argv,
            cwd=spec.cwd,
            env=environment,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )

    async def terminate(self, process: asyncio.subprocess.Process) -> None:
        if _KILL_PROCESS_GROUP is None:
            await super().terminate(process)
            return
        try:
            _KILL_PROCESS_GROUP(process.pid, 15)
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except (ProcessLookupError, TimeoutError):
            try:
                _KILL_PROCESS_GROUP(process.pid, 9)
            except ProcessLookupError:
                pass
            await process.wait()
