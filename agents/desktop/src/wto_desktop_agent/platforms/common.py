from __future__ import annotations

import asyncio
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel

from wto_desktop_agent.domain.errors import PluginUnavailableError
from wto_desktop_agent.domain.models import DoctorCheck
from wto_desktop_agent.ports.platform import CommandRequest, ProcessResult, SecretStore
from wto_desktop_agent.ports.plugins import CancellationToken


class UnsupportedWifiCollector:
    def capability_overrides(self) -> dict[str, dict[str, object]]:
        return {}


class UnsupportedNetworkController:
    def capability_overrides(self) -> dict[str, dict[str, object]]:
        return {}


class DeferredServiceManager:
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
        environment = {str(key): str(value) for key, value in spec.environment.items()}
        process = await self.start_process(spec, argv, environment)
        self.after_start(process)
        communicate = asyncio.create_task(process.communicate())
        cancelled = asyncio.create_task(cancellation.wait())
        try:
            done, _ = await asyncio.wait(
                {communicate, cancelled},
                timeout=request.timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if communicate not in done:
                await self.terminate(process)
                if cancelled in done:
                    raise asyncio.CancelledError
                raise TimeoutError("allowlisted process timed out")
            stdout, stderr = communicate.result()
            if len(stdout) > spec.max_output_bytes or len(stderr) > spec.max_output_bytes:
                raise RuntimeError("allowlisted process output limit exceeded")
            return ProcessResult(process.returncode or 0, stdout, stderr)
        finally:
            cancelled.cancel()
            if not communicate.done():
                communicate.cancel()


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
        try:
            os.killpg(process.pid, 15)
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except (ProcessLookupError, TimeoutError):
            try:
                os.killpg(process.pid, 9)
            except ProcessLookupError:
                pass
            await process.wait()
