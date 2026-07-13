from __future__ import annotations

import asyncio
import hashlib
import inspect
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
    # Cleanup gets one bounded grace period after the request fails or is
    # cancelled. The final 100 ms are reserved for force-closing transports
    # and draining the asyncio tasks owned by this runner.
    _cleanup_grace_seconds = 5.0
    _cleanup_force_close_reserve_seconds = 0.1

    def __init__(self, commands: Mapping[str, CommandSpec]) -> None:
        self._commands = dict(commands)

    def after_start(self, process: asyncio.subprocess.Process) -> None:
        return None

    def after_finish(self, process: asyncio.subprocess.Process) -> None:
        return None

    async def wait_after_finish(self, process: asyncio.subprocess.Process) -> None:
        return None

    async def start_process(
        self,
        spec: CommandSpec,
        argv: list[str],
        environment: dict[str, str],
        *,
        execution_token: object,
        deadline: float | None = None,
    ) -> asyncio.subprocess.Process:
        del execution_token, deadline
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
        loop = asyncio.get_running_loop()
        request_deadline = loop.time() + max(0.0, request.timeout_seconds)
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
        process: asyncio.subprocess.Process | None = None
        managed: list[asyncio.Future[Any]] = []
        execution_token = object()
        spawn_task: asyncio.Task[Any] | None = None
        primary_error: BaseException | None = None
        primary_traceback: Any = None
        cleanup_error: BaseException | None = None
        cleanup_cancellation: asyncio.CancelledError | None = None
        result: ProcessResult | None = None
        succeeded = False
        try:
            if cancellation.cancelled:
                raise asyncio.CancelledError
            if loop.time() >= request_deadline:
                raise TimeoutError("allowlisted process timed out before spawn")
            spawn_task = self._create_managed_task(
                self.start_process(
                    spec,
                    argv,
                    environment,
                    execution_token=execution_token,
                    deadline=request_deadline,
                ),
                managed,
            )
            cancelled = self._create_managed_task(cancellation.wait(), managed)
            done, _ = await asyncio.wait(
                {spawn_task, cancelled},
                timeout=max(0.0, request_deadline - loop.time()),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancelled in done:
                raise asyncio.CancelledError
            if spawn_task not in done:
                raise TimeoutError("allowlisted process timed out during spawn")
            process = cast(asyncio.subprocess.Process, spawn_task.result())
            # This is only an additional post-spawn change detector. It does not
            # make path-based executable validation atomic with process creation.
            after = resolved.stat()
            if fingerprint != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise PluginUnavailableError(
                    "allowlisted executable changed during process creation"
                )
            if cancellation.cancelled:
                raise asyncio.CancelledError
            if loop.time() >= request_deadline:
                raise TimeoutError("allowlisted process timed out during spawn validation")
            self.after_start(process)
            if loop.time() >= request_deadline:
                raise TimeoutError("allowlisted process timed out during start finalization")
            stdout_task = self._create_managed_task(
                self._read_limited(process.stdout, spec.max_output_bytes), managed
            )
            stderr_task = self._create_managed_task(
                self._read_limited(process.stderr, spec.max_output_bytes), managed
            )
            process_task = self._create_managed_task(process.wait(), managed)
            combined = self._create_managed_task(
                self._gather_process_tasks(process_task, stdout_task, stderr_task),
                managed,
            )
            if cancellation.cancelled:
                raise asyncio.CancelledError
            wait_set: set[asyncio.Task[Any]] = {combined, cancelled}
            done, _ = await asyncio.wait(
                wait_set,
                timeout=max(0.0, request_deadline - loop.time()),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancelled in done:
                raise asyncio.CancelledError
            if combined not in done:
                raise TimeoutError("allowlisted process timed out")
            _, stdout, stderr = await combined
            result = ProcessResult(int(process.returncode or 0), stdout, stderr)
            succeeded = True
        except BaseException as error:
            primary_error = error
            primary_traceback = error.__traceback__
        finally:
            cleanup_deadline = loop.time() + self._cleanup_grace_seconds
            operation_deadline = max(
                loop.time(),
                cleanup_deadline - self._cleanup_force_close_reserve_seconds,
            )
            if spawn_task is not None and process is None:
                if not spawn_task.done():
                    spawn_task.cancel()
                spawn_error, spawn_cancellation, spawn_timed_out = (
                    await self._wait_for_protected_task(
                        spawn_task,
                        deadline=operation_deadline,
                    )
                )
                cleanup_cancellation = cleanup_cancellation or spawn_cancellation
                if spawn_timed_out:
                    cleanup_error = TimeoutError("process spawn cleanup exceeded the cleanup grace")
                elif spawn_error is None and not spawn_task.cancelled():
                    process = cast(asyncio.subprocess.Process, spawn_task.result())
                elif (
                    spawn_error is not None
                    and not isinstance(spawn_error, asyncio.CancelledError)
                    and spawn_error is not primary_error
                ):
                    cleanup_error = spawn_error
                if process is None:
                    try:
                        self._force_cleanup_spawn(execution_token)
                    except BaseException as error:
                        cleanup_error = cleanup_error or error
            if process is not None:
                cleanup_awaitable = self._cleanup_process(
                    process,
                    managed,
                    terminate=not succeeded,
                    deadline=cleanup_deadline,
                )
                cleanup: asyncio.Task[None] | None
                try:
                    cleanup = loop.create_task(cleanup_awaitable)
                    cleanup.add_done_callback(self._consume_future_result)
                except BaseException as error:
                    cleanup_error = cleanup_error or error
                    try:
                        # Emergency fallback for a task-factory failure after spawn.
                        cleanup = asyncio.Task(cleanup_awaitable, loop=loop)
                        cleanup.add_done_callback(self._consume_future_result)
                    except BaseException as fallback_error:
                        cleanup_awaitable.close()
                        error.add_note(
                            f"emergency cleanup task creation also failed: {fallback_error!r}"
                        )
                        cleanup = None
                if cleanup is not None:
                    cleanup_task_error, cancellation_error, timed_out = (
                        await self._wait_for_protected_task(
                            cleanup,
                            deadline=operation_deadline,
                        )
                    )
                    cleanup_cancellation = cleanup_cancellation or cancellation_error
                    if timed_out:
                        cleanup.cancel()
                        try:
                            self._force_cleanup_process(process)
                        except BaseException as force_error:
                            cleanup_error = cleanup_error or force_error
                        cleanup_error = cleanup_error or TimeoutError(
                            "process cleanup exceeded the cleanup grace"
                        )
                        drain_error, drain_cancellation, drain_timed_out = (
                            await self._wait_for_protected_task(
                                cleanup,
                                deadline=cleanup_deadline,
                            )
                        )
                        cleanup_cancellation = cleanup_cancellation or drain_cancellation
                        if drain_timed_out:
                            cleanup_error = cleanup_error or TimeoutError(
                                "process cleanup task remained pending after force-close"
                            )
                        elif drain_error is not None and not isinstance(
                            drain_error, asyncio.CancelledError
                        ):
                            cleanup_error = cleanup_error or drain_error
                    elif cleanup_task_error is not None:
                        cleanup_error = cleanup_task_error
                else:
                    try:
                        # Even if both normal and emergency task creation fail,
                        # the synchronous lifecycle hook still runs exactly once.
                        self.after_finish(process)
                    except BaseException as finish_error:
                        cleanup_error = cleanup_error or finish_error
                    try:
                        self._force_cleanup_process(process)
                    except BaseException as force_error:
                        cleanup_error = cleanup_error or force_error
                    unique_managed = self._unique_futures(managed)
                    for future in unique_managed:
                        if not future.done():
                            future.cancel()
                    pending, cancellation_error = await self._wait_for_futures_protected(
                        unique_managed,
                        deadline=cleanup_deadline,
                    )
                    cleanup_cancellation = cleanup_cancellation or cancellation_error
                    if pending:
                        cleanup_error = cleanup_error or TimeoutError(
                            "async process tasks exceeded cleanup grace"
                        )
            else:
                unique_managed = self._unique_futures(managed)
                for future in unique_managed:
                    if not future.done():
                        future.cancel()
                if unique_managed:
                    pending, cancellation_error = await self._wait_for_futures_protected(
                        unique_managed,
                        deadline=cleanup_deadline,
                    )
                    cleanup_cancellation = cleanup_cancellation or cancellation_error
                    if pending:
                        cleanup_error = cleanup_error or TimeoutError(
                            "spawn tasks remained pending after cleanup"
                        )

            if cleanup_cancellation is not None and primary_error is None:
                primary_error = cleanup_cancellation
                primary_traceback = cleanup_cancellation.__traceback__

        if primary_error is not None:
            if cleanup_error is not None:
                primary_error.add_note(f"process cleanup also failed: {cleanup_error!r}")
            if cleanup_cancellation is not None and cleanup_cancellation is not primary_error:
                primary_error.add_note("process cleanup was also cancelled")
            raise primary_error.with_traceback(primary_traceback)
        if cleanup_error is not None:
            raise cleanup_error
        if result is None:
            raise RuntimeError("allowlisted process completed without a result")
        return result

    async def _wait_for_protected_task(
        self,
        task: asyncio.Future[Any],
        *,
        deadline: float,
    ) -> tuple[BaseException | None, asyncio.CancelledError | None, bool]:
        """Wait without propagating caller cancellation into *task*, up to deadline."""
        cancellation: asyncio.CancelledError | None = None
        loop = asyncio.get_running_loop()
        while not task.done():
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None, cancellation, True
            try:
                done, _ = await asyncio.wait({task}, timeout=remaining)
            except asyncio.CancelledError as error:
                cancellation = cancellation or error
                continue
            if not done:
                return None, cancellation, True
        try:
            task.result()
        except BaseException as error:
            return error, cancellation, False
        return None, cancellation, False

    async def _wait_for_futures_protected(
        self,
        futures: set[asyncio.Future[Any]],
        *,
        deadline: float,
    ) -> tuple[set[asyncio.Future[Any]], asyncio.CancelledError | None]:
        pending = {future for future in futures if not future.done()}
        cancellation: asyncio.CancelledError | None = None
        loop = asyncio.get_running_loop()
        while pending:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                _, pending = await asyncio.wait(pending, timeout=remaining)
            except asyncio.CancelledError as error:
                cancellation = cancellation or error
        return pending, cancellation

    @staticmethod
    def _consume_future_result(future: asyncio.Future[Any]) -> None:
        if future.cancelled():
            return
        try:
            future.exception()
        except BaseException:
            return

    @staticmethod
    def _unique_futures(
        futures: list[asyncio.Future[Any]],
    ) -> set[asyncio.Future[Any]]:
        return set(futures)

    def _force_cleanup_spawn(self, execution_token: object) -> None:
        del execution_token

    def _force_cleanup_process(self, process: asyncio.subprocess.Process) -> None:
        marker_name = "_wto_force_cleanup_started"
        if bool(getattr(process, marker_name, False)):
            return
        # The caller which expires the cleanup deadline and the cancelled
        # cleanup coroutine's finally block can reach this method in the same
        # event-loop turn. Claim ownership before touching the process so kill,
        # pipe close, and transport close each happen at most once for this
        # process object; PID is never used as the ownership key.
        setattr(process, marker_name, True)
        errors: list[BaseException] = []
        transport = getattr(process, "_transport", None)
        close_transport = getattr(transport, "close", None)
        # asyncio's subprocess transport owns both pipe closure and the native
        # kill of a still-running child. Calling process.kill() first would let
        # BaseSubprocessTransport.close() issue a second native termination.
        if close_transport is None and process.returncode is None:
            try:
                process.kill()
            except (ProcessLookupError, OSError):
                pass
            except BaseException as error:
                errors.append(error)
        try:
            self._close_process_pipes(process)
        except BaseException as error:
            errors.append(error)
        if errors:
            raise errors[0]

    def _create_managed_task(
        self, awaitable: Any, managed: list[asyncio.Future[Any]]
    ) -> asyncio.Task[Any]:
        try:
            task = asyncio.create_task(awaitable)
        except BaseException:
            if inspect.iscoroutine(awaitable):
                awaitable.close()
            raise
        task.add_done_callback(self._consume_future_result)
        managed.append(task)
        return task

    async def _gather_process_tasks(
        self,
        process_task: asyncio.Future[Any],
        stdout_task: asyncio.Future[Any],
        stderr_task: asyncio.Future[Any],
    ) -> tuple[Any, Any, Any]:
        result = await asyncio.gather(process_task, stdout_task, stderr_task)
        return result[0], result[1], result[2]

    async def _cleanup_process(
        self,
        process: asyncio.subprocess.Process,
        managed: list[asyncio.Future[Any]],
        *,
        terminate: bool,
        deadline: float,
    ) -> None:
        errors: list[BaseException] = []
        cleanup_steps: list[asyncio.Future[Any]] = []
        operation_deadline = max(
            asyncio.get_running_loop().time(),
            deadline - self._cleanup_force_close_reserve_seconds,
        )
        try:
            if terminate:
                await self._run_cleanup_step(
                    self.terminate(process),
                    cleanup_steps,
                    deadline=operation_deadline,
                    description="process termination",
                    errors=errors,
                )

            try:
                self.after_finish(process)
            except BaseException as error:
                errors.append(error)
            await self._run_cleanup_step(
                self.wait_after_finish(process),
                cleanup_steps,
                deadline=operation_deadline,
                description="post-process cleanup",
                errors=errors,
            )

            if process.returncode is None:
                try:
                    process.kill()
                except (ProcessLookupError, OSError):
                    pass
                except BaseException as error:
                    errors.append(error)
                await self._run_cleanup_step(
                    process.wait(),
                    cleanup_steps,
                    deadline=operation_deadline,
                    description="process exit wait",
                    errors=errors,
                )
        finally:
            try:
                self._force_cleanup_process(process)
            except BaseException as error:
                errors.append(error)
            unique_managed = self._unique_futures([*cleanup_steps, *managed])
            for future in unique_managed:
                if not future.done():
                    future.cancel()
            if unique_managed:
                try:
                    _, pending = await asyncio.wait(
                        unique_managed,
                        timeout=max(0.0, deadline - asyncio.get_running_loop().time()),
                    )
                    if pending:
                        errors.append(TimeoutError("async process tasks exceeded cleanup grace"))
                except BaseException as error:
                    errors.append(error)
        if errors:
            raise errors[0]

    async def _run_cleanup_step(
        self,
        awaitable: Any,
        cleanup_steps: list[asyncio.Future[Any]],
        *,
        deadline: float,
        description: str,
        errors: list[BaseException],
    ) -> None:
        try:
            task = asyncio.create_task(awaitable)
        except BaseException as error:
            if inspect.iscoroutine(awaitable):
                awaitable.close()
            errors.append(error)
            return
        task.add_done_callback(self._consume_future_result)
        cleanup_steps.append(task)
        remaining = max(0.0, deadline - asyncio.get_running_loop().time())
        try:
            done, _ = await asyncio.wait({task}, timeout=remaining)
        except BaseException as error:
            errors.append(error)
            return
        if not done:
            task.cancel()
            errors.append(TimeoutError(f"{description} exceeded cleanup grace"))
            return
        try:
            task.result()
        except BaseException as error:
            errors.append(error)

    def _close_process_pipes(self, process: asyncio.subprocess.Process) -> None:
        transport = getattr(process, "_transport", None)
        close_transport = getattr(transport, "close", None)
        if close_transport is not None:
            close_transport()
            return
        get_pipe_transport = getattr(transport, "get_pipe_transport", None)
        errors: list[BaseException] = []
        if get_pipe_transport is not None:
            for file_descriptor in (1, 2):
                try:
                    pipe_transport = get_pipe_transport(file_descriptor)
                    if pipe_transport is not None:
                        pipe_transport.close()
                except BaseException as error:
                    errors.append(error)
        if errors:
            raise errors[0]

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
        self,
        spec: CommandSpec,
        argv: list[str],
        environment: dict[str, str],
        *,
        execution_token: object,
        deadline: float | None = None,
    ) -> asyncio.subprocess.Process:
        del execution_token, deadline
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
