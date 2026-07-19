from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import secrets
import signal
import stat
import struct
import sys
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Protocol, TypeVar, cast
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

_SIGTERM = int(getattr(signal, "SIGTERM", 15))
_SIGKILL = int(getattr(signal, "SIGKILL", 9))
_PIDFD_OPEN = cast(Callable[[int], int] | None, getattr(os, "pidfd_open", None))
_PIDFD_SEND_SIGNAL = cast(
    Callable[[int, int], None] | None,
    getattr(signal, "pidfd_send_signal", None),
)

_T = TypeVar("_T")


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


class LinuxCleanupScope(str, Enum):
    """Linux lifecycle guarantee explicitly accepted by a command registration."""

    LEADER_ONLY = "leader_only"
    PROCESS_TREE = "process_tree"


class CommandOutputMode(str, Enum):
    CAPTURE = "capture"
    CALLER_FILE_DESCRIPTOR = "caller_file_descriptor"


class LinuxCgroupExecution(Protocol):
    @property
    def path(self) -> object: ...

    def attach_pid(self, pid: int) -> None: ...

    def verify_pid(self, pid: int) -> None: ...

    def kill_remaining(self) -> None: ...

    def is_populated(self) -> bool: ...

    async def wait_empty(self, deadline_monotonic: float) -> None: ...

    def remove_empty(self) -> None: ...

    def close(self) -> None: ...


class LinuxCgroupReadiness(Protocol):
    @property
    def available(self) -> bool: ...

    @property
    def reason(self) -> str | None: ...


class LinuxCgroupManager(Protocol):
    @property
    def readiness(self) -> LinuxCgroupReadiness: ...

    def create_execution(self) -> LinuxCgroupExecution: ...


@dataclass(frozen=True)
class ExecutableIdentity:
    """Immutable filesystem identity recorded for a locally trusted executable."""

    dev: int
    ino: int
    uid: int
    gid: int
    file_type: int
    mode: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, metadata: os.stat_result) -> ExecutableIdentity:
        mtime_ns = getattr(metadata, "st_mtime_ns", None)
        ctime_ns = getattr(metadata, "st_ctime_ns", None)
        return cls(
            dev=int(metadata.st_dev),
            ino=int(metadata.st_ino),
            uid=int(metadata.st_uid),
            gid=int(metadata.st_gid),
            file_type=stat.S_IFMT(metadata.st_mode),
            mode=stat.S_IMODE(metadata.st_mode),
            nlink=int(metadata.st_nlink),
            size=int(metadata.st_size),
            mtime_ns=(
                int(mtime_ns) if mtime_ns is not None else int(metadata.st_mtime * 1_000_000_000)
            ),
            ctime_ns=(
                int(ctime_ns) if ctime_ns is not None else int(metadata.st_ctime * 1_000_000_000)
            ),
        )


@dataclass(frozen=True)
class CommandSpec:
    command_id: str
    executable: Path
    argument_model: type[BaseModel]
    # The argument model validates before this callback is invoked. ``Any`` is
    # intentional here so heterogeneous, model-specific builders can coexist
    # in one immutable allowlist without unsafe casts at every registration.
    build_argv: Callable[[Any], list[str]]
    cwd: Path
    environment: Mapping[str, str]
    max_output_bytes: int = 1_048_576
    expected_sha256: str | None = None
    linux_cleanup_scope: LinuxCleanupScope | None = None
    output_mode: CommandOutputMode = CommandOutputMode.CAPTURE
    executable_identity: ExecutableIdentity | None = None


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
        stdout_descriptor: int | None = None,
    ) -> asyncio.subprocess.Process:
        del execution_token, deadline
        return await asyncio.create_subprocess_exec(
            str(spec.executable),
            *argv,
            cwd=spec.cwd,
            env=environment,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=(
                stdout_descriptor if stdout_descriptor is not None else asyncio.subprocess.PIPE
            ),
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
        return await self._run(request, cancellation, stdout_descriptor=None)

    async def run_with_stdout_descriptor(
        self,
        request: CommandRequest,
        cancellation: CancellationToken,
        *,
        stdout_descriptor: int,
    ) -> ProcessResult:
        """Run a locally registered command with stdout wired to a caller-owned FD.

        The descriptor never comes from task arguments and remains owned by the
        caller. The subprocess receives it only as file descriptor 1.
        """

        if stdout_descriptor < 0:
            raise ValueError("stdout descriptor is invalid")
        metadata = os.fstat(stdout_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("stdout descriptor must reference a regular file")
        return await self._run(
            request,
            cancellation,
            stdout_descriptor=stdout_descriptor,
        )

    async def _run(
        self,
        request: CommandRequest,
        cancellation: CancellationToken,
        *,
        stdout_descriptor: int | None,
    ) -> ProcessResult:
        loop = asyncio.get_running_loop()
        request_deadline = loop.time() + max(0.0, request.timeout_seconds)
        try:
            spec = self._commands[request.command_id]
        except KeyError as error:
            raise PluginUnavailableError("command_id is not locally allowlisted") from error
        if spec.output_mode == CommandOutputMode.CALLER_FILE_DESCRIPTOR:
            if stdout_descriptor is None:
                raise PluginUnavailableError(
                    "allowlisted command requires a pre-opened stdout descriptor"
                )
        elif stdout_descriptor is not None:
            raise ValueError("allowlisted command does not permit stdout redirection")
        parameters = spec.argument_model.model_validate(dict(request.arguments))
        argv = spec.build_argv(parameters)
        if not spec.executable.is_absolute():
            raise ValueError("allowlisted executable must use an absolute path")
        if not spec.cwd.is_absolute():
            raise ValueError("allowlisted working directory must use an absolute path")
        resolved = spec.executable.resolve(strict=True)
        if resolved != spec.executable or not resolved.is_file():
            raise ValueError("allowlisted executable path changed during resolution")
        before = resolved.stat()
        if spec.executable_identity is not None:
            actual_identity = ExecutableIdentity.from_stat(before)
            mode = stat.S_IMODE(before.st_mode)
            if (
                actual_identity != spec.executable_identity
                or not stat.S_ISREG(before.st_mode)
                or bool(before.st_mode & (stat.S_ISUID | stat.S_ISGID))
                or bool(mode & 0o022)
                or not bool(mode & 0o111)
                or not os.access(resolved, os.X_OK)
            ):
                raise PluginUnavailableError(
                    "allowlisted executable identity or permissions changed"
                )
        if spec.expected_sha256 is not None:
            actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
            if actual != spec.expected_sha256:
                raise PluginUnavailableError("allowlisted executable integrity mismatch")
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
            if stdout_descriptor is None:
                spawn_operation = self.start_process(
                    spec,
                    argv,
                    environment,
                    execution_token=execution_token,
                    deadline=request_deadline,
                )
            else:
                spawn_operation = self.start_process(
                    spec,
                    argv,
                    environment,
                    execution_token=execution_token,
                    deadline=request_deadline,
                    stdout_descriptor=stdout_descriptor,
                )
            spawn_task = self._create_managed_task(spawn_operation, managed)
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
            if fingerprint != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
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
                (
                    spawn_error,
                    spawn_cancellation,
                    spawn_timed_out,
                ) = await self._wait_for_protected_task(
                    spawn_task,
                    deadline=operation_deadline,
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
                    (
                        cleanup_task_error,
                        cancellation_error,
                        timed_out,
                    ) = await self._wait_for_protected_task(
                        cleanup,
                        deadline=operation_deadline,
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
                        (
                            drain_error,
                            drain_cancellation,
                            drain_timed_out,
                        ) = await self._wait_for_protected_task(
                            cleanup,
                            deadline=cleanup_deadline,
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

    async def _ensure_process_exit(self, process: asyncio.subprocess.Process) -> None:
        errors: list[BaseException] = []
        if process.returncode is None:
            try:
                process.kill()
            except (ProcessLookupError, OSError):
                pass
            except BaseException as error:
                errors.append(error)
            try:
                await process.wait()
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
                await self._run_cleanup_step(
                    self._ensure_process_exit(process),
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

    @staticmethod
    def _close_pipe_transports_only(process: asyncio.subprocess.Process) -> None:
        transport = getattr(process, "_transport", None)
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


@dataclass
class LinuxProcessContext:
    process: asyncio.subprocess.Process
    pid: int
    process_group_id: int
    session_id: int
    start_time: str
    pidfd: int
    cleanup_scope: LinuxCleanupScope = LinuxCleanupScope.LEADER_ONLY
    cgroup: LinuxCgroupExecution | None = None
    closed: bool = False
    term_sent: bool = False
    kill_sent: bool = False
    termination_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    cleanup_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    cleanup_complete: bool = False
    cleanup_error: BaseException | None = None
    cgroup_removed: bool = False

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        errors: list[BaseException] = []
        try:
            os.close(self.pidfd)
        except BaseException as error:
            errors.append(error)
        if self.cgroup is not None:
            try:
                self.cgroup.close()
            except BaseException as error:
                errors.append(error)
        if errors:
            for secondary in errors[1:]:
                errors[0].add_note(f"additional Linux process context close error: {secondary!r}")
            raise errors[0]


class LinuxSpawnState(str, Enum):
    RELEASE_NOT_SENT = "RELEASE_NOT_SENT"
    RELEASE_SENT = "RELEASE_SENT"
    TARGET_RUNNING_OR_EXEC_FAILED = "TARGET_RUNNING_OR_EXEC_FAILED"
    CLEANED = "CLEANED"


@dataclass
class LinuxSpawnHandshake:
    execution_token: object
    marker_read_descriptor: int | None
    marker_write_descriptor: int | None
    control_read_descriptor: int | None
    control_write_descriptor: int | None
    stdout_descriptor: int | None = None
    marker_transport: asyncio.ReadTransport | None = None
    process: asyncio.subprocess.Process | None = None
    context: LinuxProcessContext | None = None
    state: LinuxSpawnState = LinuxSpawnState.RELEASE_NOT_SENT
    release_sent: bool = False
    closed: bool = False

    @property
    def released(self) -> bool:
        return self.release_sent

    def close_parent_channels(self) -> BaseException | None:
        if self.closed:
            return None
        self.closed = True
        errors: list[BaseException] = []
        if self.marker_transport is not None:
            try:
                self.marker_transport.close()
            except BaseException as error:
                errors.append(error)
            self.marker_transport = None
        for name in (
            "marker_read_descriptor",
            "marker_write_descriptor",
            "control_read_descriptor",
            "control_write_descriptor",
        ):
            descriptor = cast(int | None, getattr(self, name))
            setattr(self, name, None)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError as error:
                    errors.append(error)
        if errors:
            for secondary in errors[1:]:
                errors[0].add_note(f"additional Linux handshake channel close error: {secondary!r}")
            return errors[0]
        return None


class LinuxProcessRunner(AllowlistedProcessRunner):
    _spawn_handshake_timeout_seconds = 5.0

    def __init__(
        self,
        commands: Mapping[str, CommandSpec],
        *,
        cgroup_manager: LinuxCgroupManager | None = None,
    ) -> None:
        super().__init__(commands)
        self._cgroup_manager = cgroup_manager
        self._contexts: dict[int, LinuxProcessContext] = {}
        self._handshakes: dict[object, LinuxSpawnHandshake] = {}

    @staticmethod
    def _start_time(pid: int) -> str | None:
        try:
            # comm may contain spaces and parentheses; fields after the final
            # ')' start at proc field 3, so field 22 is offset 19 here.
            text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
            return text[text.rfind(")") + 2 :].split()[19]
        except (OSError, IndexError):
            return None

    def _register(
        self,
        process: asyncio.subprocess.Process,
        *,
        pidfd: int,
        start_time: str,
        session_id: int,
        process_group_id: int,
        cleanup_scope: LinuxCleanupScope,
    ) -> LinuxProcessContext:
        context = LinuxProcessContext(
            process=process,
            pid=process.pid,
            process_group_id=process_group_id,
            session_id=session_id,
            start_time=start_time,
            pidfd=pidfd,
            cleanup_scope=cleanup_scope,
        )
        self._contexts[id(process)] = context
        return context

    def _context(self, process: asyncio.subprocess.Process) -> LinuxProcessContext:
        context = self._contexts.get(id(process))
        if context is None or context.process is not process:
            raise RuntimeError("Linux process ownership context is unavailable")
        return context

    async def start_process(
        self,
        spec: CommandSpec,
        argv: list[str],
        environment: dict[str, str],
        *,
        execution_token: object,
        deadline: float | None = None,
        stdout_descriptor: int | None = None,
    ) -> asyncio.subprocess.Process:
        if _PIDFD_OPEN is None or _PIDFD_SEND_SIGNAL is None:
            raise PluginUnavailableError("Linux pidfd process ownership is unavailable")
        if spec.linux_cleanup_scope is None:
            raise PluginUnavailableError("Linux cleanup scope is not registered")
        if spec.linux_cleanup_scope == LinuxCleanupScope.PROCESS_TREE:
            manager = self._cgroup_manager
            readiness = manager.readiness if manager is not None else None
            if readiness is None or not readiness.available:
                reason = readiness.reason if readiness is not None else "cgroup_v2_unavailable"
                raise PluginUnavailableError(
                    f"Linux process-tree containment is unavailable: {reason}"
                )
        loop = asyncio.get_running_loop()
        absolute_deadline = (
            loop.time() + self._spawn_handshake_timeout_seconds if deadline is None else deadline
        )
        marker_read, marker_write = os.pipe()
        control_read, control_write = os.pipe()
        os.set_inheritable(marker_write, True)
        os.set_inheritable(control_read, True)
        handshake = LinuxSpawnHandshake(
            execution_token=execution_token,
            marker_read_descriptor=marker_read,
            marker_write_descriptor=marker_write,
            control_read_descriptor=control_read,
            control_write_descriptor=control_write,
            stdout_descriptor=stdout_descriptor,
        )
        self._handshakes[execution_token] = handshake
        primary_error: BaseException | None = None
        guard_creation: asyncio.Task[asyncio.subprocess.Process] | None = None
        try:
            guard_creation = asyncio.create_task(self._spawn_guard(handshake))
            guard_creation.add_done_callback(self._consume_future_result)
            process = await self._await_spawn_stage(
                asyncio.shield(guard_creation),
                absolute_deadline,
                "guard creation",
            )
            handshake.process = process
            self._close_handshake_child_ends(handshake)
            reader, transport = await self._connect_marker_reader(handshake)
            handshake.marker_transport = transport
            nonce = secrets.token_hex(32)
            from wto_desktop_agent.platforms.linux import spawn_guard

            target = {
                "version": 1,
                "nonce": nonce,
                "executable": str(spec.executable),
                "argv": list(argv),
                "cwd": str(spec.cwd),
                "environment": environment,
            }
            control = handshake.control_write_descriptor
            if control is None:
                raise RuntimeError("spawn guard control channel is unavailable")
            await self._await_spawn_stage(
                self._write_stream_frame(control, spawn_guard.encode_frame(target)),
                absolute_deadline,
                "target payload",
            )
            marker_payload = await self._await_spawn_stage(
                self._read_stream_frame(reader),
                absolute_deadline,
                "identity marker",
            )
            marker = self._validate_guard_marker(marker_payload, nonce, process)
            before_open = self._start_time(process.pid)
            if before_open != marker[0]:
                raise RuntimeError("spawn guard start-time changed before pidfd acquisition")
            pidfd = _PIDFD_OPEN(process.pid)
            context: LinuxProcessContext | None = None
            try:
                after_open = self._start_time(process.pid)
                if process.returncode is not None or after_open != marker[0]:
                    raise RuntimeError("spawn guard identity changed during pidfd acquisition")
                _PIDFD_SEND_SIGNAL(pidfd, 0)
                context = self._register(
                    process,
                    pidfd=pidfd,
                    start_time=marker[0],
                    session_id=marker[1],
                    process_group_id=marker[2],
                    cleanup_scope=spec.linux_cleanup_scope,
                )
                handshake.context = context
            except BaseException:
                if context is None:
                    os.close(pidfd)
                raise
            await self._await_spawn_stage(
                self._before_guard_release(context),
                absolute_deadline,
                "release validation",
            )
            spawn_guard.write_frame(
                control,
                {"version": 1, "nonce": nonce, "command": "release"},
            )
            # write_frame returns only after the complete, PIPE_BUF-sized
            # release frame has been written. Record that irreversible fact
            # before close, logging, hooks, or any other fallible operation.
            handshake.release_sent = True
            handshake.state = LinuxSpawnState.RELEASE_SENT
            await self._after_guard_release_sent(context)
            handshake.control_write_descriptor = None
            os.close(control)
            handshake.state = LinuxSpawnState.TARGET_RUNNING_OR_EXEC_FAILED
            self._finish_handshake(handshake)
            return process
        except BaseException as error:
            primary_error = error
            creation_error = await self._recover_guard_creation(
                handshake,
                guard_creation,
                primary_error,
            )
            cleanup_error = await self._abort_handshake(handshake, absolute_deadline)
            if creation_error is not None:
                primary_error.add_note(
                    f"Linux guard creation cleanup incomplete: {creation_error!r}"
                )
            if cleanup_error is not None:
                primary_error.add_note(f"Linux spawn guard cleanup incomplete: {cleanup_error!r}")
            raise
        finally:
            if primary_error is not None:
                self._finish_handshake(handshake)

    async def _spawn_guard(self, handshake: LinuxSpawnHandshake) -> asyncio.subprocess.Process:
        marker_write = handshake.marker_write_descriptor
        control_read = handshake.control_read_descriptor
        if marker_write is None or control_read is None:
            raise RuntimeError("spawn guard child channels are unavailable")
        from wto_desktop_agent.platforms.linux import spawn_guard

        guard_path = Path(spawn_guard.__file__).resolve(strict=True)
        guard_environment = {
            key: value
            for key, value in os.environ.items()
            if key in {"LANG", "LC_ALL", "LC_CTYPE", "TZ"}
        }
        return await asyncio.create_subprocess_exec(
            sys.executable,
            str(guard_path),
            "--marker-fd",
            str(marker_write),
            "--control-fd",
            str(control_read),
            cwd="/",
            env=guard_environment,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=(
                handshake.stdout_descriptor
                if handshake.stdout_descriptor is not None
                else asyncio.subprocess.PIPE
            ),
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            pass_fds=(marker_write, control_read),
        )

    async def _before_guard_release(self, context: LinuxProcessContext) -> None:
        if context.cleanup_scope == LinuxCleanupScope.LEADER_ONLY:
            await asyncio.sleep(0)
            return
        manager = self._cgroup_manager
        if manager is None:
            raise PluginUnavailableError("Linux process-tree containment is unavailable")
        await asyncio.sleep(0)
        handle = manager.create_execution()
        # Register the handle before the first fallible attach operation so
        # cancellation and handshake abort can always recover the private leaf.
        context.cgroup = handle
        await asyncio.sleep(0)
        handle.attach_pid(context.pid)
        await asyncio.sleep(0)
        handle.verify_pid(context.pid)

    async def _after_guard_release_sent(self, context: LinuxProcessContext) -> None:
        del context
        await asyncio.sleep(0)

    async def _recover_guard_creation(
        self,
        handshake: LinuxSpawnHandshake,
        creation: asyncio.Task[asyncio.subprocess.Process] | None,
        primary_error: BaseException,
    ) -> BaseException | None:
        if creation is None or handshake.process is not None:
            return None
        try:
            process = await asyncio.wait_for(
                asyncio.shield(creation),
                timeout=self._spawn_handshake_timeout_seconds,
            )
        except TimeoutError:
            creation.add_done_callback(
                lambda task: self._cleanup_late_guard_creation(task, handshake)
            )
            return TimeoutError("spawn guard creation did not settle during cleanup")
        except BaseException as error:
            return None if error is primary_error else error
        handshake.process = process
        self._close_handshake_child_ends(handshake)
        return None

    def _cleanup_late_guard_creation(
        self,
        task: asyncio.Future[asyncio.subprocess.Process],
        handshake: LinuxSpawnHandshake,
    ) -> None:
        if task.cancelled():
            return
        try:
            process = task.result()
        except BaseException:
            return
        handshake.process = process
        try:
            self._close_handshake_child_ends(handshake)
        except OSError:
            pass
        handshake.close_parent_channels()
        waiter = asyncio.create_task(process.wait())
        waiter.add_done_callback(self._consume_future_result)

    async def _await_spawn_stage(
        self,
        awaitable: Awaitable[_T],
        deadline: float,
        stage: str,
    ) -> _T:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            if inspect.iscoroutine(awaitable):
                awaitable.close()
            raise TimeoutError(f"allowlisted process timed out during {stage}")
        try:
            return await asyncio.wait_for(awaitable, timeout=remaining)
        except TimeoutError as error:
            raise TimeoutError(f"allowlisted process timed out during {stage}") from error

    async def _connect_marker_reader(
        self, handshake: LinuxSpawnHandshake
    ) -> tuple[asyncio.StreamReader, asyncio.ReadTransport]:
        descriptor = handshake.marker_read_descriptor
        if descriptor is None:
            raise RuntimeError("spawn guard marker channel is unavailable")
        stream = os.fdopen(descriptor, "rb", buffering=0)
        handshake.marker_read_descriptor = None
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        try:
            transport, _ = await asyncio.get_running_loop().connect_read_pipe(
                lambda: protocol,
                stream,
            )
        except BaseException:
            stream.close()
            raise
        return reader, transport

    @staticmethod
    async def _read_stream_frame(reader: asyncio.StreamReader) -> dict[str, Any]:
        size = struct.unpack("!I", await reader.readexactly(4))[0]
        if size <= 0 or size > 4 * 1024 * 1024:
            raise ValueError("spawn guard marker size is invalid")
        decoded = json.loads((await reader.readexactly(size)).decode("utf-8"))
        if not isinstance(decoded, dict):
            raise ValueError("spawn guard marker must be an object")
        return decoded

    @staticmethod
    async def _write_stream_frame(descriptor: int, payload: bytes) -> None:
        loop = asyncio.get_running_loop()
        os.set_blocking(descriptor, False)
        view = memoryview(payload)
        while view:
            try:
                written = os.write(descriptor, view)
            except BlockingIOError:
                writable = loop.create_future()
                loop.add_writer(descriptor, writable.set_result, None)
                try:
                    await writable
                finally:
                    loop.remove_writer(descriptor)
                continue
            if written <= 0:
                raise BrokenPipeError("spawn guard control channel closed")
            view = view[written:]

    def _validate_guard_marker(
        self,
        marker: dict[str, Any],
        nonce: str,
        process: asyncio.subprocess.Process,
    ) -> tuple[str, int, int]:
        if set(marker) != {
            "version",
            "nonce",
            "pid",
            "start_time",
            "session_id",
            "process_group_id",
        }:
            raise ValueError("spawn guard marker fields are invalid")
        if marker.get("version") != 1 or marker.get("nonce") != nonce:
            raise ValueError("spawn guard marker nonce is invalid")
        if marker.get("pid") != process.pid or process.returncode is not None:
            raise RuntimeError("spawn guard process identity is invalid")
        start_time = marker.get("start_time")
        session_id = marker.get("session_id")
        process_group_id = marker.get("process_group_id")
        if not isinstance(start_time, str) or not start_time.isdigit():
            raise ValueError("spawn guard start-time is invalid")
        if session_id != process.pid or process_group_id != process.pid:
            raise RuntimeError("spawn guard session identity is invalid")
        return start_time, int(session_id), int(process_group_id)

    @staticmethod
    def _close_handshake_child_ends(handshake: LinuxSpawnHandshake) -> None:
        for name in ("marker_write_descriptor", "control_read_descriptor"):
            descriptor = cast(int | None, getattr(handshake, name))
            setattr(handshake, name, None)
            if descriptor is not None:
                os.close(descriptor)

    async def _abort_handshake(
        self,
        handshake: LinuxSpawnHandshake,
        deadline: float,
    ) -> BaseException | None:
        errors: list[BaseException] = []
        control = handshake.control_write_descriptor
        handshake.control_write_descriptor = None
        if control is not None:
            try:
                os.close(control)
            except OSError as error:
                errors.append(error)
        process = handshake.process
        context = handshake.context
        process_wait: asyncio.Task[int] | None = None
        if process is not None and handshake.released and context is not None:
            cleanup_deadline = asyncio.get_running_loop().time() + self._cleanup_grace_seconds
            operation_deadline = max(
                asyncio.get_running_loop().time(),
                cleanup_deadline - self._cleanup_force_close_reserve_seconds,
            )
            cleanup = asyncio.create_task(
                self._cleanup_process(
                    process,
                    [],
                    terminate=True,
                    deadline=cleanup_deadline,
                )
            )
            cleanup.add_done_callback(self._consume_future_result)
            cleanup_error, cleanup_cancellation, timed_out = await self._wait_for_protected_task(
                cleanup,
                deadline=operation_deadline,
            )
            if timed_out:
                cleanup.cancel()
                try:
                    self._force_cleanup_process(process)
                except BaseException as error:
                    errors.append(error)
                errors.append(TimeoutError("released process cleanup exceeded its deadline"))
                drain_error, drain_cancellation, drain_timed_out = (
                    await self._wait_for_protected_task(
                        cleanup,
                        deadline=cleanup_deadline,
                    )
                )
                cleanup_cancellation = cleanup_cancellation or drain_cancellation
                if drain_timed_out:
                    errors.append(TimeoutError("released process cleanup task remained pending"))
                elif drain_error is not None and not isinstance(
                    drain_error, asyncio.CancelledError
                ):
                    errors.append(drain_error)
            elif cleanup_error is not None:
                errors.append(cleanup_error)
            if cleanup_cancellation is not None:
                errors.append(cleanup_cancellation)
        elif process is not None:
            del deadline
            wait_deadline = (
                asyncio.get_running_loop().time() + self._spawn_handshake_timeout_seconds
            )
            process_wait = asyncio.create_task(process.wait())
            process_wait.add_done_callback(self._consume_future_result)
            wait_error, wait_cancellation, wait_timed_out = await self._wait_for_protected_task(
                process_wait,
                deadline=wait_deadline,
            )
            if wait_timed_out:
                errors.append(TimeoutError("spawn guard process wait timed out"))
            elif wait_error is not None:
                errors.append(wait_error)
            if wait_cancellation is not None:
                errors.append(wait_cancellation)
            try:
                if process.returncode is None:
                    self._close_pipe_transports_only(process)
                else:
                    self._close_process_pipes(process)
            except BaseException as error:
                errors.append(error)
        if (
            context is not None
            and context.cleanup_scope == LinuxCleanupScope.PROCESS_TREE
            and context.cgroup is not None
            and not context.cgroup_removed
        ):
            try:
                await self._finish_cgroup(context)
                if process is not None and process.returncode is None:
                    if process_wait is None:
                        process_wait = asyncio.create_task(process.wait())
                        process_wait.add_done_callback(self._consume_future_result)
                    wait_error, wait_cancellation, wait_timed_out = (
                        await self._wait_for_protected_task(
                            process_wait,
                            deadline=(
                                asyncio.get_running_loop().time()
                                + self._spawn_handshake_timeout_seconds
                            ),
                        )
                    )
                    if wait_timed_out:
                        raise TimeoutError("cgroup process wait timed out")
                    if wait_error is not None:
                        raise wait_error
                    if wait_cancellation is not None:
                        errors.append(wait_cancellation)
            except BaseException as error:
                errors.append(error)
        if process_wait is not None and not process_wait.done():
            process_wait.cancel()
            drain_error, drain_cancellation, drain_timed_out = await self._wait_for_protected_task(
                process_wait,
                deadline=(
                    asyncio.get_running_loop().time() + self._spawn_handshake_timeout_seconds
                ),
            )
            if drain_timed_out:
                errors.append(TimeoutError("spawn guard process waiter remained pending"))
            elif drain_error is not None and not isinstance(drain_error, asyncio.CancelledError):
                errors.append(drain_error)
            if drain_cancellation is not None:
                errors.append(drain_cancellation)
        if context is not None and not context.closed:
            self._contexts.pop(id(context.process), None)
            try:
                context.close()
            except BaseException as error:
                errors.append(error)
        channel_error = handshake.close_parent_channels()
        if channel_error is not None:
            errors.append(channel_error)
        handshake.state = LinuxSpawnState.CLEANED
        if errors:
            for secondary in errors[1:]:
                errors[0].add_note(f"additional Linux handshake cleanup error: {secondary!r}")
        return errors[0] if errors else None

    def _finish_handshake(self, handshake: LinuxSpawnHandshake) -> None:
        channel_error = handshake.close_parent_channels()
        if self._handshakes.get(handshake.execution_token) is handshake:
            self._handshakes.pop(handshake.execution_token, None)
        if channel_error is not None:
            raise channel_error

    def _force_cleanup_spawn(self, execution_token: object) -> None:
        handshake = self._handshakes.get(execution_token)
        if handshake is not None:
            channel_error = handshake.close_parent_channels()
            if channel_error is not None:
                raise channel_error

    def after_finish(self, process: asyncio.subprocess.Process) -> None:
        # Context lifetime ends in _force_cleanup_process, after all bounded
        # waits. Keeping it here prevents any fallback from reopening by PID.
        self._context(process)

    async def wait_after_finish(self, process: asyncio.subprocess.Process) -> None:
        context = self._context(process)
        if context.cleanup_scope == LinuxCleanupScope.PROCESS_TREE:
            await self._finish_cgroup(context)

    async def _finish_cgroup(self, context: LinuxProcessContext) -> None:
        handle = context.cgroup
        if handle is None:
            raise RuntimeError("cleanup_cgroup_context_unavailable")
        if context.cgroup_removed:
            return
        if handle.is_populated():
            handle.kill_remaining()
        deadline = asyncio.get_running_loop().time() + 2.0
        await handle.wait_empty(deadline)
        handle.remove_empty()
        context.cgroup_removed = True

    def _identity_matches(self, context: LinuxProcessContext) -> bool:
        if (
            context.closed
            or context.process.pid != context.pid
            or context.process.returncode is not None
        ):
            return False
        if _PIDFD_SEND_SIGNAL is None:
            return False
        try:
            _PIDFD_SEND_SIGNAL(context.pidfd, 0)
            return True
        except (ProcessLookupError, OSError):
            return False

    def _signal_context(self, context: LinuxProcessContext, signal_number: int) -> None:
        if not self._identity_matches(context):
            raise RuntimeError("cleanup_identity_lost")
        if _PIDFD_SEND_SIGNAL is None:
            raise RuntimeError("cleanup_pidfd_signalling_unavailable")
        try:
            _PIDFD_SEND_SIGNAL(context.pidfd, signal_number)
        except (ProcessLookupError, OSError) as error:
            raise RuntimeError("cleanup_identity_lost") from error

    async def _cleanup_process(
        self,
        process: asyncio.subprocess.Process,
        managed: list[asyncio.Future[Any]],
        *,
        terminate: bool,
        deadline: float,
    ) -> None:
        context = self._contexts.get(id(process))
        if context is None or context.process is not process:
            if bool(getattr(process, "_wto_force_cleanup_started", False)):
                return
            raise RuntimeError("cleanup_identity_lost")
        async with context.cleanup_lock:
            if context.cleanup_complete:
                if context.cleanup_error is not None:
                    raise context.cleanup_error
                return
            try:
                await super()._cleanup_process(
                    process,
                    managed,
                    terminate=terminate,
                    deadline=deadline,
                )
            except BaseException as error:
                context.cleanup_error = error
                raise
            finally:
                context.cleanup_complete = True

    async def _ensure_process_exit(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is None:
            await self.terminate(process)
        if process.returncode is None:
            await process.wait()

    def _force_cleanup_process(self, process: asyncio.subprocess.Process) -> None:
        marker_name = "_wto_force_cleanup_started"
        if bool(getattr(process, marker_name, False)):
            return
        setattr(process, marker_name, True)
        context = self._contexts.get(id(process))
        errors: list[BaseException] = []
        try:
            if context is None or context.process is not process:
                if process.returncode is None:
                    errors.append(RuntimeError("cleanup_identity_lost"))
            elif process.returncode is None:
                if context.cleanup_scope == LinuxCleanupScope.PROCESS_TREE:
                    try:
                        if context.cgroup is None:
                            raise RuntimeError("cleanup_cgroup_context_unavailable")
                        if context.cgroup.is_populated() and not context.kill_sent:
                            context.cgroup.kill_remaining()
                            context.kill_sent = True
                        errors.append(RuntimeError("cleanup_process_exit_unconfirmed"))
                    except BaseException as error:
                        errors.append(error)
                elif self._identity_matches(context):
                    try:
                        if not context.kill_sent:
                            self._signal_context(context, _SIGKILL)
                            context.kill_sent = True
                        errors.append(RuntimeError("cleanup_process_exit_unconfirmed"))
                    except BaseException as error:
                        errors.append(error)
                else:
                    errors.append(RuntimeError("cleanup_identity_lost"))

            try:
                if process.returncode is None:
                    # Closing the parent subprocess transport can call kill()
                    # by numeric PID. Only close independent pipe transports.
                    self._close_pipe_transports_only(process)
                else:
                    self._close_process_pipes(process)
            except BaseException as error:
                errors.append(error)
        finally:
            if context is not None and context.process is process:
                self._contexts.pop(id(process), None)
                try:
                    context.close()
                except BaseException as error:
                    errors.append(error)
        if errors:
            raise errors[0]

    async def terminate(self, process: asyncio.subprocess.Process) -> None:
        context = self._context(process)
        async with context.termination_lock:
            if process.returncode is not None:
                if context.cleanup_scope == LinuxCleanupScope.PROCESS_TREE:
                    await self._finish_cgroup(context)
                return
            if not context.term_sent:
                self._signal_context(context, _SIGTERM)
                context.term_sent = True
            try:
                await asyncio.wait_for(asyncio.shield(process.wait()), timeout=2.0)
            except TimeoutError:
                pass
            if context.cleanup_scope == LinuxCleanupScope.PROCESS_TREE:
                handle = context.cgroup
                if handle is None:
                    raise RuntimeError("cleanup_cgroup_context_unavailable")
                if handle.is_populated():
                    handle.kill_remaining()
                    context.kill_sent = True
                deadline = asyncio.get_running_loop().time() + 2.0
                await handle.wait_empty(deadline)
                if process.returncode is None:
                    await process.wait()
                return
            if process.returncode is not None:
                return
            if not context.kill_sent:
                self._signal_context(context, _SIGKILL)
                context.kill_sent = True
            await process.wait()
