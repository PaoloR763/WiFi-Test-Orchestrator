from __future__ import annotations

import asyncio
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict

from wto_desktop_agent.platforms.common import AllowlistedProcessRunner, CommandSpec
from wto_desktop_agent.ports.platform import CommandRequest
from wto_desktop_agent.ports.plugins import CancellationToken


class _NoArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _PipeTransport:
    def __init__(self) -> None:
        self.closed = False
        self.close_calls = 0
        self.close_error: BaseException | None = None

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class _ProcessTransport:
    def __init__(self, kill_process: Callable[[], None]) -> None:
        self.pipes = {1: _PipeTransport(), 2: _PipeTransport()}
        self.closed = False
        self.close_calls = 0
        self._kill_process = kill_process

    def get_pipe_transport(self, file_descriptor: int) -> _PipeTransport | None:
        return self.pipes.get(file_descriptor)

    def close(self) -> None:
        self.close_calls += 1
        errors: list[BaseException] = []
        for pipe in self.pipes.values():
            try:
                pipe.close()
            except BaseException as error:
                errors.append(error)
        self._kill_process()
        self.closed = True
        if errors:
            raise errors[0]


class _FakeProcess:
    def __init__(self) -> None:
        self.pid = 4100
        self.returncode: int | None = None
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self._transport = _ProcessTransport(
            lambda: self.kill() if self.returncode is None else None
        )
        self._finished = asyncio.Event()
        self.wait_calls = 0
        self.kill_calls = 0
        self.wait_error_once: BaseException | None = None

    async def wait(self) -> int:
        self.wait_calls += 1
        if self.wait_error_once is not None:
            error = self.wait_error_once
            self.wait_error_once = None
            raise error
        await self._finished.wait()
        assert self.returncode is not None
        return self.returncode

    def finish(self, returncode: int = -1) -> None:
        if self.returncode is None:
            self.returncode = returncode
            self.stdout.feed_eof()
            self.stderr.feed_eof()
            self._finished.set()

    def kill(self) -> None:
        self.kill_calls += 1
        self.finish()


class _InstrumentedRunner(AllowlistedProcessRunner):
    def __init__(self, spec: CommandSpec, process: _FakeProcess) -> None:
        super().__init__({spec.command_id: spec})
        self.process = process
        self.spawned = False
        self.after_start_error: BaseException | None = None
        self.after_start_delay_seconds = 0.0
        self.after_finish_error: BaseException | None = None
        self.terminate_calls = 0
        self.after_start_calls = 0
        self.after_finish_calls = 0
        self.managed_tasks: list[asyncio.Future[Any]] = []
        self.terminate_started = asyncio.Event()
        self.allow_terminate = asyncio.Event()
        self.after_start_completed = asyncio.Event()
        self.block_termination = False
        self.block_spawn = False
        self.spawn_started = asyncio.Event()
        self.allow_spawn = asyncio.Event()
        self.block_readers = False
        self.reader_started = asyncio.Event()

    async def start_process(
        self,
        spec: CommandSpec,
        argv: list[str],
        environment: dict[str, str],
        *,
        execution_token: object,
        deadline: float | None = None,
    ) -> asyncio.subprocess.Process:
        del spec, argv, environment, execution_token, deadline
        self.spawned = True
        self.spawn_started.set()
        if self.block_spawn:
            await self.allow_spawn.wait()
        return self.process  # type: ignore[return-value]

    def after_start(self, process: asyncio.subprocess.Process) -> None:
        del process
        self.after_start_calls += 1
        self.after_start_completed.set()
        if self.after_start_delay_seconds:
            time.sleep(self.after_start_delay_seconds)
        if self.after_start_error is not None:
            raise self.after_start_error

    async def terminate(self, process: asyncio.subprocess.Process) -> None:
        del process
        self.terminate_calls += 1
        self.terminate_started.set()
        if self.block_termination:
            await self.allow_terminate.wait()
        self.process.finish()
        await self.process.wait()

    def after_finish(self, process: asyncio.subprocess.Process) -> None:
        del process
        self.after_finish_calls += 1
        if self.after_finish_error is not None:
            raise self.after_finish_error

    def _create_managed_task(
        self, awaitable: Any, managed: list[asyncio.Future[Any]]
    ) -> asyncio.Task[Any]:
        task = super()._create_managed_task(awaitable, managed)
        self.managed_tasks.append(task)
        return task

    async def _read_limited(self, stream: asyncio.StreamReader | None, limit: int) -> bytes:
        if self.block_readers:
            self.reader_started.set()
            await asyncio.Event().wait()
        return await super()._read_limited(stream, limit)


def _command_spec() -> CommandSpec:
    executable = Path(sys.executable).resolve()
    return CommandSpec(
        command_id="controlled.lifecycle",
        executable=executable,
        argument_model=_NoArguments,
        build_argv=lambda _: [],
        cwd=executable.parent,
        environment={},
    )


def _small_output_command_spec() -> CommandSpec:
    spec = _command_spec()
    return CommandSpec(
        command_id=spec.command_id,
        executable=spec.executable,
        argument_model=spec.argument_model,
        build_argv=spec.build_argv,
        cwd=spec.cwd,
        environment=spec.environment,
        max_output_bytes=1,
    )


def _request(timeout_seconds: float = 5.0) -> CommandRequest:
    return CommandRequest(
        command_id="controlled.lifecycle",
        arguments={},
        timeout_seconds=timeout_seconds,
    )


@pytest.mark.asyncio
async def test_success_runs_after_finish_once_without_termination() -> None:
    spec = _command_spec()
    process = _FakeProcess()
    process.finish(0)
    runner = _InstrumentedRunner(spec, process)

    result = await runner.run(_request(), CancellationToken())

    assert result.return_code == 0
    assert runner.terminate_calls == 0
    assert runner.after_finish_calls == 1
    assert all(managed.done() for managed in runner.managed_tasks)


@pytest.mark.asyncio
async def test_post_spawn_stat_error_runs_complete_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _command_spec()
    process = _FakeProcess()
    runner = _InstrumentedRunner(spec, process)
    original_stat = Path.stat
    sentinel = OSError("controlled post-spawn stat failure")

    def controlled_stat(path: Path, *args: object, **kwargs: object) -> Any:
        if runner.spawned and path == spec.executable:
            raise sentinel
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", controlled_stat)

    with pytest.raises(OSError) as raised:
        await runner.run(_request(), CancellationToken())

    assert raised.value is sentinel
    assert runner.terminate_calls == 1
    assert runner.after_finish_calls == 1
    assert process.returncode == -1
    assert all(pipe.closed for pipe in process._transport.pipes.values())


@pytest.mark.asyncio
async def test_after_start_error_preserves_primary_error_and_cleans_once() -> None:
    spec = _command_spec()
    process = _FakeProcess()
    runner = _InstrumentedRunner(spec, process)
    primary = RuntimeError("controlled after_start failure")
    runner.after_start_error = primary
    runner.after_finish_error = RuntimeError("controlled after_finish failure")

    with pytest.raises(RuntimeError) as raised:
        await runner.run(_request(), CancellationToken())

    assert raised.value is primary
    assert any("cleanup also failed" in note for note in getattr(primary, "__notes__", ()))
    assert runner.terminate_calls == 1
    assert runner.after_start_calls == 1
    assert runner.after_finish_calls == 1
    assert all(task.done() for task in runner.managed_tasks)


@pytest.mark.asyncio
async def test_after_start_consumes_the_original_request_deadline() -> None:
    spec = _command_spec()
    process = _FakeProcess()
    runner = _InstrumentedRunner(spec, process)
    runner.after_start_delay_seconds = 0.06

    with pytest.raises(TimeoutError, match="start finalization"):
        await runner.run(_request(0.02), CancellationToken())

    assert runner.after_start_calls == 1
    assert runner.terminate_calls == 1
    assert runner.after_finish_calls == 1
    assert process.returncode == -1
    assert all(task.done() for task in runner.managed_tasks)


@pytest.mark.asyncio
async def test_managed_task_creation_error_awaits_existing_tasks_and_cleans_once() -> None:
    spec = _command_spec()
    process = _FakeProcess()
    runner = _InstrumentedRunner(spec, process)
    original_create = runner._create_managed_task
    calls = 0
    sentinel = RuntimeError("controlled task creation failure")

    def fail_second_task(awaitable: Any, managed: list[asyncio.Future[Any]]) -> asyncio.Task[Any]:
        nonlocal calls
        calls += 1
        if calls == 3:
            if hasattr(awaitable, "close"):
                awaitable.close()
            raise sentinel
        return original_create(awaitable, managed)

    runner._create_managed_task = fail_second_task  # type: ignore[method-assign]

    with pytest.raises(RuntimeError) as raised:
        await runner.run(_request(), CancellationToken())

    assert raised.value is sentinel
    assert runner.terminate_calls == 1
    assert runner.after_finish_calls == 1
    assert all(task.done() for task in runner.managed_tasks)


@pytest.mark.asyncio
async def test_external_cancellation_and_second_cancel_wait_for_complete_cleanup() -> None:
    spec = _command_spec()
    process = _FakeProcess()
    runner = _InstrumentedRunner(spec, process)
    runner.block_termination = True
    task = asyncio.create_task(runner.run(_request(), CancellationToken()))
    await runner.after_start_completed.wait()

    task.cancel()
    await runner.terminate_started.wait()
    task.cancel()
    runner.allow_terminate.set()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert runner.terminate_calls == 1
    assert runner.after_finish_calls == 1
    assert process.returncode == -1
    assert process.stdout.at_eof()
    assert process.stderr.at_eof()
    assert all(pipe.closed for pipe in process._transport.pipes.values())
    assert all(managed.done() for managed in runner.managed_tasks)


@pytest.mark.asyncio
async def test_external_cancellation_during_blocked_spawn_is_bounded() -> None:
    spec = _command_spec()
    process = _FakeProcess()
    runner = _InstrumentedRunner(spec, process)
    runner._cleanup_grace_seconds = 0.2
    runner._cleanup_force_close_reserve_seconds = 0.02
    runner.block_spawn = True
    task = asyncio.create_task(runner.run(_request(), CancellationToken()))
    await runner.spawn_started.wait()

    started = time.monotonic()
    task.cancel()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=0.5)

    assert time.monotonic() - started < 0.5
    assert runner.terminate_calls == 0
    assert runner.after_finish_calls == 0
    assert all(managed.done() for managed in runner.managed_tasks)


@pytest.mark.asyncio
async def test_request_timeout_includes_blocked_spawn() -> None:
    spec = _command_spec()
    process = _FakeProcess()
    runner = _InstrumentedRunner(spec, process)
    runner._cleanup_grace_seconds = 0.2
    runner._cleanup_force_close_reserve_seconds = 0.02
    runner.block_spawn = True

    started = time.monotonic()
    with pytest.raises(TimeoutError, match="timed out during spawn"):
        await asyncio.wait_for(
            runner.run(_request(0.05), CancellationToken()),
            timeout=0.5,
        )

    assert time.monotonic() - started < 0.5
    assert runner.terminate_calls == 0
    assert runner.after_finish_calls == 0
    assert all(managed.done() for managed in runner.managed_tasks)


@pytest.mark.asyncio
async def test_cleanup_grace_force_closes_blocked_reader_and_termination() -> None:
    spec = _command_spec()
    process = _FakeProcess()
    runner = _InstrumentedRunner(spec, process)
    runner._cleanup_grace_seconds = 0.2
    runner._cleanup_force_close_reserve_seconds = 0.05
    runner.block_readers = True
    runner.block_termination = True

    started = time.monotonic()
    with pytest.raises(TimeoutError, match="allowlisted process timed out"):
        await asyncio.wait_for(
            runner.run(_request(0.05), CancellationToken()),
            timeout=0.5,
        )

    assert time.monotonic() - started < 0.5
    assert runner.reader_started.is_set()
    assert runner.terminate_calls == 1
    assert runner.after_finish_calls == 1
    assert process.kill_calls == 1
    assert process.returncode == -1
    assert process._transport.closed
    assert process._transport.close_calls == 1
    assert all(pipe.close_calls == 1 for pipe in process._transport.pipes.values())
    assert all(managed.done() for managed in runner.managed_tasks)


@pytest.mark.asyncio
async def test_reader_error_terminates_process_and_awaits_every_task() -> None:
    spec = _small_output_command_spec()
    process = _FakeProcess()
    process.stdout.feed_data(b"too-large")
    runner = _InstrumentedRunner(spec, process)

    with pytest.raises(RuntimeError, match="output limit exceeded"):
        await runner.run(_request(), CancellationToken())

    assert runner.terminate_calls == 1
    assert runner.after_finish_calls == 1
    assert all(managed.done() for managed in runner.managed_tasks)


@pytest.mark.asyncio
async def test_wait_error_and_pipe_close_error_preserve_primary_and_finish_tasks() -> None:
    spec = _command_spec()
    process = _FakeProcess()
    primary = RuntimeError("controlled process wait failure")
    process.wait_error_once = primary
    process._transport.pipes[1].close_error = RuntimeError("controlled pipe close failure")
    runner = _InstrumentedRunner(spec, process)

    with pytest.raises(RuntimeError) as raised:
        await runner.run(_request(), CancellationToken())

    assert raised.value is primary
    assert any("cleanup also failed" in note for note in getattr(primary, "__notes__", ()))
    assert runner.terminate_calls == 1
    assert runner.after_finish_calls == 1
    assert all(pipe.closed for pipe in process._transport.pipes.values())
    assert all(managed.done() for managed in runner.managed_tasks)


@pytest.mark.asyncio
async def test_cleanup_task_factory_error_uses_emergency_shielded_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _command_spec()
    process = _FakeProcess()
    runner = _InstrumentedRunner(spec, process)
    primary = RuntimeError("controlled after_start failure")
    task_factory_error = RuntimeError("controlled cleanup task factory failure")
    runner.after_start_error = primary
    loop = asyncio.get_running_loop()
    original_create_task = loop.create_task
    failed = False

    def controlled_create_task(awaitable: Any, *args: Any, **kwargs: Any) -> asyncio.Task[Any]:
        nonlocal failed
        code = getattr(awaitable, "cr_code", None)
        if not failed and getattr(code, "co_name", "") == "_cleanup_process":
            failed = True
            raise task_factory_error
        return original_create_task(awaitable, *args, **kwargs)

    monkeypatch.setattr(loop, "create_task", controlled_create_task)

    with pytest.raises(RuntimeError) as raised:
        await runner.run(_request(), CancellationToken())

    assert raised.value is primary
    assert any("cleanup also failed" in note for note in getattr(primary, "__notes__", ()))
    assert runner.terminate_calls == 1
    assert runner.after_finish_calls == 1
    assert process.returncode == -1
    assert all(managed.done() for managed in runner.managed_tasks)
