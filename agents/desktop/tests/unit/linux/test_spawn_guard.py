from __future__ import annotations

import asyncio
import inspect
import os
import signal
import struct
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict

import wto_desktop_agent.platforms.common as common
from wto_desktop_agent.domain.errors import PluginUnavailableError
from wto_desktop_agent.platforms.common import (
    CommandSpec,
    LinuxCleanupScope,
    LinuxProcessContext,
    LinuxProcessRunner,
    LinuxSpawnState,
)
from wto_desktop_agent.platforms.linux import spawn_guard
from wto_desktop_agent.ports.platform import CommandRequest
from wto_desktop_agent.ports.plugins import CancellationToken

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux pidfd semantics")


class EmptyArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _spec(
    tmp_path: Path,
    argv: list[str],
    executable: Path | None = None,
    *,
    cleanup_scope: LinuxCleanupScope = LinuxCleanupScope.LEADER_ONLY,
) -> CommandSpec:
    target = (executable or Path(sys.executable)).resolve(strict=True)
    return CommandSpec(
        command_id="guard.test",
        executable=target,
        argument_model=EmptyArguments,
        build_argv=lambda _value: list(argv),
        cwd=tmp_path,
        environment={"PYTHONDONTWRITEBYTECODE": "1"},
        max_output_bytes=4096,
        linux_cleanup_scope=cleanup_scope,
    )


def _request(timeout: float = 5.0) -> CommandRequest:
    return CommandRequest(command_id="guard.test", arguments={}, timeout_seconds=timeout)


async def _wait_for_path(path: Path) -> None:
    for _ in range(500):
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError("target marker was not created")


class _FakeCgroupHandle:
    def __init__(self, events: list[str]) -> None:
        self.path = Path("/sys/fs/cgroup/fake/wto-exec-test")
        self.events = events
        self.pid: int | None = None
        self.populated = False
        self.closed = False

    def attach_pid(self, pid: int) -> None:
        self.events.append("attach")
        self.pid = pid
        self.populated = True

    def verify_pid(self, pid: int) -> None:
        assert pid == self.pid
        self.events.append("verify")

    def kill_remaining(self) -> None:
        self.events.append("cgroup.kill")
        self.populated = False

    def is_populated(self) -> bool:
        return self.populated

    async def wait_empty(self, deadline_monotonic: float) -> None:
        del deadline_monotonic
        self.events.append("wait_empty")
        if self.populated:
            raise RuntimeError("fake cgroup remained populated")

    def remove_empty(self) -> None:
        if self.populated:
            raise RuntimeError("fake cgroup is populated")
        self.events.append("remove")

    def close(self) -> None:
        if not self.closed:
            self.events.append("close")
            self.closed = True


class _FakeCgroupManager:
    def __init__(self, events: list[str], *, available: bool = True) -> None:
        self.events = events
        self.handle = _FakeCgroupHandle(events)
        self._available = available

    @property
    def readiness(self) -> object:
        return type(
            "Readiness",
            (),
            {
                "available": self._available,
                "reason": None if self._available else "subtree_not_delegated",
            },
        )()

    def create_execution(self) -> _FakeCgroupHandle:
        self.events.append("create")
        return self.handle


@pytest.mark.asyncio
async def test_process_tree_is_attached_and_verified_before_guard_release(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    manager = _FakeCgroupManager(events)

    class RecordingReleaseRunner(LinuxProcessRunner):
        async def _after_guard_release_sent(self, context: LinuxProcessContext) -> None:
            assert context.cgroup is manager.handle
            events.append("release")

    spec = _spec(
        tmp_path,
        ["-c", "pass"],
        cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
    )
    runner = RecordingReleaseRunner(  # type: ignore[arg-type]
        {spec.command_id: spec},
        cgroup_manager=manager,
    )

    result = await runner.run(_request(), CancellationToken())

    assert result.return_code == 0
    assert events.index("create") < events.index("attach") < events.index("verify")
    assert events.index("verify") < events.index("release")
    assert events[-3:] == ["wait_empty", "remove", "close"]
    assert events.count("remove") == 1


@pytest.mark.asyncio
async def test_process_tree_fails_before_spawn_without_delegated_cgroup(
    tmp_path: Path,
) -> None:
    spec = _spec(
        tmp_path,
        ["-c", "pass"],
        cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
    )
    manager = _FakeCgroupManager([], available=False)
    runner = LinuxProcessRunner(  # type: ignore[arg-type]
        {spec.command_id: spec},
        cgroup_manager=manager,
    )

    async def forbidden_spawn(_handshake: object) -> asyncio.subprocess.Process:
        raise AssertionError("spawn guard must not start without cgroup containment")

    runner._spawn_guard = forbidden_spawn  # type: ignore[method-assign]

    with pytest.raises(PluginUnavailableError, match="subtree_not_delegated"):
        await runner.run(_request(), CancellationToken())


@pytest.mark.asyncio
async def test_cancellation_after_cgroup_creation_cleans_leaf_without_release(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    cancellation = CancellationToken()

    class CancellingManager(_FakeCgroupManager):
        def create_execution(self) -> _FakeCgroupHandle:
            handle = super().create_execution()
            cancellation.cancel()
            return handle

    target_marker = tmp_path / "target-must-not-run"
    code = f"from pathlib import Path;Path({str(target_marker)!r}).write_text('bad')"
    spec = _spec(
        tmp_path,
        ["-c", code],
        cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
    )
    runner = LinuxProcessRunner(  # type: ignore[arg-type]
        {spec.command_id: spec},
        cgroup_manager=CancellingManager(events),
    )

    with pytest.raises(asyncio.CancelledError):
        await runner.run(_request(), cancellation)

    assert "release" not in events
    assert not target_marker.exists()
    assert events.count("remove") == 1
    assert events.count("close") == 1


@pytest.mark.asyncio
async def test_cancellation_before_cgroup_creation_has_no_false_cleanup_failure(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    manager = _FakeCgroupManager(events)
    entered = asyncio.Event()

    class PausedBeforeContainmentRunner(LinuxProcessRunner):
        async def _before_guard_release(self, context: LinuxProcessContext) -> None:
            del context
            entered.set()
            await asyncio.Event().wait()

    spec = _spec(
        tmp_path,
        ["-c", "raise AssertionError('target must remain blocked')"],
        cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
    )
    runner = PausedBeforeContainmentRunner(  # type: ignore[arg-type]
        {spec.command_id: spec},
        cgroup_manager=manager,
    )
    cancellation = CancellationToken()
    running = asyncio.create_task(runner.run(_request(), cancellation))
    await asyncio.wait_for(entered.wait(), timeout=2)
    cancellation.cancel()

    with pytest.raises(asyncio.CancelledError) as raised:
        await running

    assert "create" not in events
    assert not any(
        "cleanup_cgroup_context_unavailable" in note
        for note in getattr(raised.value, "__notes__", ())
    )
    assert not runner._contexts
    assert not runner._handshakes


@pytest.mark.asyncio
async def test_guard_publishes_identity_and_pidfd_before_releasing_immediate_target(
    tmp_path: Path,
) -> None:
    target_marker = tmp_path / "target-ran"
    release = asyncio.Event()
    observed = asyncio.Event()

    class InspectingRunner(LinuxProcessRunner):
        context: LinuxProcessContext | None = None

        async def _before_guard_release(self, context: LinuxProcessContext) -> None:
            self.context = context
            observed.set()
            await release.wait()

    code = f"from pathlib import Path;Path({str(target_marker)!r}).write_text('ran')"
    spec = _spec(tmp_path, ["-c", code])
    runner = InspectingRunner({spec.command_id: spec})
    running = asyncio.create_task(runner.run(_request(), CancellationToken()))
    await asyncio.wait_for(observed.wait(), timeout=2)

    context = runner.context
    assert context is not None
    assert context.process.returncode is None
    assert context.pid == context.process.pid == context.session_id == context.process_group_id
    assert runner._start_time(context.pid) == context.start_time
    assert context.pidfd >= 0
    assert not target_marker.exists()

    release.set()
    result = await running
    assert result.return_code == 0
    assert target_marker.read_text(encoding="utf-8") == "ran"
    assert context.closed
    assert not runner._contexts


@pytest.mark.asyncio
async def test_failure_after_release_uses_pidfd_and_preserves_primary_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ready = tmp_path / "released-target-ready"
    release_error = RuntimeError("controlled failure after release")

    class FailingAfterReleaseRunner(LinuxProcessRunner):
        context: LinuxProcessContext | None = None

        async def _after_guard_release_sent(self, context: LinuxProcessContext) -> None:
            self.context = context
            handshake = next(iter(self._handshakes.values()))
            assert handshake.released
            assert handshake.state is LinuxSpawnState.RELEASE_SENT
            await _wait_for_path(ready)
            raise release_error

    code = (
        "from pathlib import Path;import time;"
        f"Path({str(ready)!r}).write_text('ready');time.sleep(30)"
    )
    events: list[str] = []
    manager = _FakeCgroupManager(events)
    spec = _spec(
        tmp_path,
        ["-c", code],
        cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
    )
    runner = FailingAfterReleaseRunner(  # type: ignore[arg-type]
        {spec.command_id: spec},
        cgroup_manager=manager,
    )
    signals: list[int] = []
    real_send = common._PIDFD_SEND_SIGNAL
    assert real_send is not None

    def send(pidfd: int, signal_number: int) -> None:
        signals.append(signal_number)
        real_send(pidfd, signal_number)

    real_close = os.close
    pidfd_close_calls = 0

    def close(descriptor: int) -> None:
        nonlocal pidfd_close_calls
        context = runner.context
        if context is not None and descriptor == context.pidfd:
            pidfd_close_calls += 1
            real_close(descriptor)
            raise OSError("controlled pidfd close failure")
        real_close(descriptor)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("numeric process signalling is forbidden")

    monkeypatch.setattr(common, "_PIDFD_SEND_SIGNAL", send)
    monkeypatch.setattr(common.os, "close", close)
    monkeypatch.setattr(common.os, "kill", forbidden)
    if hasattr(common.os, "killpg"):
        monkeypatch.setattr(common.os, "killpg", forbidden)
    monkeypatch.setattr(asyncio.subprocess.Process, "kill", forbidden)
    monkeypatch.setattr(asyncio.subprocess.Process, "terminate", forbidden)

    with pytest.raises(RuntimeError) as raised:
        await runner.run(_request(), CancellationToken())

    assert raised.value is release_error
    assert int(getattr(signal, "SIGTERM", 15)) in signals
    assert pidfd_close_calls == 1
    assert runner.context is not None
    assert runner.context.process.returncode is not None
    assert runner.context.closed
    assert not runner._contexts
    assert not runner._handshakes
    assert events.count("cgroup.kill") == 1
    assert events.count("remove") == 1
    assert events.count("close") == 1
    assert any("controlled pidfd close failure" in note for note in raised.value.__notes__)


@pytest.mark.asyncio
async def test_failure_after_release_escalates_to_pidfd_sigkill(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ready = tmp_path / "sigterm-ignored"
    release_error = RuntimeError("controlled post-release cleanup")

    class FailingAfterReleaseRunner(LinuxProcessRunner):
        context: LinuxProcessContext | None = None

        async def _after_guard_release_sent(self, context: LinuxProcessContext) -> None:
            self.context = context
            await _wait_for_path(ready)
            raise release_error

    code = (
        "from pathlib import Path;import signal,time;"
        "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
        f"Path({str(ready)!r}).write_text('ready');time.sleep(30)"
    )
    spec = _spec(tmp_path, ["-c", code])
    runner = FailingAfterReleaseRunner({spec.command_id: spec})
    signals: list[int] = []
    real_send = common._PIDFD_SEND_SIGNAL
    assert real_send is not None

    def send(pidfd: int, signal_number: int) -> None:
        signals.append(signal_number)
        real_send(pidfd, signal_number)

    monkeypatch.setattr(common, "_PIDFD_SEND_SIGNAL", send)
    with pytest.raises(RuntimeError) as raised:
        await runner.run(_request(), CancellationToken())

    assert raised.value is release_error
    assert int(getattr(signal, "SIGTERM", 15)) in signals
    assert int(getattr(signal, "SIGKILL", 9)) in signals
    assert runner.context is not None
    assert runner.context.process.returncode is not None
    assert runner.context.closed
    assert not runner._contexts
    assert not runner._handshakes


@pytest.mark.asyncio
async def test_cancellation_immediately_after_release_reaps_target(
    tmp_path: Path,
) -> None:
    ready = tmp_path / "released-before-cancellation"
    released = asyncio.Event()

    class BlockingAfterReleaseRunner(LinuxProcessRunner):
        context: LinuxProcessContext | None = None

        async def _after_guard_release_sent(self, context: LinuxProcessContext) -> None:
            self.context = context
            await _wait_for_path(ready)
            released.set()
            await asyncio.Event().wait()

    code = (
        "from pathlib import Path;import time;"
        f"Path({str(ready)!r}).write_text('ready');time.sleep(30)"
    )
    events: list[str] = []
    manager = _FakeCgroupManager(events)
    spec = _spec(
        tmp_path,
        ["-c", code],
        cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
    )
    runner = BlockingAfterReleaseRunner(  # type: ignore[arg-type]
        {spec.command_id: spec},
        cgroup_manager=manager,
    )
    cancellation = CancellationToken()
    running = asyncio.create_task(runner.run(_request(), cancellation))
    await asyncio.wait_for(released.wait(), timeout=2)
    cancellation.cancel()

    with pytest.raises(asyncio.CancelledError):
        await running

    assert runner.context is not None
    assert runner.context.process.returncode is not None
    assert runner.context.closed
    assert not runner._contexts
    assert not runner._handshakes
    assert events.count("remove") == 1
    assert events.count("close") == 1


@pytest.mark.asyncio
async def test_process_tree_timeout_cleans_cgroup_once(tmp_path: Path) -> None:
    events: list[str] = []
    manager = _FakeCgroupManager(events)
    released = asyncio.Event()
    continue_after_release = asyncio.Event()

    class ReleaseBarrierRunner(LinuxProcessRunner):
        async def _after_guard_release_sent(self, context: LinuxProcessContext) -> None:
            assert context.cgroup is manager.handle
            released.set()
            await continue_after_release.wait()

    spec = _spec(
        tmp_path,
        ["-c", "import time;time.sleep(30)"],
        cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
    )
    runner = ReleaseBarrierRunner(  # type: ignore[arg-type]
        {spec.command_id: spec},
        cgroup_manager=manager,
    )

    running = asyncio.create_task(runner.run(_request(timeout=2.0), CancellationToken()))
    await asyncio.wait_for(released.wait(), timeout=1.5)
    assert events[:3] == ["create", "attach", "verify"]
    continue_after_release.set()
    with pytest.raises(TimeoutError):
        await running

    assert events.count("cgroup.kill") == 1
    assert events.count("remove") == 1
    assert events.count("close") == 1
    assert not runner._contexts
    assert not [
        task
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task()
        and not task.done()
        and "Process.wait" in getattr(task.get_coro(), "__qualname__", "")
    ]


@pytest.mark.asyncio
async def test_timeout_before_cgroup_creation_does_not_report_cgroup_cleanup(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    manager = _FakeCgroupManager(events)
    before_cgroup = asyncio.Event()

    class BeforeCgroupBarrierRunner(LinuxProcessRunner):
        async def _before_guard_release(self, context: LinuxProcessContext) -> None:
            del context
            before_cgroup.set()
            await asyncio.Event().wait()

    spec = _spec(
        tmp_path,
        ["-c", "import time;time.sleep(30)"],
        cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
    )
    runner = BeforeCgroupBarrierRunner(  # type: ignore[arg-type]
        {spec.command_id: spec},
        cgroup_manager=manager,
    )
    running = asyncio.create_task(runner.run(_request(timeout=1.0), CancellationToken()))
    await asyncio.wait_for(before_cgroup.wait(), timeout=0.8)

    with pytest.raises(TimeoutError):
        await running

    assert events == []
    assert not runner._contexts
    assert not runner._handshakes
    assert not [
        task
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task()
        and not task.done()
        and "Process.wait" in getattr(task.get_coro(), "__qualname__", "")
    ]


@pytest.mark.asyncio
async def test_cancellation_during_handshake_never_executes_target_and_reaps_guard(
    tmp_path: Path,
) -> None:
    target_marker = tmp_path / "must-not-run"
    observed = asyncio.Event()

    class BlockingRunner(LinuxProcessRunner):
        context: LinuxProcessContext | None = None

        async def _before_guard_release(self, context: LinuxProcessContext) -> None:
            self.context = context
            observed.set()
            await asyncio.Event().wait()

    code = f"from pathlib import Path;Path({str(target_marker)!r}).write_text('bad')"
    spec = _spec(tmp_path, ["-c", code])
    runner = BlockingRunner({spec.command_id: spec})
    cancellation = CancellationToken()
    running = asyncio.create_task(runner.run(_request(), cancellation))
    await asyncio.wait_for(observed.wait(), timeout=2)
    cancellation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running

    assert not target_marker.exists()
    assert runner.context is not None and runner.context.closed
    assert runner.context.process.returncode is not None
    assert not runner._contexts
    assert not runner._handshakes


@pytest.mark.asyncio
async def test_cancellation_while_guard_creation_settles_reaps_without_exec(
    tmp_path: Path,
) -> None:
    target_marker = tmp_path / "must-not-run-during-creation"
    guard_created = asyncio.Event()
    allow_creation_to_return = asyncio.Event()
    recovery_started = asyncio.Event()

    class SettlingCreationRunner(LinuxProcessRunner):
        guard_process: asyncio.subprocess.Process | None = None

        async def _spawn_guard(
            self, handshake: common.LinuxSpawnHandshake
        ) -> asyncio.subprocess.Process:
            process = await super()._spawn_guard(handshake)
            self.guard_process = process
            guard_created.set()
            await allow_creation_to_return.wait()
            return process

        async def _recover_guard_creation(
            self,
            handshake: common.LinuxSpawnHandshake,
            creation: asyncio.Task[asyncio.subprocess.Process] | None,
            primary_error: BaseException,
        ) -> BaseException | None:
            recovery_started.set()
            return await super()._recover_guard_creation(
                handshake,
                creation,
                primary_error,
            )

    code = f"from pathlib import Path;Path({str(target_marker)!r}).write_text('bad')"
    spec = _spec(tmp_path, ["-c", code])
    runner = SettlingCreationRunner({spec.command_id: spec})
    cancellation = CancellationToken()
    running = asyncio.create_task(runner.run(_request(), cancellation))
    await asyncio.wait_for(guard_created.wait(), timeout=2)

    cancellation.cancel()
    await asyncio.wait_for(recovery_started.wait(), timeout=2)
    allow_creation_to_return.set()
    with pytest.raises(asyncio.CancelledError):
        await running

    assert not target_marker.exists()
    assert runner.guard_process is not None
    assert runner.guard_process.returncode is not None
    assert not runner._contexts
    assert not runner._handshakes


@pytest.mark.asyncio
async def test_cancellation_after_release_signals_only_pidfd_and_reaps_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ready = tmp_path / "ready"
    code = (
        "from pathlib import Path;import time;"
        f"Path({str(ready)!r}).write_text('ready');time.sleep(30)"
    )
    spec = _spec(tmp_path, ["-c", code])
    runner = LinuxProcessRunner({spec.command_id: spec})
    cancellation = CancellationToken()
    killpg_calls: list[tuple[object, ...]] = []
    if hasattr(os, "killpg"):
        monkeypatch.setattr(os, "killpg", lambda *args: killpg_calls.append(args))
    running = asyncio.create_task(runner.run(_request(), cancellation))
    await _wait_for_path(ready)
    cancellation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running

    assert killpg_calls == []
    assert not runner._contexts
    assert "killpg(" not in inspect.getsource(common)


@pytest.mark.asyncio
async def test_pidfd_unavailable_or_open_failure_is_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_marker = tmp_path / "must-not-run"
    code = f"from pathlib import Path;Path({str(target_marker)!r}).write_text('bad')"
    spec = _spec(tmp_path, ["-c", code])

    monkeypatch.setattr(common, "_PIDFD_OPEN", None)
    with pytest.raises(PluginUnavailableError, match="pidfd"):
        await LinuxProcessRunner({spec.command_id: spec}).run(_request(), CancellationToken())
    assert not target_marker.exists()

    def fail_open(_pid: int) -> int:
        raise OSError("synthetic pidfd_open failure")

    monkeypatch.setattr(common, "_PIDFD_OPEN", fail_open)
    runner = LinuxProcessRunner({spec.command_id: spec})
    with pytest.raises(OSError, match="synthetic pidfd_open"):
        await runner.run(_request(), CancellationToken())
    assert not target_marker.exists()
    assert not runner._contexts
    assert not runner._handshakes


@pytest.mark.asyncio
async def test_start_time_change_and_wrong_nonce_abort_before_release(
    tmp_path: Path,
) -> None:
    target_marker = tmp_path / "must-not-run"
    code = f"from pathlib import Path;Path({str(target_marker)!r}).write_text('bad')"
    spec = _spec(tmp_path, ["-c", code])

    class ChangingStartTimeRunner(LinuxProcessRunner):
        reads = 0

        def _start_time(self, pid: int) -> str | None:
            self.reads += 1
            value = super()._start_time(pid)
            return value if self.reads == 1 else "0"

    changed = ChangingStartTimeRunner({spec.command_id: spec})
    with pytest.raises(RuntimeError, match="identity changed.*pidfd"):
        await changed.run(_request(), CancellationToken())
    assert not target_marker.exists()
    assert not changed._contexts

    class WrongNonceRunner(LinuxProcessRunner):
        def _validate_guard_marker(
            self,
            marker: dict[str, Any],
            nonce: str,
            process: asyncio.subprocess.Process,
        ) -> tuple[str, int, int]:
            marker["nonce"] = "0" * 64
            return super()._validate_guard_marker(marker, nonce, process)

    wrong = WrongNonceRunner({spec.command_id: spec})
    with pytest.raises(ValueError, match="nonce"):
        await wrong.run(_request(), CancellationToken())
    assert not target_marker.exists()
    assert not wrong._contexts


@pytest.mark.asyncio
async def test_marker_timeout_and_guard_exit_before_release_are_bounded(
    tmp_path: Path,
) -> None:
    target_marker = tmp_path / "must-not-run"
    code = f"from pathlib import Path;Path({str(target_marker)!r}).write_text('bad')"
    spec = _spec(tmp_path, ["-c", code])

    class MarkerTimeoutRunner(LinuxProcessRunner):
        _spawn_handshake_timeout_seconds = 0.05

        @staticmethod
        async def _read_stream_frame(reader: asyncio.StreamReader) -> dict[str, Any]:
            del reader
            await asyncio.sleep(30)
            raise AssertionError("unreachable")

    timed = MarkerTimeoutRunner({spec.command_id: spec})
    with pytest.raises(TimeoutError, match="identity marker"):
        await timed.run(_request(timeout=1), CancellationToken())
    assert not timed._contexts
    assert not timed._handshakes

    class EarlyExitRunner(LinuxProcessRunner):
        async def _before_guard_release(self, context: LinuxProcessContext) -> None:
            handshake = next(iter(self._handshakes.values()))
            descriptor = handshake.control_write_descriptor
            assert descriptor is not None
            os.close(descriptor)
            handshake.control_write_descriptor = None
            await context.process.wait()

    exited = EarlyExitRunner({spec.command_id: spec})
    with pytest.raises(OSError):
        await exited.run(_request(), CancellationToken())
    assert not target_marker.exists()
    assert not exited._contexts
    assert not exited._handshakes


@pytest.mark.asyncio
async def test_execve_failure_and_concurrent_cleanup_remain_bounded(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "ephemeral-target"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    spec = _spec(tmp_path, [], executable)

    class RemovingTargetRunner(LinuxProcessRunner):
        async def _before_guard_release(self, context: LinuxProcessContext) -> None:
            del context
            executable.unlink()

    removed = RemovingTargetRunner({spec.command_id: spec})
    with pytest.raises(FileNotFoundError):
        await removed.run(_request(), CancellationToken())
    assert not removed._contexts

    events: list[str] = []
    manager = _FakeCgroupManager(events)
    sleeping_spec = _spec(
        tmp_path,
        ["-c", "import time;time.sleep(30)"],
        cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
    )
    runner = LinuxProcessRunner({}, cgroup_manager=manager)  # type: ignore[arg-type]
    process = await runner.start_process(
        sleeping_spec,
        sleeping_spec.build_argv(EmptyArguments()),
        dict(sleeping_spec.environment),
        execution_token=object(),
        deadline=asyncio.get_running_loop().time() + 5,
    )
    deadline = asyncio.get_running_loop().time() + 5
    first, second = await asyncio.gather(
        runner._cleanup_process(process, [], terminate=True, deadline=deadline),
        runner._cleanup_process(process, [], terminate=True, deadline=deadline),
        return_exceptions=True,
    )
    assert first is None
    assert second is None
    assert process.returncode is not None
    assert not runner._contexts
    assert events.count("remove") == 1
    assert events.count("close") == 1


@pytest.mark.asyncio
async def test_partial_marker_is_rejected_through_runner_lifecycle(
    tmp_path: Path,
) -> None:
    target_marker = tmp_path / "partial-marker-target"

    class PartialMarkerRunner(LinuxProcessRunner):
        @staticmethod
        async def _read_stream_frame(reader: asyncio.StreamReader) -> dict[str, Any]:
            del reader
            raise asyncio.IncompleteReadError(partial=b"{}", expected=10)

    code = f"from pathlib import Path;Path({str(target_marker)!r}).write_text('bad')"
    spec = _spec(tmp_path, ["-c", code])
    runner = PartialMarkerRunner({spec.command_id: spec})

    with pytest.raises(asyncio.IncompleteReadError):
        await runner.run(_request(), CancellationToken())

    assert not target_marker.exists()
    assert not runner._contexts
    assert not runner._handshakes


@pytest.mark.asyncio
async def test_partial_marker_parser_is_rejected() -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack("!I", 10) + b"{}")
    reader.feed_eof()
    with pytest.raises(asyncio.IncompleteReadError):
        await LinuxProcessRunner._read_stream_frame(reader)


def test_spawn_guard_rejects_invalid_payload_and_release() -> None:
    with pytest.raises(ValueError):
        spawn_guard.parse_target({"version": 1})
    with pytest.raises(ValueError):
        spawn_guard.parse_release({"version": 1, "command": "release"}, "0" * 64)
