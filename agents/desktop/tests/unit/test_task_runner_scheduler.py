from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from conftest import FakeClock
from pydantic import BaseModel, ConfigDict

from wto_desktop_agent.application.scheduler import Scheduler
from wto_desktop_agent.application.task_runner import TaskRunner
from wto_desktop_agent.domain.models import LocalTaskEnvelope, PluginResult
from wto_desktop_agent.domain.states import TaskState
from wto_desktop_agent.infrastructure.simulated_transport import SimulatedAgentTransport
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.plugins.registry import PluginRegistry, build_plugin_registry
from wto_desktop_agent.ports.plugins import CancellationToken, PluginDescriptor


def local_task(
    *,
    task_type: str = "protocol.contract_check",
    parameters: dict | None = None,
    expires_at: datetime | None = None,
) -> LocalTaskEnvelope:
    now = datetime.now(UTC)
    return LocalTaskEnvelope(
        task_id=uuid4(),
        execution_id=uuid4(),
        task_type=task_type,
        task_type_version="1.0.0",
        issued_at=now,
        not_before=now,
        expires_at=expires_at or now + timedelta(minutes=5),
        idempotency_key=uuid4(),
        required_capabilities=["network.http.probe"],
        foreground_requirement="not_required",
        user_interaction_requirement="none",
        parameters=parameters or {},
    )


@pytest.mark.asyncio
async def test_builtin_plugin_completes_without_process_and_outbox_syncs(
    store: SQLiteStore,
) -> None:
    transport = SimulatedAgentTransport()
    item = local_task()
    transport.tasks.append(item.model_dump(mode="json"))
    runner = TaskRunner(store, build_plugin_registry(frozenset({item.task_type})), FakeClock())
    scheduler = Scheduler(
        store,
        runner,
        transport,
        FakeClock(),
        max_concurrency=1,
        polling_interval_seconds=1,
        shutdown_grace_seconds=1,
    )
    await scheduler.run_once()
    assert store.rows("inbox_tasks")[0]["state"] == "completed"
    assert len(store.rows("task_attempts")) == 1
    assert store.rows("task_attempts")[0]["cleanup_completed_at"] is not None
    assert len(transport.results) == 1
    assert all(row["state"] == "confirmed" for row in store.rows("outbox_results"))
    assert all(row["state"] == "confirmed" for row in store.rows("outbox_progress"))


@pytest.mark.asyncio
async def test_expired_unknown_and_invalid_tasks_end_before_claim(
    store: SQLiteStore,
) -> None:
    runner = TaskRunner(
        store,
        build_plugin_registry(frozenset({"protocol.contract_check"})),
        FakeClock(),
    )
    expired = local_task(expires_at=FakeClock().now() - timedelta(seconds=1))
    unknown = local_task(task_type="unknown.plugin")
    invalid = local_task(parameters={"unknown": True})
    for item, expected in (
        (expired, TaskState.SKIPPED),
        (unknown, TaskState.BLOCKED),
        (invalid, TaskState.REJECTED),
    ):
        store.ingest_task(item)
        assert await runner.run(item) == expected
    assert store.rows("task_attempts") == []


class EmptyParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ControlledPlugin:
    def __init__(self, mode: str, cleanup_fails: bool = False) -> None:
        self.mode = mode
        self.cleanup_fails = cleanup_fails
        self.cleanup_calls = 0
        self.descriptor = PluginDescriptor(
            task_type="test.controlled",
            task_type_version="1.0.0",
            provider_id="test-controlled",
            provider_version="1.0.0",
            method=mode,
            parameter_model=EmptyParameters,
            max_timeout_seconds=0.02,
        )

    async def execute(self, task, cancellation: CancellationToken, progress):  # type: ignore[no-untyped-def]
        if self.mode == "cancel":
            await cancellation.wait()
            raise asyncio.CancelledError
        if self.mode == "timeout":
            await asyncio.sleep(60)
        if self.mode == "fail":
            raise RuntimeError("synthetic")
        return PluginResult(status="completed", outcome="pass")

    async def cleanup(self, task):  # type: ignore[no-untyped-def]
        self.cleanup_calls += 1
        if self.cleanup_fails:
            raise RuntimeError("synthetic cleanup")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "expected"),
    [("timeout", "failed"), ("fail", "failed"), ("success", "completed")],
)
async def test_timeout_failure_success_all_request_cleanup(
    store: SQLiteStore, mode: str, expected: str
) -> None:
    item = local_task(task_type="test.controlled")
    plugin = ControlledPlugin(mode)
    registry = PluginRegistry([plugin], frozenset({"test.controlled"}))
    store.ingest_task(item)
    assert (await TaskRunner(store, registry, FakeClock()).run(item)).value == expected
    attempt = store.rows("task_attempts")[0]
    assert attempt["cleanup_requested_at"] is not None
    assert attempt["cleanup_completed_at"] is not None
    assert plugin.cleanup_calls == 1


@pytest.mark.asyncio
async def test_cooperative_cancellation_and_shutdown_grace_exhaustion(
    store: SQLiteStore,
) -> None:
    item = local_task(task_type="test.controlled")
    plugin = ControlledPlugin("cancel")
    runner = TaskRunner(
        store, PluginRegistry([plugin], frozenset({"test.controlled"})), FakeClock()
    )
    store.ingest_task(item)
    running = asyncio.create_task(runner.run(item))
    for _ in range(100):
        if store.rows("inbox_tasks")[0]["state"] == "running":
            break
        await asyncio.sleep(0)
    runner.cancel(str(item.task_id))
    assert await running == TaskState.CANCELLED
    assert plugin.cleanup_calls == 1

    class NeverStopsRunner:
        def cancel(self, task_id: str) -> None:
            pass

    transport = SimulatedAgentTransport()
    scheduler = Scheduler(
        store,
        NeverStopsRunner(),
        transport,
        FakeClock(),
        max_concurrency=1,
        polling_interval_seconds=1,
        shutdown_grace_seconds=0.001,
    )  # type: ignore[arg-type]
    blocker = asyncio.create_task(asyncio.sleep(60))
    scheduler._running["blocked"] = blocker
    await scheduler.shutdown()
    assert blocker.cancelled()


@pytest.mark.asyncio
async def test_result_stays_pending_until_later_sync(store: SQLiteStore) -> None:
    item = local_task()
    store.ingest_task(item)
    runner = TaskRunner(store, build_plugin_registry(frozenset({item.task_type})), FakeClock())
    await runner.run(item)
    assert store.rows("outbox_results")[0]["state"] == "pending"
    transport = SimulatedAgentTransport()
    scheduler = Scheduler(
        store,
        runner,
        transport,
        FakeClock(),
        max_concurrency=1,
        polling_interval_seconds=1,
        shutdown_grace_seconds=1,
    )
    await scheduler.run_once()
    assert store.rows("outbox_results")[0]["state"] == "confirmed"
    assert len(transport.results) == 1
