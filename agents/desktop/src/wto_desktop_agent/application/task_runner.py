from __future__ import annotations

import asyncio
from datetime import UTC
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from wto_desktop_agent.domain.errors import PluginUnavailableError
from wto_desktop_agent.domain.models import LocalTaskEnvelope, PluginResult
from wto_desktop_agent.domain.states import TaskState
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.plugins.registry import PluginRegistry
from wto_desktop_agent.ports.plugins import CancellationToken
from wto_desktop_agent.ports.time import Clock


class TaskRunner:
    def __init__(self, store: SQLiteStore, plugins: PluginRegistry, clock: Clock) -> None:
        self.store = store
        self.plugins = plugins
        self.clock = clock
        self._cancellations: dict[str, CancellationToken] = {}

    def cancel(self, task_id: str) -> None:
        token = self._cancellations.get(task_id)
        if token:
            token.cancel()

    async def run(self, task: LocalTaskEnvelope) -> TaskState:
        task_id = str(task.task_id)
        if self.clock.now().astimezone(UTC) >= task.expires_at.astimezone(UTC):
            self.store.transition(task_id, TaskState.QUEUED, TaskState.SKIPPED)
            return TaskState.SKIPPED
        try:
            plugin = self.plugins.get(task.task_type, task.task_type_version)
        except PluginUnavailableError:
            self.store.transition(task_id, TaskState.QUEUED, TaskState.BLOCKED)
            return TaskState.BLOCKED
        try:
            plugin.descriptor.parameter_model.model_validate(task.parameters)
        except ValidationError:
            self.store.transition(task_id, TaskState.QUEUED, TaskState.REJECTED)
            return TaskState.REJECTED
        attempt_id = self.store.claim_task(task_id)
        if attempt_id is None:
            return TaskState.INTERRUPTED
        self.store.transition(task_id, TaskState.PREPARING, TaskState.RUNNING)
        token = CancellationToken()
        self._cancellations[task_id] = token
        sequence = 0

        async def progress(percent: float) -> None:
            nonlocal sequence
            sequence += 1
            self.store.queue_progress(
                task_id,
                {
                    "schema_version": "1.0.0",
                    "event_id": str(uuid4()),
                    "task_id": task_id,
                    "execution_id": str(task.execution_id),
                    "sequence": sequence,
                    "event_type": "running",
                    "occurred_at": self.clock.now()
                    .astimezone(UTC)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "progress_percent": percent,
                    "reason": None,
                    "idempotency_key": str(uuid4()),
                },
            )

        result: PluginResult | None = None
        final_state = TaskState.COMPLETED
        detail: str | None = None
        self.store.mark_invoked(task_id)
        try:
            result = await asyncio.wait_for(
                plugin.execute(task, token, progress),
                timeout=plugin.descriptor.max_timeout_seconds,
            )
            if result.status == "failed":
                final_state = TaskState.FAILED
        except TimeoutError:
            token.cancel()
            self.store.transition(task_id, TaskState.RUNNING, TaskState.CANCEL_REQUESTED)
            final_state = TaskState.FAILED
            detail = "timeout"
        except asyncio.CancelledError:
            token.cancel()
            self.store.transition(task_id, TaskState.RUNNING, TaskState.CANCEL_REQUESTED)
            final_state = TaskState.CANCELLED
            detail = "cancelled"
        except Exception:
            final_state = TaskState.FAILED
            detail = "plugin_failed"

        current = TaskState.CANCEL_REQUESTED if token.cancelled else TaskState.RUNNING
        self.store.transition(current=current, target=TaskState.CLEANING_UP, task_id=task_id)
        self.store.request_cleanup(task_id)
        try:
            await asyncio.wait_for(plugin.cleanup(task), timeout=10.0)
            self.store.complete_cleanup(task_id)
        except Exception:
            self.store.complete_cleanup(task_id, "cleanup_failed")
            final_state = TaskState.FAILED
            detail = "cleanup_failed"
        payload: dict[str, Any] = {
            "schema_version": "1.0.0",
            "result_id": str(uuid4()),
            "task_id": task_id,
            "execution_id": str(task.execution_id),
            "local_state": final_state.value,
            "outcome": result.outcome if result else "not_evaluated",
            "provider": {
                "provider_id": plugin.descriptor.provider_id,
                "provider_version": plugin.descriptor.provider_version,
                "method": plugin.descriptor.method,
            },
            "metrics": result.metrics if result else [],
            "reason": detail,
            "finished_at": self.clock.now().astimezone(UTC).isoformat().replace("+00:00", "Z"),
        }
        self.store.finish_with_result(task_id, TaskState.CLEANING_UP, final_state, payload)
        self._cancellations.pop(task_id, None)
        return final_state
