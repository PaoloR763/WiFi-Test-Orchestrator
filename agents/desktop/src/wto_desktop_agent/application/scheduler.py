from __future__ import annotations

import asyncio
import json
import logging

from wto_desktop_agent.application.task_runner import TaskRunner
from wto_desktop_agent.domain.models import LocalTaskEnvelope
from wto_desktop_agent.domain.states import TaskState
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.ports.time import Clock
from wto_desktop_agent.ports.transport import LocalTaskTransport

logger = logging.getLogger(__name__)


class Scheduler:
    def __init__(
        self,
        store: SQLiteStore,
        runner: TaskRunner,
        transport: LocalTaskTransport,
        clock: Clock,
        *,
        max_concurrency: int,
        polling_interval_seconds: float,
        shutdown_grace_seconds: float,
    ) -> None:
        self.store = store
        self.runner = runner
        self.transport = transport
        self.clock = clock
        self.max_concurrency = max_concurrency
        self.polling_interval_seconds = polling_interval_seconds
        self.shutdown_grace_seconds = shutdown_grace_seconds
        self._stopping = asyncio.Event()
        self._running: dict[str, asyncio.Task[object]] = {}

    async def run_once(self) -> None:
        while True:
            payload = await self.transport.fetch_local_task()
            if payload is None:
                break
            task = LocalTaskEnvelope.model_validate(payload)
            self.store.ingest_task(task)
        available = max(0, self.max_concurrency - len(self._running))
        for task in self.store.queued_tasks(available):
            task_id = str(task.task_id)
            running = asyncio.create_task(self.runner.run(task))
            self._running[task_id] = running

            def remove_finished(_future: asyncio.Task[TaskState], key: str = task_id) -> None:
                self._running.pop(key, None)

            running.add_done_callback(remove_finished)
        if self._running:
            await asyncio.gather(*list(self._running.values()), return_exceptions=True)
        await self._sync_outboxes()

    async def _sync_outboxes(self) -> None:
        for row in self.store.pending_outbox("outbox_progress"):
            await self.transport.publish_progress(json.loads(str(row["payload"])))
            self.store.confirm_outbox("outbox_progress", "event_id", str(row["event_id"]))
        for row in self.store.pending_outbox("outbox_results"):
            await self.transport.publish_result(json.loads(str(row["payload"])))
            self.store.confirm_outbox("outbox_results", "result_id", str(row["result_id"]))
        for row in self.store.pending_outbox("pending_uploads"):
            await self.transport.publish_upload(json.loads(str(row["payload"])))
            self.store.confirm_outbox("pending_uploads", "upload_id", str(row["upload_id"]))

    async def run(self) -> None:
        while not self._stopping.is_set():
            await self.run_once()
            await self.clock.sleep(self.polling_interval_seconds)

    async def shutdown(self) -> None:
        self._stopping.set()
        for task_id in list(self._running):
            self.runner.cancel(task_id)
        if self._running:
            done, pending = await asyncio.wait(
                list(self._running.values()), timeout=self.shutdown_grace_seconds
            )
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
                logger.warning(
                    "shutdown grace period exhausted",
                    extra={"event": "shutdown_timeout"},
                )
