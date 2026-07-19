from __future__ import annotations

import asyncio
from uuid import uuid4

from wto_desktop_agent.application.capabilities import ManifestService
from wto_desktop_agent.application.heartbeat import HeartbeatService
from wto_desktop_agent.application.identity import IdentityManager
from wto_desktop_agent.application.scheduler import Scheduler
from wto_desktop_agent.domain.errors import TransportError
from wto_desktop_agent.infrastructure.backoff import BackoffPolicy
from wto_desktop_agent.infrastructure.http_transport import AgentAuthenticationFailed
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.ports.time import Clock, RandomSource


class AgentRuntime:
    def __init__(
        self,
        store: SQLiteStore,
        identity: IdentityManager,
        manifests: ManifestService,
        heartbeat: HeartbeatService,
        clock: Clock,
        *,
        heartbeat_interval_seconds: float,
        backoff: BackoffPolicy,
        random_source: RandomSource,
        scheduler: Scheduler | None = None,
    ) -> None:
        self.store = store
        self.identity = identity
        self.manifests = manifests
        self.heartbeat = heartbeat
        self.clock = clock
        self.heartbeat_interval_seconds = heartbeat_interval_seconds
        self.backoff = backoff
        self.random_source = random_source
        self.scheduler = scheduler
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        self.store.recover_interrupted()
        self.store.start_runtime(str(uuid4()))
        current = self.store.identity()
        if current:
            rotation_state = current.get("rotation_state")
            has_revoked_references = any(
                current.get(field)
                for field in (
                    "active_credential_ref",
                    "pending_credential_ref",
                    "previous_credential_ref",
                )
            )
            if rotation_state == "revoked" and has_revoked_references:
                await self.identity.mark_revoked_async()
            elif rotation_state not in {None, "none", "revoked"}:
                await self.identity.rotate()

    async def cycle(self) -> None:
        credential = await self.identity.active_credential_async()
        try:
            refresh_after_tasks = False
            if self.scheduler:
                refresh_after_tasks = await self.manifests.ensure_fast_start_published(credential)
            else:
                await self.manifests.ensure_published(credential)
            await self.heartbeat.send(credential)
            if self.scheduler:
                await self.scheduler.run_once()
                if refresh_after_tasks:
                    await self.manifests.ensure_published(credential)
        except AgentAuthenticationFailed:
            await self.identity.mark_revoked_async()
            raise
        finally:
            del credential

    async def run(self, *, once: bool) -> None:
        await self.start()
        try:
            if once:
                await self.cycle()
                return
            failures = 0
            while not self._stopping.is_set():
                try:
                    await self.cycle()
                    failures = 0
                    await self.clock.sleep(self.heartbeat_interval_seconds)
                except TransportError:
                    delay = self.backoff.delay(failures, self.random_source)
                    failures += 1
                    await self.clock.sleep(delay)
        finally:
            await self.shutdown()

    async def shutdown(self) -> None:
        self._stopping.set()
        if self.scheduler:
            await self.scheduler.shutdown()
        self.store.stop_runtime()
