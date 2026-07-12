from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel

from wto_desktop_agent.domain.models import LocalTaskEnvelope, PluginResult


class CancellationToken:
    def __init__(self) -> None:
        self._event = asyncio.Event()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        self._event.set()

    async def wait(self) -> None:
        await self._event.wait()


@dataclass(frozen=True)
class PluginDescriptor:
    task_type: str
    task_type_version: str
    provider_id: str
    provider_version: str
    method: str
    parameter_model: type[BaseModel]
    required_commands: frozenset[str] = frozenset()
    max_timeout_seconds: float = 300.0


ProgressCallback = Callable[[float], Awaitable[None]]


class TestPlugin(Protocol):
    descriptor: PluginDescriptor

    async def execute(
        self,
        task: LocalTaskEnvelope,
        cancellation: CancellationToken,
        progress: ProgressCallback,
    ) -> PluginResult: ...

    async def cleanup(self, task: LocalTaskEnvelope) -> None: ...
