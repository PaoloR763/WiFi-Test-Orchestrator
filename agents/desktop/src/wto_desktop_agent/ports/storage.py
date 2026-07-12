from __future__ import annotations

from typing import Any, Protocol

from wto_desktop_agent.domain.models import LocalTaskEnvelope


class LocalStore(Protocol):
    def initialize(self) -> None: ...

    def identity(self) -> dict[str, Any] | None: ...

    def ingest_task(self, task: LocalTaskEnvelope) -> str: ...
