from __future__ import annotations

from typing import Any, Protocol
from uuid import UUID


class AgentTransport(Protocol):
    async def enroll(self, payload: dict[str, Any], idempotency_key: UUID) -> dict[str, Any]: ...

    async def create_rotation(
        self, credential: str, payload: dict[str, Any], idempotency_key: UUID
    ) -> dict[str, Any]: ...

    async def activate_rotation(
        self,
        credential: str,
        rotation_id: UUID,
        payload: dict[str, Any],
        idempotency_key: UUID,
    ) -> dict[str, Any]: ...

    async def publish_manifest(
        self, credential: str, payload: dict[str, Any]
    ) -> dict[str, Any]: ...

    async def heartbeat(self, credential: str, payload: dict[str, Any]) -> dict[str, Any]: ...


class LocalTaskTransport(Protocol):
    async def fetch_local_task(self) -> dict[str, Any] | None: ...

    async def publish_progress(self, payload: dict[str, Any]) -> None: ...

    async def publish_result(self, payload: dict[str, Any]) -> None: ...

    async def publish_upload(self, payload: dict[str, Any]) -> None: ...
