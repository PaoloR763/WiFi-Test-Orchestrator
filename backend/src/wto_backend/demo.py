from __future__ import annotations

from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Literal

from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

router = APIRouter(prefix="/demo", include_in_schema=False)


class DemoAgentHeartbeat(BaseModel):
    """Transient Phase 02 DTO; it is not an Agent Protocol contract."""

    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    display_name: str = Field(min_length=1, max_length=128)
    platform: Literal["simulated"]
    process_started_at: datetime
    sent_at: datetime


class DemoAgentView(BaseModel):
    """Replaceable Phase 02 UI projection, deliberately not normative."""

    agent_id: str
    display_name: str
    platform: Literal["simulated"]
    process_started_at: datetime
    last_seen_at: datetime


class DemoAgentList(BaseModel):
    agents: list[DemoAgentView]


class DemoAgentStore:
    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = timedelta(seconds=ttl_seconds)
        self._records: dict[str, DemoAgentView] = {}
        self._lock = Lock()

    def heartbeat(self, heartbeat: DemoAgentHeartbeat) -> None:
        now = datetime.now(UTC)
        record = DemoAgentView(
            agent_id=heartbeat.agent_id,
            display_name=heartbeat.display_name,
            platform=heartbeat.platform,
            process_started_at=heartbeat.process_started_at,
            last_seen_at=now,
        )
        with self._lock:
            self._records[heartbeat.agent_id] = record

    def active(self) -> list[DemoAgentView]:
        cutoff = datetime.now(UTC) - self._ttl
        with self._lock:
            expired = [
                agent_id
                for agent_id, record in self._records.items()
                if record.last_seen_at < cutoff
            ]
            for agent_id in expired:
                del self._records[agent_id]
            return sorted(self._records.values(), key=lambda item: item.agent_id)


@router.post("/agents/heartbeat", status_code=status.HTTP_204_NO_CONTENT)
async def heartbeat(payload: DemoAgentHeartbeat, request: Request) -> Response:
    store: DemoAgentStore = request.app.state.demo_agent_store
    store.heartbeat(payload)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/agents", response_model=DemoAgentList)
async def agents(request: Request) -> DemoAgentList:
    store: DemoAgentStore = request.app.state.demo_agent_store
    return DemoAgentList(agents=store.active())
