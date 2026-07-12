from __future__ import annotations

from datetime import UTC
from typing import Any

from wto_desktop_agent import __version__
from wto_desktop_agent.infrastructure.contracts import validate_contract
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.ports.time import Clock
from wto_desktop_agent.ports.transport import AgentTransport


class HeartbeatService:
    def __init__(self, store: SQLiteStore, transport: AgentTransport, clock: Clock) -> None:
        self.store = store
        self.transport = transport
        self.clock = clock

    async def send(self, credential: str) -> dict[str, object]:
        pending = self.store.pending_heartbeat()
        if pending:
            payload: dict[str, Any] = pending
        else:
            identity = self.store.identity()
            runtime = self.store.runtime_state()
            manifest = self.store.confirmed_manifest()
            if not identity or not runtime or not manifest:
                raise RuntimeError("identity, runtime and confirmed manifest are required")
            sequence = int(runtime["heartbeat_acked_sequence"]) + 1
            payload = {
                "schema_version": "1.0.0",
                "agent_id": str(identity["agent_id"]),
                "boot_id": str(runtime["boot_id"]),
                "sequence": sequence,
                "agent_version": __version__,
                "protocol_version": "1.0.0",
                "agent_reported_at": self.clock.now()
                .astimezone(UTC)
                .isoformat()
                .replace("+00:00", "Z"),
                "readiness": "ready",
                "reason": None,
                "manifest_id": str(manifest["manifest_id"]),
                "manifest_digest": str(manifest["server_digest"]),
            }
            validate_contract("desktop-heartbeat.schema.json", payload)
            self.store.persist_heartbeat(sequence, payload)
        response = await self.transport.heartbeat(credential, payload)
        if int(response["accepted_sequence"]) != int(payload["sequence"]):
            raise RuntimeError("server acknowledged a different heartbeat sequence")
        self.store.confirm_heartbeat(int(payload["sequence"]))
        return dict(payload)
