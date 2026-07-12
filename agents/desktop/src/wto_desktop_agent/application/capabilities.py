from __future__ import annotations

import json
from datetime import UTC
from typing import Any, cast
from uuid import uuid4

from wto_desktop_agent import __version__
from wto_desktop_agent.infrastructure.contracts import contract_root, validate_contract
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.ports.platform import PlatformAdapter
from wto_desktop_agent.ports.time import Clock
from wto_desktop_agent.ports.transport import AgentTransport


def _reason(code: str) -> dict[str, str]:
    return {"code": code}


class CapabilityRegistry:
    def __init__(self, platform: PlatformAdapter) -> None:
        self.platform = platform
        catalog = json.loads(
            (contract_root() / "catalog" / "capabilities-1.0.0.json").read_text(encoding="utf-8")
        )
        self.capability_ids: list[str] = list(catalog["capability_ids"])
        if len(self.capability_ids) != 15:
            raise RuntimeError("capability catalog must contain exactly 15 IDs")

    def _entry(self, capability_id: str) -> dict[str, object]:
        technical_status = "unknown"
        technical_reason: dict[str, str] | None = _reason("unknown")
        implementation = "not_implemented"
        implementation_reason: dict[str, str] | None = _reason("not_implemented")
        permission_status = "unknown"
        permission_reason: dict[str, str] | None = _reason("unknown")
        user_status = "none"
        user_reason: dict[str, str] | None = None
        background_status = "unknown"
        background_reason: dict[str, str] | None = _reason("unknown")
        provider_status = "unavailable"
        provider_reason: dict[str, str] | None = _reason("provider_unavailable")
        limitation_status = "unknown"
        limitation_reason: dict[str, str] | None = _reason("unknown")

        if capability_id == "capture.ieee80211.monitor" and self.platform.platform_id == "windows":
            technical_status = "unsupported"
            technical_reason = _reason("not_exposed_by_platform")
            implementation = "excluded"
            implementation_reason = _reason("not_applicable")
            permission_status = "not_applicable"
            permission_reason = _reason("not_applicable")
            user_status = "not_applicable"
            user_reason = _reason("not_applicable")
            background_status = "not_applicable"
            background_reason = _reason("not_applicable")
            provider_status = "not_applicable"
            provider_reason = _reason("not_applicable")
            limitation_status = "not_applicable"
            limitation_reason = _reason("not_applicable")
        elif capability_id == "traffic.pcap.replay":
            technical_status = "not_applicable"
            technical_reason = _reason("not_applicable")
            implementation = "excluded"
            implementation_reason = _reason("not_applicable")
            permission_status = "not_applicable"
            permission_reason = _reason("not_applicable")
            user_status = "not_applicable"
            user_reason = _reason("not_applicable")
            background_status = "not_applicable"
            background_reason = _reason("not_applicable")
            provider_status = "not_applicable"
            provider_reason = _reason("not_applicable")
            limitation_status = "not_applicable"
            limitation_reason = _reason("not_applicable")
        elif capability_id == "execution.background.continuous":
            technical_status = "supported"
            technical_reason = None
            implementation = "planned"
            permission_status = "required"
            permission_reason = _reason("permission_missing")
            user_status = "conditional"
            background_status = "continuous"
            background_reason = None

        return {
            "id": capability_id,
            "version": "1.0.0",
            "technical_support": {
                "status": technical_status,
                "reason": technical_reason,
            },
            "implementation_status": {
                "status": implementation,
                "reason": implementation_reason,
            },
            "permission_requirement": {
                "status": permission_status,
                "permissions": (
                    ["service.install"]
                    if capability_id == "execution.background.continuous"
                    else []
                ),
                "reason": permission_reason,
            },
            "user_interaction": {"status": user_status, "reason": user_reason},
            "background_execution": {
                "status": background_status,
                "reason": background_reason,
            },
            "provider": {
                "status": provider_status,
                "implementations": [],
                "reason": provider_reason,
            },
            "limitations": {"status": limitation_status, "reason": limitation_reason},
        }

    def entries(self) -> list[dict[str, object]]:
        return [self._entry(capability_id) for capability_id in self.capability_ids]


class ManifestService:
    def __init__(
        self,
        store: SQLiteStore,
        registry: CapabilityRegistry,
        transport: AgentTransport,
        platform: PlatformAdapter,
        clock: Clock,
    ) -> None:
        self.store = store
        self.registry = registry
        self.transport = transport
        self.platform = platform
        self.clock = clock

    async def ensure_published(self, credential: str) -> dict[str, object]:
        pending = self.store.pending_manifest()
        if pending:
            payload: dict[str, Any] = cast(dict[str, Any], json.loads(str(pending["payload"])))
        else:
            identity = self.store.identity()
            runtime = self.store.runtime_state()
            if not identity or not identity.get("agent_id") or not runtime:
                raise RuntimeError("identity and runtime are required before manifest publication")
            confirmed = self.store.confirmed_manifest()
            if confirmed:
                confirmed_payload = cast(dict[str, Any], json.loads(str(confirmed["payload"])))
                if (
                    confirmed_payload.get("agent_version") == __version__
                    and confirmed_payload.get("platform") == self.platform.platform_id
                    and confirmed_payload.get("platform_version") == self.platform.platform_version
                    and confirmed_payload.get("capabilities") == self.registry.entries()
                ):
                    return confirmed_payload
            sequence = int(runtime["manifest_acked_sequence"]) + 1
            payload = {
                "schema_version": "1.0.0",
                "manifest_id": str(uuid4()),
                "manifest_sequence": sequence,
                "agent_id": str(identity["agent_id"]),
                "agent_version": __version__,
                "platform": self.platform.platform_id,
                "platform_version": self.platform.platform_version,
                "protocol_version": "1.0.0",
                "capability_catalog_version": "1.0.0",
                "generated_at": self.clock.now().astimezone(UTC).isoformat().replace("+00:00", "Z"),
                "capabilities": self.registry.entries(),
            }
            validate_contract("capability-manifest.schema.json", payload)
            self.store.persist_manifest(str(payload["manifest_id"]), sequence, payload)
        response = await self.transport.publish_manifest(credential, payload)
        self.store.confirm_manifest(
            str(payload["manifest_id"]),
            int(payload["manifest_sequence"]),
            str(response["manifest_digest"]),
        )
        return dict(payload)
