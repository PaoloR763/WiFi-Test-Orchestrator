from __future__ import annotations

import asyncio
import copy
import json
from datetime import UTC
from typing import Any, cast
from uuid import uuid4

from wto_desktop_agent import __version__
from wto_desktop_agent.infrastructure.contracts import contract_root, validate_contract
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore, digest
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

    def _entry(
        self,
        capability_id: str,
        overrides: dict[str, dict[str, object]],
    ) -> dict[str, object]:
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

        entry: dict[str, object] = {
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
        override = overrides.get(capability_id)
        if override:
            unknown = set(override) - {
                "technical_support",
                "implementation_status",
                "permission_requirement",
                "user_interaction",
                "background_execution",
                "provider",
                "limitations",
            }
            if unknown:
                raise RuntimeError(f"unknown capability override dimensions: {sorted(unknown)}")
            entry.update(override)
        return entry

    def entries(self) -> list[dict[str, object]]:
        overrides = copy.deepcopy(self.platform.capability_overrides())
        return [self._entry(capability_id, overrides) for capability_id in self.capability_ids]

    async def entries_async(self) -> list[dict[str, object]]:
        method = getattr(self.platform, "capability_overrides_async", None)
        if method is None:
            raw = await asyncio.to_thread(self.platform.capability_overrides)
        else:
            raw = await method()
        overrides = copy.deepcopy(raw)
        return [self._entry(capability_id, overrides) for capability_id in self.capability_ids]


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

    @staticmethod
    def _validated_manifest_payload(
        row: dict[str, Any],
        *,
        expected_state: str,
    ) -> dict[str, Any]:
        try:
            payload = cast(dict[str, Any], json.loads(str(row["payload"])))
            row_sequence = int(row["sequence"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError("durable capability manifest row is invalid") from error
        if (
            row.get("state") != expected_state
            or digest(payload) != row.get("payload_hash")
            or payload.get("manifest_id") != row.get("manifest_id")
            or payload.get("manifest_sequence") != row_sequence
        ):
            raise RuntimeError("durable capability manifest identity is invalid")
        if expected_state == "confirmed" and (
            not row.get("server_digest") or not row.get("confirmed_at")
        ):
            raise RuntimeError("confirmed capability manifest lacks server evidence")
        validate_contract("capability-manifest.schema.json", payload)
        return payload

    def _static_manifest_is_compatible(
        self,
        payload: dict[str, Any],
        identity: dict[str, Any],
    ) -> bool:
        validate_contract("capability-manifest.schema.json", payload)
        return (
            payload.get("schema_version") == "1.0.0"
            and payload.get("agent_id") == str(identity["agent_id"])
            and payload.get("agent_version") == __version__
            and payload.get("platform") == self.platform.platform_id
            and payload.get("platform_version") == self.platform.platform_version
            and payload.get("protocol_version") == "1.0.0"
            and payload.get("capability_catalog_version") == "1.0.0"
        )

    async def ensure_fast_start_published(self, credential: str) -> bool:
        """Ensure a usable manifest without refreshing live platform probes.

        Returns ``True`` when a live capability refresh is still required after
        already-authorized queued/retried work has had a chance to complete.
        Initial publication and static manifest incompatibilities retain the
        normal fail-closed live publication path.
        """

        if self.store.pending_manifest():
            await self.ensure_published(credential)
        confirmed = self.store.confirmed_manifest()
        identity = self.store.identity()
        runtime = self.store.runtime_state()
        if confirmed and identity and identity.get("agent_id") and runtime:
            payload = self._validated_manifest_payload(confirmed, expected_state="confirmed")
            if int(confirmed["sequence"]) == int(
                runtime["manifest_acked_sequence"]
            ) and self._static_manifest_is_compatible(payload, identity):
                return True
        await self.ensure_published(credential)
        return False

    async def ensure_published(self, credential: str) -> dict[str, object]:
        pending = self.store.pending_manifest()
        if pending:
            payload = self._validated_manifest_payload(pending, expected_state="pending")
        else:
            identity = self.store.identity()
            runtime = self.store.runtime_state()
            if not identity or not identity.get("agent_id") or not runtime:
                raise RuntimeError("identity and runtime are required before manifest publication")
            capabilities = await self.registry.entries_async()
            confirmed = self.store.confirmed_manifest()
            if confirmed:
                confirmed_payload = self._validated_manifest_payload(
                    confirmed,
                    expected_state="confirmed",
                )
                if (
                    int(confirmed["sequence"]) == int(runtime["manifest_acked_sequence"])
                    and self._static_manifest_is_compatible(confirmed_payload, identity)
                    and confirmed_payload.get("capabilities") == capabilities
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
                "capabilities": capabilities,
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
