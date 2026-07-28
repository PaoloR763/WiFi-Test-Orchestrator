from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from wto_backend.api.agent_schemas import (
    DesktopHeartbeatRequest,
    MobilePresenceRequest,
    PresenceResponse,
)
from wto_backend.audit import write_audit
from wto_backend.config import Settings
from wto_backend.contracts import (
    ContractValidationError,
    canonical_json,
    validate_contract,
)
from wto_backend.domain.models import AgentPresence, CapabilityManifest
from wto_backend.logging import correlation_id_context
from wto_backend.repositories.agents import AgentRepository
from wto_backend.services.errors import (
    AgentAuthenticationError,
    ConflictError,
    ProtocolVersionError,
    RequestClockSkewError,
    SequenceConflictError,
)


class AgentProtocolService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings
        self.repo = AgentRepository(session)

    def publish_manifest(self, *, agent_id: UUID, document: dict[str, Any]) -> dict[str, Any]:
        try:
            validate_contract("capability-manifest.schema.json", document)
        except ContractValidationError:
            self._audit_incompatibility(agent_id, "manifest_schema_invalid")
            raise
        if document.get("agent_id") != str(agent_id):
            raise AgentAuthenticationError
        if document.get("capability_catalog_version") != "1.0.0":
            self._audit_incompatibility(agent_id, "capability_catalog_incompatible")
            raise ProtocolVersionError
        manifest_id = UUID(str(document["manifest_id"]))
        sequence = int(document["manifest_sequence"])
        digest = hashlib.sha256(canonical_json(document)).digest()
        existing = self.session.scalar(
            select(CapabilityManifest).where(
                CapabilityManifest.agent_id == agent_id,
                CapabilityManifest.manifest_sequence == sequence,
            )
        )
        if existing is not None:
            if existing.document_digest != digest or existing.id != manifest_id:
                raise SequenceConflictError
            return {
                "schema_version": "1.0.0",
                "manifest_id": str(existing.id),
                "manifest_digest": existing.document_digest.hex(),
                "server_received_at": existing.server_received_at.isoformat().replace(
                    "+00:00", "Z"
                ),
            }
        now = datetime.now(UTC)
        manifest = CapabilityManifest(
            id=manifest_id,
            agent_id=agent_id,
            manifest_sequence=sequence,
            schema_version=str(document["schema_version"]),
            catalog_version=str(document["capability_catalog_version"]),
            generated_at=datetime.fromisoformat(
                str(document["generated_at"]).replace("Z", "+00:00")
            ),
            server_received_at=now,
            document_digest=digest,
            document=document,
        )
        self.session.add(manifest)
        self.session.commit()
        return {
            "schema_version": "1.0.0",
            "manifest_id": str(manifest.id),
            "manifest_digest": digest.hex(),
            "server_received_at": now.isoformat().replace("+00:00", "Z"),
        }

    def heartbeat(self, *, agent_id: UUID, payload: DesktopHeartbeatRequest) -> PresenceResponse:
        validate_contract("desktop-heartbeat.schema.json", payload.model_dump(mode="json"))
        return self._presence(
            agent_id=agent_id,
            kind="desktop",
            payload=payload.model_dump(mode="json"),
            boot_id=payload.boot_id,
            sequence=payload.sequence,
            reported_at=payload.agent_reported_at,
            manifest_id=payload.manifest_id,
            manifest_digest=payload.manifest_digest,
            ttl=90,
            poll_after=30,
        )

    def mobile_presence(
        self, *, agent_id: UUID, payload: MobilePresenceRequest
    ) -> PresenceResponse:
        validate_contract("mobile-presence.schema.json", payload.model_dump(mode="json"))
        return self._presence(
            agent_id=agent_id,
            kind="mobile",
            payload=payload.model_dump(mode="json"),
            boot_id=payload.boot_id,
            sequence=payload.sequence,
            reported_at=payload.agent_reported_at,
            manifest_id=payload.manifest_id,
            manifest_digest=payload.manifest_digest,
            ttl=120,
            poll_after=60,
        )

    def validate_stub(self, *, schema_name: str, payload: dict[str, Any]) -> None:
        validate_contract(schema_name, payload)

    def _presence(
        self,
        *,
        agent_id: UUID,
        kind: str,
        payload: dict[str, Any],
        boot_id: UUID,
        sequence: int,
        reported_at: datetime,
        manifest_id: UUID,
        manifest_digest: str,
        ttl: int,
        poll_after: int,
    ) -> PresenceResponse:
        if payload.get("agent_id") != str(agent_id):
            raise AgentAuthenticationError
        digest = hashlib.sha256(canonical_json(payload)).digest()
        presence = self.repo.presence(agent_id, lock=True)
        if presence is not None and presence.boot_id == boot_id and presence.sequence == sequence:
            agent = self.repo.agent(agent_id, lock=True, refresh_existing=True)
            if agent is None or agent.revoked_at is not None or not agent.is_active:
                raise AgentAuthenticationError
            if digest != presence.payload_digest:
                raise SequenceConflictError
            return PresenceResponse(
                accepted_sequence=presence.sequence,
                server_received_at=presence.server_received_at,
                presence_expires_at=presence.presence_expires_at,
                poll_after_seconds=poll_after,
            )
        now = datetime.now(UTC)
        reported = reported_at.astimezone(UTC)
        if abs((now - reported).total_seconds()) > self.settings.agent_clock_skew_seconds:
            raise RequestClockSkewError
        manifest = self.repo.manifest(agent_id, manifest_id)
        if manifest is None or manifest.document_digest.hex() != manifest_digest:
            raise ConflictError
        if presence is not None and presence.boot_id == boot_id:
            if sequence < presence.sequence:
                raise SequenceConflictError
        expires = now + timedelta(seconds=ttl)
        if presence is None:
            presence = AgentPresence(
                agent_id=agent_id,
                kind=kind,
                boot_id=boot_id,
                sequence=sequence,
                payload_digest=digest,
                agent_reported_at=reported,
                server_received_at=now,
                presence_expires_at=expires,
                manifest_id=manifest_id,
            )
            self.session.add(presence)
        else:
            presence.kind = kind
            presence.boot_id = boot_id
            presence.sequence = sequence
            presence.payload_digest = digest
            presence.agent_reported_at = reported
            presence.server_received_at = now
            presence.presence_expires_at = expires
            presence.manifest_id = manifest_id
        agent = self.repo.agent(agent_id, lock=True)
        if agent is None or agent.revoked_at is not None or not agent.is_active:
            raise AgentAuthenticationError
        agent.last_seen_at = now
        self.session.commit()
        return PresenceResponse(
            accepted_sequence=sequence,
            server_received_at=now,
            presence_expires_at=expires,
            poll_after_seconds=poll_after,
        )

    def _audit_incompatibility(self, agent_id: UUID, reason: str) -> None:
        write_audit(
            self.session,
            actor_type="agent",
            actor_id=None,
            actor_agent_id=agent_id,
            action="agent_protocol.incompatible",
            resource_type="agent",
            resource_id=agent_id,
            outcome="denied",
            correlation_id=correlation_id_context.get() or "unavailable",
            metadata={"agent_id": str(agent_id), "reason_code": reason},
        )
        self.session.commit()
