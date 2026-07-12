from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from wto_backend.domain.models import (
    Agent,
    AgentCredential,
    AgentCredentialRotation,
    AgentPresence,
    CapabilityManifest,
    EnrollmentToken,
    IdempotencyRecord,
    SecretReplay,
)


class AgentRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def agent(self, agent_id: UUID, *, lock: bool = False) -> Agent | None:
        statement = select(Agent).where(Agent.id == agent_id)
        if lock:
            statement = statement.with_for_update()
        return self.session.scalar(statement)

    def agent_by_installation(self, installation_id: UUID, *, lock: bool = False) -> Agent | None:
        statement = select(Agent).where(Agent.installation_id == installation_id)
        if lock:
            statement = statement.with_for_update()
        return self.session.scalar(statement)

    def enrollment_token(self, token_id: UUID, *, lock: bool = False) -> EnrollmentToken | None:
        statement = select(EnrollmentToken).where(EnrollmentToken.id == token_id)
        if lock:
            statement = statement.with_for_update()
        return self.session.scalar(statement)

    def credential(self, credential_id: UUID, *, lock: bool = False) -> AgentCredential | None:
        statement = select(AgentCredential).where(AgentCredential.id == credential_id)
        if lock:
            statement = statement.with_for_update()
        return self.session.scalar(statement)

    def active_credential(self, agent_id: UUID) -> AgentCredential | None:
        return self.session.scalar(
            select(AgentCredential).where(
                AgentCredential.agent_id == agent_id, AgentCredential.state == "active"
            )
        )

    def pending_rotation(
        self, agent_id: UUID, *, lock: bool = False
    ) -> AgentCredentialRotation | None:
        statement = select(AgentCredentialRotation).where(
            AgentCredentialRotation.agent_id == agent_id,
            AgentCredentialRotation.state == "pending",
        )
        if lock:
            statement = statement.with_for_update()
        return self.session.scalar(statement)

    def rotation(self, rotation_id: UUID, *, lock: bool = False) -> AgentCredentialRotation | None:
        statement = select(AgentCredentialRotation).where(AgentCredentialRotation.id == rotation_id)
        if lock:
            statement = statement.with_for_update()
        return self.session.scalar(statement)

    def idempotency(
        self,
        *,
        principal_type: str,
        principal_id: UUID,
        operation_id: str,
        idempotency_key: UUID,
        lock: bool = False,
    ) -> IdempotencyRecord | None:
        statement = select(IdempotencyRecord).where(
            IdempotencyRecord.principal_type == principal_type,
            IdempotencyRecord.principal_id == principal_id,
            IdempotencyRecord.operation_id == operation_id,
            IdempotencyRecord.idempotency_key == idempotency_key,
        )
        if lock:
            statement = statement.with_for_update()
        return self.session.scalar(statement)

    def secret_replay(self, record_id: UUID) -> SecretReplay | None:
        return self.session.scalar(
            select(SecretReplay).where(SecretReplay.idempotency_record_id == record_id)
        )

    def manifest(self, agent_id: UUID, manifest_id: UUID) -> CapabilityManifest | None:
        return self.session.scalar(
            select(CapabilityManifest).where(
                CapabilityManifest.agent_id == agent_id,
                CapabilityManifest.id == manifest_id,
            )
        )

    def presence(self, agent_id: UUID, *, lock: bool = False) -> AgentPresence | None:
        statement = select(AgentPresence).where(AgentPresence.agent_id == agent_id)
        if lock:
            statement = statement.with_for_update()
        return self.session.scalar(statement)
