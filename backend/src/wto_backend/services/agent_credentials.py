from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from wto_backend.api.agent_schemas import (
    AgentCredentialResponse,
    CredentialMetadata,
    RotationActivateRequest,
    RotationActivateResponse,
    RotationCreateRequest,
    RotationCreateResponse,
)
from wto_backend.audit import write_audit
from wto_backend.config import Settings
from wto_backend.contracts import canonical_json
from wto_backend.domain.models import AgentCredential, AgentCredentialRotation, User
from wto_backend.logging import correlation_id_context
from wto_backend.repositories.agents import AgentRepository
from wto_backend.security.agent_credentials import new_agent_credential, secret_digest
from wto_backend.security.secret_replay import SecretReplayCipher
from wto_backend.services.errors import (
    AgentAuthenticationError,
    ConflictError,
    ResourceNotFoundError,
    SecretReplayExpiredError,
)
from wto_backend.services.idempotency import IdempotencyService


class AgentCredentialService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings
        self.repo = AgentRepository(session)
        self.idempotency = IdempotencyService(
            session,
            SecretReplayCipher(settings.secret_replay_encryption_key.get_secret_value()),
        )

    def create_rotation(
        self,
        *,
        agent_id: UUID,
        active_credential: AgentCredential,
        payload: RotationCreateRequest,
    ) -> RotationCreateResponse:
        fingerprint = IdempotencyService.fingerprint(
            canonical_json({"schema_version": payload.schema_version})
        )
        try:
            start = self.idempotency.begin(
                principal_type="agent",
                principal_id=agent_id,
                operation_id="agent.credential.rotate",
                idempotency_key=payload.idempotency_key,
                request_fingerprint=fingerprint,
                secret_response=True,
            )
        except SecretReplayExpiredError:
            self._expire_pending(agent_id)
            self.session.commit()
            raise
        if not start.is_new:
            assert start.replay_body is not None
            response = RotationCreateResponse.model_validate(start.replay_body)
            write_audit(
                self.session,
                actor_type="agent",
                actor_id=None,
                actor_agent_id=agent_id,
                action="idempotency.replay",
                resource_type="agent_credential_rotation",
                resource_id=response.rotation_id,
                outcome="success",
                correlation_id=correlation_id_context.get() or "unavailable",
                metadata={
                    "operation_id": "agent.credential.rotate",
                    "agent_id": str(agent_id),
                    "rotation_id": str(response.rotation_id),
                },
            )
            self.session.commit()
            return response
        agent = self.repo.agent(agent_id, lock=True)
        if agent is None or not agent.is_active or agent.revoked_at is not None:
            raise AgentAuthenticationError
        self._expire_pending(agent_id)
        if self.repo.pending_rotation(agent_id, lock=True) is not None:
            raise ConflictError
        active = self.repo.credential(active_credential.id, lock=True)
        if active is None or active.state != "active":
            raise AgentAuthenticationError
        highest = self.session.scalar(
            select(func.max(AgentCredential.credential_version)).where(
                AgentCredential.agent_id == agent_id
            )
        )
        now = datetime.now(UTC)
        credential_id = uuid4()
        value, secret = new_agent_credential(credential_id)
        pending = AgentCredential(
            id=credential_id,
            agent_id=agent_id,
            credential_version=int(highest or 0) + 1,
            secret_digest=secret_digest(
                self.settings.agent_credential_hmac_key.get_secret_value(), secret
            ),
            digest_key_version=1,
            state="pending",
            issued_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        self.session.add(pending)
        self.session.flush()
        rotation = AgentCredentialRotation(
            agent_id=agent_id,
            previous_credential_id=active.id,
            pending_credential_id=pending.id,
            state="pending",
            created_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        self.session.add(rotation)
        self.session.flush()
        response = RotationCreateResponse(
            rotation_id=rotation.id,
            expires_at=rotation.expires_at,
            pending_credential=AgentCredentialResponse(
                credential_id=pending.id,
                credential_version=pending.credential_version,
                credential=value,
                issued_at=pending.issued_at,
                expires_at=pending.expires_at,
                state="pending",
            ),
        )
        self.idempotency.complete_secret(
            start.record, body=response.model_dump(mode="json"), status=201
        )
        write_audit(
            self.session,
            actor_type="agent",
            actor_id=None,
            actor_agent_id=agent_id,
            action="agent_credential.rotation_create",
            resource_type="agent_credential_rotation",
            resource_id=rotation.id,
            outcome="success",
            correlation_id=correlation_id_context.get() or "unavailable",
            metadata={
                "agent_id": str(agent_id),
                "credential_id": str(pending.id),
                "credential_version": pending.credential_version,
                "rotation_id": str(rotation.id),
            },
        )
        self.session.commit()
        return response

    def activate_rotation(
        self,
        *,
        agent_id: UUID,
        supplied_credential: AgentCredential,
        rotation_id: UUID,
        payload: RotationActivateRequest,
    ) -> RotationActivateResponse:
        start = self.idempotency.begin(
            principal_type="agent",
            principal_id=agent_id,
            operation_id=f"agent.credential.activate:{rotation_id}",
            idempotency_key=payload.idempotency_key,
            request_fingerprint=IdempotencyService.fingerprint(
                canonical_json(
                    {
                        "schema_version": payload.schema_version,
                        "rotation_id": str(rotation_id),
                    }
                )
            ),
            secret_response=False,
        )
        if not start.is_new:
            assert start.replay_body is not None
            response = RotationActivateResponse.model_validate(start.replay_body)
            write_audit(
                self.session,
                actor_type="agent",
                actor_id=None,
                actor_agent_id=agent_id,
                action="idempotency.replay",
                resource_type="agent_credential_rotation",
                resource_id=response.rotation_id,
                outcome="success",
                correlation_id=correlation_id_context.get() or "unavailable",
                metadata={
                    "operation_id": "agent.credential.activate",
                    "agent_id": str(agent_id),
                    "rotation_id": str(response.rotation_id),
                },
            )
            self.session.commit()
            return response
        agent = self.repo.agent(agent_id, lock=True)
        rotation = self.repo.rotation(rotation_id, lock=True)
        if (
            agent is None
            or not agent.is_active
            or agent.revoked_at is not None
            or rotation is None
            or rotation.agent_id != agent_id
            or rotation.pending_credential_id != supplied_credential.id
        ):
            raise AgentAuthenticationError
        now = datetime.now(UTC)
        if rotation.state != "pending" or rotation.expires_at <= now:
            raise ConflictError
        pending = self.repo.credential(rotation.pending_credential_id, lock=True)
        previous = self.repo.credential(rotation.previous_credential_id, lock=True)
        if pending is None or previous is None or pending.state != "pending":
            raise ConflictError
        previous.state = "revoked"
        previous.revoked_at = now
        previous.revocation_reason = "credential_rotated"
        self.session.flush()
        pending.state = "active"
        pending.activated_at = now
        pending.expires_at = now + timedelta(days=self.settings.agent_credential_days)
        rotation.state = "activated"
        rotation.activated_at = now
        response = RotationActivateResponse(
            rotation_id=rotation.id,
            credential_id=pending.id,
            credential_version=pending.credential_version,
            activated_at=now,
        )
        self.idempotency.complete_public(
            start.record, body=response.model_dump(mode="json"), status=200
        )
        write_audit(
            self.session,
            actor_type="agent",
            actor_id=None,
            actor_agent_id=agent_id,
            action="agent_credential.rotation_activate",
            resource_type="agent_credential_rotation",
            resource_id=rotation.id,
            outcome="success",
            correlation_id=correlation_id_context.get() or "unavailable",
            metadata={
                "agent_id": str(agent_id),
                "credential_id": str(pending.id),
                "credential_version": pending.credential_version,
                "rotation_id": str(rotation.id),
            },
        )
        self.session.commit()
        return response

    def credentials(self, agent_id: UUID) -> list[CredentialMetadata]:
        if self.repo.agent(agent_id) is None:
            raise ResourceNotFoundError
        records = self.session.scalars(
            select(AgentCredential)
            .where(AgentCredential.agent_id == agent_id)
            .order_by(AgentCredential.credential_version)
        )
        return [
            CredentialMetadata(
                credential_id=item.id,
                credential_version=item.credential_version,
                state=item.state,
                issued_at=item.issued_at,
                activated_at=item.activated_at,
                expires_at=item.expires_at,
                revoked_at=item.revoked_at,
                revocation_reason=item.revocation_reason,
            )
            for item in records
        ]

    def revoke_credential(self, *, agent_id: UUID, credential_id: UUID, actor: User) -> None:
        self.repo.agent(agent_id, lock=True)
        credential = self.repo.credential(credential_id, lock=True)
        if credential is None or credential.agent_id != agent_id:
            raise ResourceNotFoundError
        now = datetime.now(UTC)
        credential.state = "revoked"
        credential.revoked_at = now
        credential.revoked_by_user_id = actor.id
        credential.revocation_reason = "administrator_revocation"
        write_audit(
            self.session,
            actor_type="user",
            actor_id=actor.id,
            action="agent_credential.revoke",
            resource_type="agent_credential",
            resource_id=credential.id,
            outcome="success",
            correlation_id=correlation_id_context.get() or "unavailable",
            metadata={"agent_id": str(agent_id), "credential_id": str(credential.id)},
        )
        self.session.commit()

    def revoke_agent(self, *, agent_id: UUID, actor: User) -> None:
        agent = self.repo.agent(agent_id, lock=True)
        if agent is None:
            raise ResourceNotFoundError
        now = datetime.now(UTC)
        agent.is_active = False
        agent.disabled_at = now
        agent.revoked_at = now
        agent.revoked_by_user_id = actor.id
        agent.revocation_reason = "administrator_revocation"
        self.session.execute(
            update(AgentCredential)
            .where(
                AgentCredential.agent_id == agent_id,
                AgentCredential.state.in_(["active", "pending"]),
            )
            .values(
                state="revoked",
                revoked_at=now,
                revoked_by_user_id=actor.id,
                revocation_reason="agent_revoked",
            )
        )
        self.session.execute(
            update(AgentCredentialRotation)
            .where(
                AgentCredentialRotation.agent_id == agent_id,
                AgentCredentialRotation.state == "pending",
            )
            .values(state="revoked")
        )
        write_audit(
            self.session,
            actor_type="user",
            actor_id=actor.id,
            action="agent.revoke",
            resource_type="agent",
            resource_id=agent.id,
            outcome="success",
            correlation_id=correlation_id_context.get() or "unavailable",
            metadata={"agent_id": str(agent.id)},
        )
        self.session.commit()

    def _expire_pending(self, agent_id: UUID) -> None:
        rotation = self.repo.pending_rotation(agent_id, lock=True)
        if rotation is None or rotation.expires_at > datetime.now(UTC):
            return
        pending = self.repo.credential(rotation.pending_credential_id, lock=True)
        rotation.state = "expired"
        if pending is not None and pending.state == "pending":
            pending.state = "expired"
            pending.revoked_at = datetime.now(UTC)
            pending.revocation_reason = "rotation_expired"
