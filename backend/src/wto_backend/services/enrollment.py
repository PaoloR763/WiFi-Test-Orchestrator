from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from wto_backend.api.agent_schemas import (
    AgentCredentialResponse,
    AgentRegistrationRequest,
    AgentRegistrationResponse,
    EnrollmentTokenCreateRequest,
    EnrollmentTokenResponse,
)
from wto_backend.audit import write_audit
from wto_backend.config import Settings
from wto_backend.contracts import canonical_json, validate_contract
from wto_backend.domain.models import (
    Agent,
    AgentCredential,
    Device,
    EnrollmentToken,
    User,
)
from wto_backend.logging import correlation_id_context
from wto_backend.repositories.agents import AgentRepository
from wto_backend.security.agent_credentials import (
    InvalidMachineSecretError,
    new_agent_credential,
    new_enrollment_token,
    parse_machine_secret,
    secret_digest,
    verify_secret,
)
from wto_backend.security.secret_replay import SecretReplayCipher
from wto_backend.services.errors import (
    ConflictError,
    EnrollmentFailedError,
    RequestClockSkewError,
)
from wto_backend.services.idempotency import IdempotencyService


def utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timezone is required")
    return value.astimezone(UTC)


class EnrollmentService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings
        self.repo = AgentRepository(session)
        self.idempotency = IdempotencyService(
            session,
            SecretReplayCipher(settings.secret_replay_encryption_key.get_secret_value()),
        )

    def create_token(
        self, *, payload: EnrollmentTokenCreateRequest, actor: User
    ) -> EnrollmentTokenResponse:
        if payload.scope == "agent.recover" and payload.bound_agent_id is None:
            raise ConflictError("recovery tokens require a bound agent")
        if payload.scope == "agent.enroll" and payload.bound_agent_id is not None:
            raise ConflictError("enrollment tokens cannot bind an existing agent")
        if payload.bound_agent_id is not None and self.repo.agent(payload.bound_agent_id) is None:
            raise ConflictError
        now = datetime.now(UTC)
        token_id = uuid4()
        token_value, token_secret = new_enrollment_token(token_id)
        restrictions: dict[str, Any] = {"allowed_platforms": payload.allowed_platforms}
        if payload.bound_agent_id is not None:
            restrictions["bound_agent_id"] = str(payload.bound_agent_id)
        record = EnrollmentToken(
            id=token_id,
            token_digest=secret_digest(
                self.settings.enrollment_token_hmac_key.get_secret_value(), token_secret
            ),
            digest_key_version=1,
            scope=payload.scope,
            max_uses=1,
            uses_consumed=0,
            restrictions=restrictions,
            created_by_user_id=actor.id,
            created_at=now,
            expires_at=now + timedelta(minutes=payload.expires_in_minutes),
        )
        self.session.add(record)
        write_audit(
            self.session,
            actor_type="user",
            actor_id=actor.id,
            action="enrollment_token.create",
            resource_type="enrollment_token",
            resource_id=record.id,
            outcome="success",
            correlation_id=correlation_id_context.get() or "unavailable",
            metadata={"enrollment_token_id": str(record.id), "scope": record.scope},
        )
        self.session.commit()
        return EnrollmentTokenResponse(
            enrollment_token_id=record.id,
            enrollment_token=token_value,
            scope=record.scope,
            expires_at=record.expires_at,
        )

    def revoke_token(self, *, token_id: UUID, actor: User) -> None:
        record = self.repo.enrollment_token(token_id, lock=True)
        if record is None:
            raise ConflictError
        if record.revoked_at is None:
            record.revoked_at = datetime.now(UTC)
            record.revoked_by_user_id = actor.id
            record.revocation_reason = "administrator_revocation"
        write_audit(
            self.session,
            actor_type="user",
            actor_id=actor.id,
            action="enrollment_token.revoke",
            resource_type="enrollment_token",
            resource_id=record.id,
            outcome="success",
            correlation_id=correlation_id_context.get() or "unavailable",
            metadata={"enrollment_token_id": str(record.id)},
        )
        self.session.commit()

    def register(self, payload: AgentRegistrationRequest) -> AgentRegistrationResponse:
        raw = payload.model_dump(mode="json")
        validate_contract("agent-registration-request.schema.json", raw)
        reported = utc(payload.agent_reported_at)
        now = datetime.now(UTC)
        if abs((now - reported).total_seconds()) > self.settings.agent_clock_skew_seconds:
            raise RequestClockSkewError
        try:
            parsed = parse_machine_secret(payload.enrollment_token, prefix="wto_enr_1")
        except InvalidMachineSecretError as error:
            raise EnrollmentFailedError from error
        token = self.repo.enrollment_token(parsed.locator, lock=True)
        if token is None or not verify_secret(
            self.settings.enrollment_token_hmac_key.get_secret_value(),
            parsed.secret,
            token.token_digest,
        ):
            raise EnrollmentFailedError
        fingerprint_payload = dict(raw)
        del fingerprint_payload["enrollment_token"]
        del fingerprint_payload["idempotency_key"]
        operation_id = f"agent.register:{payload.installation_id}"
        start = self.idempotency.begin(
            principal_type="enrollment_token",
            principal_id=token.id,
            operation_id=operation_id,
            idempotency_key=payload.idempotency_key,
            request_fingerprint=IdempotencyService.fingerprint(canonical_json(fingerprint_payload)),
            secret_response=True,
        )
        if not start.is_new:
            assert start.replay_body is not None
            response = AgentRegistrationResponse.model_validate(start.replay_body)
            write_audit(
                self.session,
                actor_type="agent",
                actor_id=None,
                actor_agent_id=response.agent_id,
                action="idempotency.replay",
                resource_type="agent",
                resource_id=response.agent_id,
                outcome="success",
                correlation_id=correlation_id_context.get() or "unavailable",
                metadata={
                    "operation_id": operation_id,
                    "agent_id": str(response.agent_id),
                },
            )
            self.session.commit()
            return response
        if (
            token.revoked_at is not None
            or token.expires_at <= now
            or token.uses_consumed >= token.max_uses
        ):
            raise EnrollmentFailedError
        allowed = token.restrictions.get("allowed_platforms", [])
        if allowed and payload.platform not in allowed:
            raise EnrollmentFailedError
        if token.scope == "agent.recover":
            bound = token.restrictions.get("bound_agent_id")
            if not isinstance(bound, str):
                raise EnrollmentFailedError
            agent = self.repo.agent(UUID(bound), lock=True)
            if agent is None:
                raise EnrollmentFailedError
            device_id = agent.device_id
            agent.is_active = True
            agent.disabled_at = None
            agent.revoked_at = None
            agent.revoked_by_user_id = None
            agent.revocation_reason = None
            agent.installation_id = payload.installation_id
            agent.display_name = payload.display_name
            if device_id is None:
                raise EnrollmentFailedError
        else:
            if self.repo.agent_by_installation(payload.installation_id, lock=True) is not None:
                raise EnrollmentFailedError
            device = Device(
                display_name=payload.display_name,
                platform=payload.platform,
                platform_version=payload.platform_version,
            )
            self.session.add(device)
            self.session.flush()
            device_id = device.id
            agent = Agent(
                device_id=device.id,
                display_name=payload.display_name,
                installation_id=payload.installation_id,
                protocol_min_version=payload.protocol_min_version,
                protocol_max_version=payload.protocol_max_version,
                protocol_version="1.0.0",
            )
            self.session.add(agent)
            self.session.flush()
        existing = self.repo.active_credential(agent.id)
        if existing is not None:
            existing.state = "revoked"
            existing.revoked_at = now
            existing.revocation_reason = "agent_recovery"
        credential_id = uuid4()
        credential_value, credential_secret = new_agent_credential(credential_id)
        highest = self.session.scalar(
            select(func.max(AgentCredential.credential_version)).where(
                AgentCredential.agent_id == agent.id
            )
        )
        version = int(highest or 0) + 1
        expires_at = now + timedelta(days=self.settings.agent_credential_days)
        credential = AgentCredential(
            id=credential_id,
            agent_id=agent.id,
            credential_version=version,
            secret_digest=secret_digest(
                self.settings.agent_credential_hmac_key.get_secret_value(),
                credential_secret,
            ),
            digest_key_version=1,
            state="active",
            issued_at=now,
            activated_at=now,
            expires_at=expires_at,
        )
        self.session.add(credential)
        token.uses_consumed += 1
        token.consumed_at = now
        response = AgentRegistrationResponse(
            device_id=device_id,
            agent_id=agent.id,
            server_received_at=now,
            credential=AgentCredentialResponse(
                credential_id=credential.id,
                credential_version=credential.credential_version,
                credential=credential_value,
                issued_at=now,
                expires_at=expires_at,
                state="active",
            ),
        )
        self.idempotency.complete_secret(
            start.record, body=response.model_dump(mode="json"), status=201
        )
        write_audit(
            self.session,
            actor_type="agent",
            actor_id=None,
            actor_agent_id=agent.id,
            action="agent.enroll" if token.scope == "agent.enroll" else "agent.recover",
            resource_type="agent",
            resource_id=agent.id,
            outcome="success",
            correlation_id=correlation_id_context.get() or "unavailable",
            metadata={
                "agent_id": str(agent.id),
                "credential_id": str(credential.id),
                "credential_version": version,
                "installation_id": str(payload.installation_id),
            },
        )
        self.session.commit()
        return response
