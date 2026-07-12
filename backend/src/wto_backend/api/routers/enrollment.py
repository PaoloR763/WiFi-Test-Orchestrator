from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, Response, status
from sqlalchemy.orm import Session

from wto_backend.api.agent_schemas import (
    AgentRegistrationRequest,
    AgentRegistrationResponse,
    EnrollmentTokenCreateRequest,
    EnrollmentTokenResponse,
)
from wto_backend.api.dependencies import (
    effective_client_ip,
    get_session,
    require_permissions,
)
from wto_backend.audit import write_audit
from wto_backend.config import Settings
from wto_backend.domain.models import User
from wto_backend.logging import correlation_id_context
from wto_backend.security.agent_credentials import (
    InvalidMachineSecretError,
    parse_machine_secret,
)
from wto_backend.security.fingerprints import hmac_fingerprint
from wto_backend.security.rate_limit import RateLimitUnavailableError
from wto_backend.services.enrollment import EnrollmentService
from wto_backend.services.errors import (
    DependencyUnavailableError,
    DomainError,
    EnrollmentFailedError,
    RateLimitedError,
)

router = APIRouter(tags=["agent-enrollment"])


@router.post(
    "/enrollment-tokens",
    response_model=EnrollmentTokenResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_enrollment_token(
    payload: EnrollmentTokenCreateRequest,
    principal: Annotated[
        tuple[User, object], Depends(require_permissions("enrollment_tokens.create"))
    ],
    session: Annotated[Session, Depends(get_session)],
    request: Request,
) -> EnrollmentTokenResponse:
    return EnrollmentService(session, request.app.state.settings).create_token(
        payload=payload, actor=principal[0]
    )


@router.post("/enrollment-tokens/{token_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
def revoke_enrollment_token(
    token_id: UUID,
    principal: Annotated[
        tuple[User, object], Depends(require_permissions("enrollment_tokens.revoke"))
    ],
    session: Annotated[Session, Depends(get_session)],
    request: Request,
) -> Response:
    EnrollmentService(session, request.app.state.settings).revoke_token(
        token_id=token_id, actor=principal[0]
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/agents/{agent_id}/recovery-enrollment-tokens",
    response_model=EnrollmentTokenResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_recovery_token(
    agent_id: UUID,
    principal: Annotated[tuple[User, object], Depends(require_permissions("agents.recover"))],
    session: Annotated[Session, Depends(get_session)],
    request: Request,
    expires_in_minutes: int = 15,
) -> EnrollmentTokenResponse:
    payload = EnrollmentTokenCreateRequest(
        scope="agent.recover",
        expires_in_minutes=expires_in_minutes,
        bound_agent_id=agent_id,
    )
    return EnrollmentService(session, request.app.state.settings).create_token(
        payload=payload, actor=principal[0]
    )


@router.post(
    "/agent-enrollments",
    response_model=AgentRegistrationResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_agent(
    payload: AgentRegistrationRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    idempotency_key: Annotated[UUID, Header(alias="Idempotency-Key")],
) -> AgentRegistrationResponse:
    if idempotency_key != payload.idempotency_key:
        raise EnrollmentFailedError
    settings: Settings = request.app.state.settings
    try:
        token_id = parse_machine_secret(payload.enrollment_token, prefix="wto_enr_1").locator
    except InvalidMachineSecretError as error:
        write_audit(
            session,
            actor_type="anonymous",
            actor_id=None,
            action="agent.enroll_rejected",
            resource_type="enrollment_token",
            resource_id=None,
            outcome="denied",
            correlation_id=correlation_id_context.get() or "unavailable",
            metadata={
                "operation_id": "agent.register",
                "reason_code": "invalid_enrollment_token",
            },
        )
        session.commit()
        raise EnrollmentFailedError from error
    ip = effective_client_ip(request, settings)
    ip_fingerprint = hmac_fingerprint(settings.rate_limit_hmac_key.get_secret_value(), ip)
    token_fingerprint = hmac_fingerprint(
        settings.rate_limit_hmac_key.get_secret_value(), str(token_id)
    )
    try:
        decision = request.app.state.enrollment_rate_limiter.check(
            ip_fingerprint=ip_fingerprint, identifier_fingerprint=token_fingerprint
        )
    except RateLimitUnavailableError as error:
        raise DependencyUnavailableError from error
    if not decision.allowed:
        raise RateLimitedError
    try:
        return EnrollmentService(session, settings).register(payload)
    except DomainError as error:
        session.rollback()
        write_audit(
            session,
            actor_type="anonymous",
            actor_id=None,
            action="agent.enroll_rejected",
            resource_type="enrollment_token",
            resource_id=token_id,
            outcome="denied",
            correlation_id=correlation_id_context.get() or "unavailable",
            metadata={
                "enrollment_token_id": str(token_id),
                "operation_id": "agent.register",
                "reason_code": error.code,
            },
        )
        session.commit()
        raise
