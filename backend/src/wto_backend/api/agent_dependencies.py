from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Literal, cast

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from wto_backend.api.dependencies import get_session
from wto_backend.audit import write_audit
from wto_backend.config import Settings
from wto_backend.domain.models import Agent, AgentCredential
from wto_backend.logging import correlation_id_context
from wto_backend.repositories.agents import AgentRepository
from wto_backend.security.agent_credentials import (
    InvalidMachineSecretError,
    parse_machine_secret,
    verify_secret,
)
from wto_backend.security.agent_replay import (
    AgentNonceReusedError,
    AgentRateLimitedError,
    AgentReplayGuard,
    AgentReplayUnavailableError,
)
from wto_backend.services.errors import (
    AgentAuthenticationError,
    AgentRateLimitedDomainError,
    DependencyUnavailableError,
    NonceReplayError,
    ProtocolVersionError,
    RequestClockSkewError,
)

NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{22}$")


@dataclass(frozen=True)
class AgentPrincipal:
    agent: Agent
    credential: AgentCredential


def _authenticate(
    request: Request,
    session: Session,
    *,
    accepted_state: Literal["active", "pending_or_activated"],
) -> AgentPrincipal:
    settings = cast(Settings, request.app.state.settings)
    authorization = request.headers.get("Authorization", "")
    timestamp_text = request.headers.get("X-WTO-Agent-Timestamp")
    nonce = request.headers.get("X-WTO-Agent-Nonce")
    protocol = request.headers.get("X-WTO-Agent-Protocol")
    supplied_correlation = request.headers.get("X-Correlation-ID")
    if not authorization.startswith("Bearer "):
        raise AgentAuthenticationError
    if protocol != "1.0.0":
        raise ProtocolVersionError
    if supplied_correlation is None:
        raise AgentAuthenticationError
    if timestamp_text is None or not timestamp_text.endswith("Z"):
        raise RequestClockSkewError
    try:
        timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError as error:
        raise RequestClockSkewError from error
    if abs((datetime.now(UTC) - timestamp).total_seconds()) > settings.agent_clock_skew_seconds:
        raise RequestClockSkewError
    if nonce is None or NONCE_PATTERN.fullmatch(nonce) is None:
        raise AgentAuthenticationError
    try:
        parsed = parse_machine_secret(authorization[7:], prefix="wto_ac_1")
    except InvalidMachineSecretError as error:
        raise AgentAuthenticationError from error
    repo = AgentRepository(session)
    credential = repo.credential(parsed.locator)
    if credential is None or not verify_secret(
        settings.agent_credential_hmac_key.get_secret_value(),
        parsed.secret,
        credential.secret_digest,
    ):
        raise AgentAuthenticationError
    agent = repo.agent(credential.agent_id)
    if agent is None or not agent.is_active or agent.revoked_at is not None:
        if agent is not None:
            write_audit(
                session,
                actor_type="agent",
                actor_id=None,
                actor_agent_id=agent.id,
                action="agent_auth.rejected",
                resource_type="agent",
                resource_id=agent.id,
                outcome="denied",
                correlation_id=correlation_id_context.get() or "unavailable",
                metadata={"agent_id": str(agent.id), "reason_code": "agent_revoked"},
            )
            session.commit()
        raise AgentAuthenticationError
    allowed = credential.state == "active"
    if accepted_state == "pending_or_activated":
        allowed = credential.state in {"pending", "active"}
    if not allowed or credential.expires_at <= datetime.now(UTC):
        raise AgentAuthenticationError
    guard = cast(AgentReplayGuard, request.app.state.agent_replay_guard)
    try:
        guard.reserve(credential_id=str(credential.id), nonce=nonce)
    except AgentReplayUnavailableError as error:
        raise DependencyUnavailableError from error
    except AgentNonceReusedError as error:
        raise NonceReplayError from error
    except AgentRateLimitedError as error:
        raise AgentRateLimitedDomainError from error
    return AgentPrincipal(agent=agent, credential=credential)


def active_agent_principal(
    request: Request, session: Annotated[Session, Depends(get_session)]
) -> AgentPrincipal:
    return _authenticate(request, session, accepted_state="active")


def pending_agent_principal(
    request: Request, session: Annotated[Session, Depends(get_session)]
) -> AgentPrincipal:
    return _authenticate(request, session, accepted_state="pending_or_activated")
