from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, status
from sqlalchemy.orm import Session

from wto_backend.api.agent_dependencies import (
    AgentPrincipal,
    active_agent_principal,
    pending_agent_principal,
)
from wto_backend.api.agent_schemas import (
    DesktopHeartbeatRequest,
    MobilePresenceRequest,
    PresenceResponse,
    ProtocolStubResponse,
    RotationActivateRequest,
    RotationActivateResponse,
    RotationCreateRequest,
    RotationCreateResponse,
)
from wto_backend.api.dependencies import get_session
from wto_backend.services.agent_credentials import AgentCredentialService
from wto_backend.services.agent_protocol import AgentProtocolService
from wto_backend.services.errors import IdempotencyConflictError

router = APIRouter(prefix="/agents/self", tags=["agent-protocol"])
internal_router = APIRouter(
    prefix="/agent-protocol",
    tags=["agent-protocol-provisional"],
    include_in_schema=False,
)


def require_idempotency_header(header: UUID, body: UUID) -> None:
    if header != body:
        raise IdempotencyConflictError


@router.post(
    "/credential-rotations",
    response_model=RotationCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_rotation(
    payload: RotationCreateRequest,
    principal: Annotated[AgentPrincipal, Depends(active_agent_principal)],
    session: Annotated[Session, Depends(get_session)],
    request: Request,
    idempotency_key: Annotated[UUID, Header(alias="Idempotency-Key")],
) -> RotationCreateResponse:
    require_idempotency_header(idempotency_key, payload.idempotency_key)
    return AgentCredentialService(session, request.app.state.settings).create_rotation(
        agent_id=principal.agent.id,
        active_credential=principal.credential,
        payload=payload,
    )


@router.post(
    "/credential-rotations/{rotation_id}/activate",
    response_model=RotationActivateResponse,
)
def activate_rotation(
    rotation_id: UUID,
    payload: RotationActivateRequest,
    principal: Annotated[AgentPrincipal, Depends(pending_agent_principal)],
    session: Annotated[Session, Depends(get_session)],
    request: Request,
    idempotency_key: Annotated[UUID, Header(alias="Idempotency-Key")],
) -> RotationActivateResponse:
    require_idempotency_header(idempotency_key, payload.idempotency_key)
    return AgentCredentialService(session, request.app.state.settings).activate_rotation(
        agent_id=principal.agent.id,
        supplied_credential=principal.credential,
        rotation_id=rotation_id,
        payload=payload,
    )


@router.put("/capability-manifest", response_model=dict[str, Any])
def capability_manifest(
    payload: dict[str, Any],
    principal: Annotated[AgentPrincipal, Depends(active_agent_principal)],
    session: Annotated[Session, Depends(get_session)],
    request: Request,
) -> dict[str, Any]:
    return AgentProtocolService(session, request.app.state.settings).publish_manifest(
        agent_id=principal.agent.id, document=payload
    )


@router.post("/heartbeats", response_model=PresenceResponse)
def heartbeat(
    payload: DesktopHeartbeatRequest,
    principal: Annotated[AgentPrincipal, Depends(active_agent_principal)],
    session: Annotated[Session, Depends(get_session)],
    request: Request,
) -> PresenceResponse:
    return AgentProtocolService(session, request.app.state.settings).heartbeat(
        agent_id=principal.agent.id, payload=payload
    )


@router.post("/presence", response_model=PresenceResponse)
def mobile_presence(
    payload: MobilePresenceRequest,
    principal: Annotated[AgentPrincipal, Depends(active_agent_principal)],
    session: Annotated[Session, Depends(get_session)],
    request: Request,
) -> PresenceResponse:
    return AgentProtocolService(session, request.app.state.settings).mobile_presence(
        agent_id=principal.agent.id, payload=payload
    )


@internal_router.post("/task-fetch", response_model=ProtocolStubResponse)
def task_fetch(
    _: Annotated[AgentPrincipal, Depends(active_agent_principal)],
) -> ProtocolStubResponse:
    return ProtocolStubResponse(status="no_task", server_received_at=datetime.now(UTC))


def _validated_stub(
    *, schema: str, payload: dict[str, Any], session: Session, request: Request
) -> ProtocolStubResponse:
    AgentProtocolService(session, request.app.state.settings).validate_stub(
        schema_name=schema, payload=payload
    )
    return ProtocolStubResponse(status="accepted", server_received_at=datetime.now(UTC))


@internal_router.post("/progress", response_model=ProtocolStubResponse)
def progress(
    payload: dict[str, Any],
    _: Annotated[AgentPrincipal, Depends(active_agent_principal)],
    session: Annotated[Session, Depends(get_session)],
    request: Request,
    idempotency_key: Annotated[UUID, Header(alias="Idempotency-Key")],
) -> ProtocolStubResponse:
    require_idempotency_header(idempotency_key, UUID(str(payload.get("idempotency_key"))))
    return _validated_stub(
        schema="progress-event.schema.json",
        payload=payload,
        session=session,
        request=request,
    )


@internal_router.post("/results", response_model=ProtocolStubResponse)
def results(
    payload: dict[str, Any],
    _: Annotated[AgentPrincipal, Depends(active_agent_principal)],
    session: Annotated[Session, Depends(get_session)],
    request: Request,
    idempotency_key: Annotated[UUID, Header(alias="Idempotency-Key")],
) -> ProtocolStubResponse:
    require_idempotency_header(idempotency_key, UUID(str(payload.get("idempotency_key"))))
    return _validated_stub(
        schema="test-result.schema.json",
        payload=payload,
        session=session,
        request=request,
    )


@internal_router.post("/artifact-manifests", response_model=ProtocolStubResponse)
def artifact_manifests(
    payload: dict[str, Any],
    _: Annotated[AgentPrincipal, Depends(active_agent_principal)],
    session: Annotated[Session, Depends(get_session)],
    request: Request,
    idempotency_key: Annotated[UUID, Header(alias="Idempotency-Key")],
) -> ProtocolStubResponse:
    require_idempotency_header(idempotency_key, UUID(str(payload.get("idempotency_key"))))
    return _validated_stub(
        schema="artifact-manifest.schema.json",
        payload=payload,
        session=session,
        request=request,
    )
