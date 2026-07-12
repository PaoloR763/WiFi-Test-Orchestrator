from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from wto_backend.api.agent_schemas import CredentialMetadata
from wto_backend.api.dependencies import get_session, require_permissions
from wto_backend.domain.models import User
from wto_backend.services.agent_credentials import AgentCredentialService

router = APIRouter(prefix="/agents", tags=["agent-administration"])


@router.get("/{agent_id}/credentials", response_model=list[CredentialMetadata])
def list_credentials(
    agent_id: UUID,
    _: Annotated[tuple[User, object], Depends(require_permissions("agent_credentials.read"))],
    session: Annotated[Session, Depends(get_session)],
    request: Request,
) -> list[CredentialMetadata]:
    return AgentCredentialService(session, request.app.state.settings).credentials(agent_id)


@router.post(
    "/{agent_id}/credentials/{credential_id}/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
)
def revoke_credential(
    agent_id: UUID,
    credential_id: UUID,
    principal: Annotated[
        tuple[User, object], Depends(require_permissions("agent_credentials.revoke"))
    ],
    session: Annotated[Session, Depends(get_session)],
    request: Request,
) -> Response:
    AgentCredentialService(session, request.app.state.settings).revoke_credential(
        agent_id=agent_id, credential_id=credential_id, actor=principal[0]
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{agent_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
def revoke_agent(
    agent_id: UUID,
    principal: Annotated[tuple[User, object], Depends(require_permissions("agents.revoke"))],
    session: Annotated[Session, Depends(get_session)],
    request: Request,
) -> Response:
    AgentCredentialService(session, request.app.state.settings).revoke_agent(
        agent_id=agent_id, actor=principal[0]
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
