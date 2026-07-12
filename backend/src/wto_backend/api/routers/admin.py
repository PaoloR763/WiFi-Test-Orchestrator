from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from wto_backend.api.dependencies import get_session, require_permissions
from wto_backend.api.routers.auth import user_view
from wto_backend.api.schemas import UserCreateRequest, UserList, UserUpdateRequest, UserView
from wto_backend.domain.models import User
from wto_backend.logging import correlation_id_context
from wto_backend.services.errors import ConflictError
from wto_backend.services.rbac import UserAdministrationService

router = APIRouter(prefix="/admin", tags=["internal-administration"])


def admin_service(session: Session, principal: tuple[User, object]) -> UserAdministrationService:
    del principal
    return UserAdministrationService(session, session.info["password_manager"])


@router.get("/users", response_model=UserList)
def list_users(
    _: Annotated[tuple[User, object], Depends(require_permissions("users.read"))],
    session: Annotated[Session, Depends(get_session)],
) -> UserList:
    users = session.scalars(
        select(User).options(selectinload(User.roles)).order_by(User.username)
    ).all()
    return UserList(items=[user_view(user) for user in users])


@router.post("/users", response_model=UserView, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateRequest,
    principal: Annotated[tuple[User, object], Depends(require_permissions("users.create"))],
    session: Annotated[Session, Depends(get_session)],
) -> UserView:
    service = UserAdministrationService(session, session.info["password_manager"])
    user = service.create_user(
        username=payload.username,
        email=payload.email,
        password=payload.password,
        actor=principal[0],
        correlation_id=correlation_id_context.get() or "unavailable",
    )
    return user_view(user)


@router.patch("/users/{user_id}", response_model=UserView)
def update_user(
    user_id: UUID,
    payload: UserUpdateRequest,
    principal: Annotated[tuple[User, object], Depends(require_permissions("users.update"))],
    session: Annotated[Session, Depends(get_session)],
) -> UserView:
    if payload.is_active:
        raise ConflictError
    user = UserAdministrationService(session, session.info["password_manager"]).disable_user(
        user_id=user_id,
        actor=principal[0],
        correlation_id=correlation_id_context.get() or "unavailable",
    )
    return user_view(user)


@router.put("/users/{user_id}/roles/{role_key}", status_code=status.HTTP_204_NO_CONTENT)
def assign_role(
    user_id: UUID,
    role_key: str,
    principal: Annotated[tuple[User, object], Depends(require_permissions("users.roles_manage"))],
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    UserAdministrationService(session, session.info["password_manager"]).assign_role(
        user_id=user_id,
        role_key=role_key,
        actor=principal[0],
        correlation_id=correlation_id_context.get() or "unavailable",
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/users/{user_id}/roles/{role_key}", status_code=status.HTTP_204_NO_CONTENT)
def remove_role(
    user_id: UUID,
    role_key: str,
    principal: Annotated[tuple[User, object], Depends(require_permissions("users.roles_manage"))],
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    UserAdministrationService(session, session.info["password_manager"]).remove_role(
        user_id=user_id,
        role_key=role_key,
        actor=principal[0],
        correlation_id=correlation_id_context.get() or "unavailable",
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/users/{user_id}/revoke-sessions", status_code=status.HTTP_204_NO_CONTENT)
def revoke_sessions(
    user_id: UUID,
    principal: Annotated[tuple[User, object], Depends(require_permissions("sessions.revoke"))],
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    UserAdministrationService(session, session.info["password_manager"]).revoke_sessions(
        user_id=user_id,
        actor=principal[0],
        correlation_id=correlation_id_context.get() or "unavailable",
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/protected")
def protected(
    principal: Annotated[tuple[User, object], Depends(require_permissions("admin.protected_read"))],
) -> dict[str, str]:
    return {"status": "authorized", "user_id": str(principal[0].id)}
