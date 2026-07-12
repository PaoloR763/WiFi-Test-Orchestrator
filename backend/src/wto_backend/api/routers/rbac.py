from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from wto_backend.api.dependencies import get_session, require_permissions
from wto_backend.api.schemas import PermissionView, RoleView
from wto_backend.domain.models import User
from wto_backend.repositories.identity import IdentityRepository

router = APIRouter(prefix="/rbac", tags=["internal-rbac"])


@router.get("/roles", response_model=list[RoleView])
def roles(
    _: Annotated[tuple[User, object], Depends(require_permissions("roles.read"))],
    session: Annotated[Session, Depends(get_session)],
) -> list[RoleView]:
    return [
        RoleView(
            id=role.id,
            key=role.key,
            display_name=role.display_name,
            description=role.description,
            permissions=sorted(permission.key for permission in role.permissions),
        )
        for role in IdentityRepository(session).roles()
    ]


@router.get("/permissions", response_model=list[PermissionView])
def permissions(
    _: Annotated[tuple[User, object], Depends(require_permissions("permissions.read"))],
    session: Annotated[Session, Depends(get_session)],
) -> list[PermissionView]:
    return [
        PermissionView(id=item.id, key=item.key, description=item.description)
        for item in IdentityRepository(session).permissions()
    ]
