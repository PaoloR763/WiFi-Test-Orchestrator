from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from wto_backend.api.dependencies import get_session, require_permissions
from wto_backend.api.schemas import AuditPage, AuditView
from wto_backend.audit import write_audit
from wto_backend.domain.models import AuditLog, User
from wto_backend.logging import correlation_id_context

router = APIRouter(prefix="/audit", tags=["internal-audit"])


@router.get("/events", response_model=AuditPage)
def events(
    principal: Annotated[tuple[User, object], Depends(require_permissions("audit.read"))],
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    before: UUID | None = None,
    action: Annotated[str | None, Query(max_length=128)] = None,
) -> AuditPage:
    statement = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit + 1)
    if before is not None:
        statement = statement.where(AuditLog.id < before)
    if action is not None:
        statement = statement.where(AuditLog.action == action)
    records = list(session.scalars(statement))
    has_more = len(records) > limit
    records = records[:limit]
    write_audit(
        session,
        actor_type="user",
        actor_id=principal[0].id,
        action="audit.read",
        resource_type="audit_log",
        resource_id=None,
        outcome="success",
        correlation_id=correlation_id_context.get() or "unavailable",
    )
    session.commit()
    return AuditPage(
        items=[
            AuditView(
                id=item.id,
                actor_type=item.actor_type,
                actor_id=item.actor_id,
                action=item.action,
                resource_type=item.resource_type,
                resource_id=item.resource_id,
                outcome=item.outcome,
                occurred_at=item.occurred_at,
                correlation_id=item.correlation_id,
                metadata=item.event_metadata,
            )
            for item in records
        ],
        next_cursor=records[-1].id if has_more and records else None,
    )
