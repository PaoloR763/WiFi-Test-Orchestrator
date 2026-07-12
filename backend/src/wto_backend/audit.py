from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from wto_backend.domain.models import AuditLog

SAFE_METADATA_KEYS = {
    "identifier_fingerprint",
    "ip_fingerprint",
    "session_id",
    "role_key",
    "reason_code",
    "changed_fields",
    "created_count",
    "updated_count",
    "already_exists",
}
FORBIDDEN_FRAGMENTS = {
    "password",
    "token",
    "cookie",
    "authorization",
    "secret",
    "hash",
    "digest",
    "dsn",
}


def sanitize_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    if metadata is None:
        return {}
    safe: dict[str, Any] = {}
    for key, value in metadata.items():
        lowered = key.lower()
        if key not in SAFE_METADATA_KEYS or any(
            fragment in lowered for fragment in FORBIDDEN_FRAGMENTS
        ):
            continue
        if isinstance(value, str | int | bool) or value is None:
            safe[key] = value[:256] if isinstance(value, str) else value
        elif key == "changed_fields" and isinstance(value, list):
            safe[key] = [str(item)[:64] for item in value[:20]]
    if len(json.dumps(safe, separators=(",", ":")).encode("utf-8")) > 12000:
        return {}
    return safe


def write_audit(
    session: Session,
    *,
    actor_type: str,
    actor_id: UUID | None,
    action: str,
    resource_type: str,
    resource_id: UUID | None,
    outcome: str,
    correlation_id: str,
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    event = AuditLog(
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        occurred_at=datetime.now(UTC),
        correlation_id=correlation_id,
        event_metadata=sanitize_metadata(metadata),
    )
    session.add(event)
    return event
