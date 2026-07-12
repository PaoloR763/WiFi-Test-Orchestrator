from __future__ import annotations

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from wto_backend.audit import write_audit
from wto_backend.domain.models import Role, User, UserRole
from wto_backend.repositories.identity import IdentityRepository
from wto_backend.security.passwords import PasswordManager
from wto_backend.services.errors import ConflictError
from wto_backend.services.rbac import ADMIN_LOCK_ID


def bootstrap_administrator(
    session: Session,
    *,
    username: str,
    password: str,
    passwords: PasswordManager,
    correlation_id: str,
) -> tuple[User, bool]:
    normalized = username.strip().lower()
    session.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": ADMIN_LOCK_ID})
    repo = IdentityRepository(session)
    administrator = repo.role_by_key("administrator")
    if administrator is None:
        raise ConflictError("RBAC seeds must be applied before bootstrap")
    existing = repo.user_by_username(normalized, lock=True)
    if existing is not None:
        has_admin = session.scalar(
            select(UserRole.id).where(
                UserRole.user_id == existing.id, UserRole.role_id == administrator.id
            )
        )
        if existing.is_active and has_admin is not None:
            write_audit(
                session,
                actor_type="system",
                actor_id=None,
                action="admin.bootstrap",
                resource_type="user",
                resource_id=existing.id,
                outcome="success",
                correlation_id=correlation_id,
                metadata={"already_exists": True},
            )
            session.commit()
            return existing, False
        raise ConflictError("bootstrap username already exists in an incompatible state")
    admin_count = session.scalar(
        select(func.count(User.id))
        .select_from(User)
        .join(UserRole, UserRole.user_id == User.id)
        .join(Role, Role.id == UserRole.role_id)
        .where(User.is_active.is_(True), Role.key == "administrator")
    )
    if admin_count:
        raise ConflictError("an active administrator already exists")
    lowered_password = password.lower()
    if lowered_password in {"administrator", "password", "change-me", normalized}:
        raise ValueError("default or username-derived credentials are forbidden")
    user = User(
        username=normalized,
        password_hash=passwords.hash(password),
        must_change_password=True,
    )
    session.add(user)
    session.flush()
    session.add(UserRole(user_id=user.id, role_id=administrator.id, assigned_by_user_id=None))
    write_audit(
        session,
        actor_type="system",
        actor_id=None,
        action="admin.bootstrap",
        resource_type="user",
        resource_id=user.id,
        outcome="success",
        correlation_id=correlation_id,
        metadata={"already_exists": False},
    )
    session.commit()
    return user, True
