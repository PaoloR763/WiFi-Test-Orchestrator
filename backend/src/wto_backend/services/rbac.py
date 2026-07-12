from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.orm import Session

from wto_backend.audit import write_audit
from wto_backend.domain.models import AuthSession, Role, User, UserRole
from wto_backend.repositories.identity import IdentityRepository
from wto_backend.security.passwords import PasswordManager
from wto_backend.services.errors import (
    ConflictError,
    LastAdministratorError,
    ResourceNotFoundError,
)

ADMIN_LOCK_ID = 87003001


class UserAdministrationService:
    def __init__(self, session: Session, passwords: PasswordManager) -> None:
        self.session = session
        self.passwords = passwords
        self.repo = IdentityRepository(session)

    def create_user(
        self,
        *,
        username: str,
        email: str | None,
        password: str,
        actor: User,
        correlation_id: str,
    ) -> User:
        normalized = username.strip().lower()
        if self.repo.user_by_username(normalized) is not None:
            raise ConflictError
        user = User(
            username=normalized,
            email=email.lower() if email else None,
            password_hash=self.passwords.hash(password),
            must_change_password=True,
        )
        self.session.add(user)
        self.session.flush()
        write_audit(
            self.session,
            actor_type="user",
            actor_id=actor.id,
            action="user.create",
            resource_type="user",
            resource_id=user.id,
            outcome="success",
            correlation_id=correlation_id,
        )
        self.session.commit()
        return user

    def disable_user(self, *, user_id: UUID, actor: User, correlation_id: str) -> User:
        self._lock_admin_invariant()
        user = self.repo.user_by_id(user_id, lock=True)
        if user is None:
            raise ResourceNotFoundError
        if self._is_administrator(user) and self._active_administrator_count() <= 1:
            raise LastAdministratorError
        now = datetime.now(UTC)
        user.is_active = False
        user.disabled_at = now
        user.auth_version += 1
        self.session.execute(
            update(AuthSession)
            .where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))
            .values(revoked_at=now, revocation_reason="user_disabled")
        )
        write_audit(
            self.session,
            actor_type="user",
            actor_id=actor.id,
            action="user.disable",
            resource_type="user",
            resource_id=user.id,
            outcome="success",
            correlation_id=correlation_id,
        )
        self.session.commit()
        return user

    def assign_role(
        self, *, user_id: UUID, role_key: str, actor: User, correlation_id: str
    ) -> None:
        user = self.repo.user_by_id(user_id, lock=True)
        role = self.repo.role_by_key(role_key)
        if user is None or role is None:
            raise ResourceNotFoundError
        exists = self.session.scalar(
            select(UserRole.id).where(UserRole.user_id == user.id, UserRole.role_id == role.id)
        )
        if exists is None:
            self.session.add(
                UserRole(user_id=user.id, role_id=role.id, assigned_by_user_id=actor.id)
            )
            write_audit(
                self.session,
                actor_type="user",
                actor_id=actor.id,
                action="user.role_assign",
                resource_type="user",
                resource_id=user.id,
                outcome="success",
                correlation_id=correlation_id,
                metadata={"role_key": role.key},
            )
        self.session.commit()

    def revoke_sessions(self, *, user_id: UUID, actor: User, correlation_id: str) -> None:
        user = self.repo.user_by_id(user_id, lock=True)
        if user is None:
            raise ResourceNotFoundError
        now = datetime.now(UTC)
        user.auth_version += 1
        self.session.execute(
            update(AuthSession)
            .where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))
            .values(revoked_at=now, revocation_reason="administrator_revocation")
        )
        write_audit(
            self.session,
            actor_type="user",
            actor_id=actor.id,
            action="session.revoke",
            resource_type="user",
            resource_id=user.id,
            outcome="success",
            correlation_id=correlation_id,
            metadata={"reason_code": "administrator_revocation"},
        )
        self.session.commit()

    def remove_role(
        self, *, user_id: UUID, role_key: str, actor: User, correlation_id: str
    ) -> None:
        if role_key == "administrator":
            self._lock_admin_invariant()
        user = self.repo.user_by_id(user_id, lock=True)
        role = self.repo.role_by_key(role_key)
        if user is None or role is None:
            raise ResourceNotFoundError
        if (
            role_key == "administrator"
            and user.is_active
            and self._active_administrator_count() <= 1
        ):
            raise LastAdministratorError
        result = self.session.execute(
            delete(UserRole).where(UserRole.user_id == user.id, UserRole.role_id == role.id)
        )
        if result.rowcount:
            write_audit(
                self.session,
                actor_type="user",
                actor_id=actor.id,
                action="user.role_remove",
                resource_type="user",
                resource_id=user.id,
                outcome="success",
                correlation_id=correlation_id,
                metadata={"role_key": role.key},
            )
        self.session.commit()

    def _lock_admin_invariant(self) -> None:
        self.session.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": ADMIN_LOCK_ID}
        )

    def _active_administrator_count(self) -> int:
        return int(
            self.session.scalar(
                select(func.count(User.id))
                .select_from(User)
                .join(UserRole, UserRole.user_id == User.id)
                .join(Role, Role.id == UserRole.role_id)
                .where(User.is_active.is_(True), Role.key == "administrator")
            )
            or 0
        )

    @staticmethod
    def _is_administrator(user: User) -> bool:
        return any(role.key == "administrator" for role in user.roles)
