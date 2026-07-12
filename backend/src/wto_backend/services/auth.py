from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import update
from sqlalchemy.orm import Session

from wto_backend.audit import write_audit
from wto_backend.domain.models import AuthSession, RefreshToken, User
from wto_backend.repositories.identity import IdentityRepository
from wto_backend.security.passwords import PasswordManager
from wto_backend.security.tokens import AccessClaims, TokenManager
from wto_backend.services.errors import InvalidCredentialsError, InvalidSessionError


class AuthService:
    def __init__(
        self,
        session: Session,
        *,
        passwords: PasswordManager,
        tokens: TokenManager,
        audit_hmac_key: str,
        absolute_days: int,
        inactivity_days: int,
    ) -> None:
        self.session = session
        self.repo = IdentityRepository(session)
        self.passwords = passwords
        self.tokens = tokens
        self.audit_hmac_key = audit_hmac_key
        self.absolute_days = absolute_days
        self.inactivity_days = inactivity_days

    def login(
        self,
        *,
        username: str,
        password: str,
        correlation_id: str,
        identifier_fingerprint: str,
        ip_fingerprint: str,
        client_metadata: dict[str, str],
    ) -> tuple[str, str, User]:
        normalized = username.strip().lower()
        user = self.repo.user_by_username(normalized, lock=True)
        if user is None:
            self.passwords.dummy_verify(password)
            write_audit(
                self.session,
                actor_type="anonymous",
                actor_id=None,
                action="auth.login",
                resource_type="session",
                resource_id=None,
                outcome="failure",
                correlation_id=correlation_id,
                metadata={
                    "identifier_fingerprint": identifier_fingerprint,
                    "ip_fingerprint": ip_fingerprint,
                },
            )
            self.session.commit()
            raise InvalidCredentialsError
        verified, replacement = self.passwords.verify(password, user.password_hash)
        if not verified or not user.is_active:
            write_audit(
                self.session,
                actor_type="anonymous",
                actor_id=None,
                action="auth.login",
                resource_type="session",
                resource_id=None,
                outcome="failure",
                correlation_id=correlation_id,
                metadata={
                    "identifier_fingerprint": identifier_fingerprint,
                    "ip_fingerprint": ip_fingerprint,
                },
            )
            self.session.commit()
            raise InvalidCredentialsError
        if replacement is not None:
            user.password_hash = replacement
        now = datetime.now(UTC)
        absolute = now + timedelta(days=self.absolute_days)
        auth_session = AuthSession(
            user=user,
            auth_version=user.auth_version,
            issued_at=now,
            absolute_expires_at=absolute,
            inactivity_expires_at=min(absolute, now + timedelta(days=self.inactivity_days)),
            last_used_at=now,
            client_metadata=client_metadata,
        )
        self.session.add(auth_session)
        self.session.flush()
        refresh_plaintext, refresh_digest = self.tokens.new_refresh_token()
        refresh = RefreshToken(
            session=auth_session,
            token_digest=refresh_digest,
            issued_at=now,
            expires_at=auth_session.inactivity_expires_at,
        )
        self.session.add(refresh)
        user.last_login_at = now
        write_audit(
            self.session,
            actor_type="user",
            actor_id=user.id,
            action="auth.login",
            resource_type="session",
            resource_id=auth_session.id,
            outcome="success",
            correlation_id=correlation_id,
            metadata={
                "session_id": str(auth_session.id),
                "ip_fingerprint": ip_fingerprint,
            },
        )
        access = self.tokens.issue_access(
            user_id=user.id, session_id=auth_session.id, auth_version=user.auth_version
        )
        self.session.commit()
        return access, refresh_plaintext, user

    def refresh(self, *, token: str, correlation_id: str) -> tuple[str, str, User]:
        now = datetime.now(UTC)
        record = self.repo.refresh_by_digest(self.tokens.refresh_digest(token))
        if record is None:
            raise InvalidSessionError
        family = record.session
        user = family.user
        invalid_family = (
            family.revoked_at is not None
            or family.absolute_expires_at <= now
            or family.inactivity_expires_at <= now
            or not user.is_active
            or family.auth_version != user.auth_version
        )
        if record.consumed_at is not None:
            self._revoke_family(family, now=now, reason="refresh_reuse")
            write_audit(
                self.session,
                actor_type="user",
                actor_id=user.id,
                action="auth.refresh_reuse",
                resource_type="session",
                resource_id=family.id,
                outcome="denied",
                correlation_id=correlation_id,
                metadata={"session_id": str(family.id), "reason_code": "refresh_reuse"},
            )
            self.session.commit()
            raise InvalidSessionError
        if invalid_family or record.revoked_at is not None or record.expires_at <= now:
            self._revoke_family(family, now=now, reason="session_invalid")
            self.session.commit()
            raise InvalidSessionError
        record.consumed_at = now
        refresh_plaintext, refresh_digest = self.tokens.new_refresh_token()
        inactivity_expiry = min(
            family.absolute_expires_at, now + timedelta(days=self.inactivity_days)
        )
        replacement = RefreshToken(
            session=family,
            token_digest=refresh_digest,
            parent_token_id=record.id,
            issued_at=now,
            expires_at=inactivity_expiry,
        )
        self.session.add(replacement)
        self.session.flush()
        record.replacement_token_id = replacement.id
        family.last_used_at = now
        family.inactivity_expires_at = inactivity_expiry
        write_audit(
            self.session,
            actor_type="user",
            actor_id=user.id,
            action="auth.refresh",
            resource_type="session",
            resource_id=family.id,
            outcome="success",
            correlation_id=correlation_id,
            metadata={"session_id": str(family.id)},
        )
        access = self.tokens.issue_access(
            user_id=user.id, session_id=family.id, auth_version=user.auth_version
        )
        self.session.commit()
        return access, refresh_plaintext, user

    def authenticate_access(self, claims: AccessClaims) -> User:
        user = self.repo.user_by_id(claims.user_id)
        auth_session = self.repo.session_by_id(claims.session_id)
        now = datetime.now(UTC)
        if (
            user is None
            or auth_session is None
            or auth_session.user_id != claims.user_id
            or not user.is_active
            or auth_session.revoked_at is not None
            or auth_session.absolute_expires_at <= now
            or auth_session.inactivity_expires_at <= now
            or user.auth_version != claims.auth_version
            or auth_session.auth_version != claims.auth_version
        ):
            raise InvalidSessionError
        return user

    def logout(self, *, user: User, session_id: UUID, correlation_id: str) -> None:
        auth_session = self.repo.session_by_id(session_id, lock=True)
        if auth_session is not None and auth_session.user_id == user.id:
            self._revoke_family(auth_session, now=datetime.now(UTC), reason="logout")
            write_audit(
                self.session,
                actor_type="user",
                actor_id=user.id,
                action="auth.logout",
                resource_type="session",
                resource_id=auth_session.id,
                outcome="success",
                correlation_id=correlation_id,
                metadata={"session_id": str(auth_session.id)},
            )
            self.session.commit()

    def logout_all(
        self, *, user: User, correlation_id: str, action: str = "auth.logout_all"
    ) -> None:
        locked = self.repo.user_by_id(user.id, lock=True)
        if locked is None:
            raise InvalidSessionError
        now = datetime.now(UTC)
        locked.auth_version += 1
        self.session.execute(
            update(AuthSession)
            .where(AuthSession.user_id == locked.id, AuthSession.revoked_at.is_(None))
            .values(revoked_at=now, revocation_reason=action)
        )
        write_audit(
            self.session,
            actor_type="user",
            actor_id=locked.id,
            action=action,
            resource_type="user",
            resource_id=locked.id,
            outcome="success",
            correlation_id=correlation_id,
        )
        self.session.commit()

    def change_password(self, *, user: User, current: str, new: str, correlation_id: str) -> None:
        locked = self.repo.user_by_id(user.id, lock=True)
        if locked is None:
            raise InvalidSessionError
        verified, _ = self.passwords.verify(current, locked.password_hash)
        if not verified:
            raise InvalidCredentialsError
        locked.password_hash = self.passwords.hash(new)
        locked.must_change_password = False
        self.logout_all(user=locked, correlation_id=correlation_id, action="auth.password_change")

    def _revoke_family(self, family: AuthSession, *, now: datetime, reason: str) -> None:
        family.revoked_at = family.revoked_at or now
        family.revocation_reason = family.revocation_reason or reason
        self.session.execute(
            update(RefreshToken)
            .where(RefreshToken.session_id == family.id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now, revocation_reason=reason)
        )


def permission_keys(user: User) -> set[str]:
    return {permission.key for role in user.roles for permission in role.permissions}
