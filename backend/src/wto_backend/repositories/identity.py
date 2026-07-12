from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from wto_backend.domain.models import AuthSession, Permission, RefreshToken, Role, User


class IdentityRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def user_by_username(self, username: str, *, lock: bool = False) -> User | None:
        statement = (
            select(User)
            .where(User.username == username)
            .options(selectinload(User.roles).selectinload(Role.permissions))
        )
        if lock:
            statement = statement.with_for_update()
        return self.session.scalar(statement)

    def user_by_id(self, user_id: UUID, *, lock: bool = False) -> User | None:
        statement = (
            select(User)
            .where(User.id == user_id)
            .options(selectinload(User.roles).selectinload(Role.permissions))
        )
        if lock:
            statement = statement.with_for_update()
        return self.session.scalar(statement)

    def role_by_key(self, key: str) -> Role | None:
        return self.session.scalar(
            select(Role).where(Role.key == key).options(selectinload(Role.permissions))
        )

    def session_by_id(self, session_id: UUID, *, lock: bool = False) -> AuthSession | None:
        statement = select(AuthSession).where(AuthSession.id == session_id)
        if lock:
            statement = statement.with_for_update()
        return self.session.scalar(statement)

    def refresh_by_digest(self, digest: bytes) -> RefreshToken | None:
        return self.session.scalar(
            select(RefreshToken)
            .where(RefreshToken.token_digest == digest)
            .options(selectinload(RefreshToken.session).selectinload(AuthSession.user))
            .with_for_update()
        )

    def permissions(self) -> list[Permission]:
        return list(self.session.scalars(select(Permission).order_by(Permission.key)))

    def roles(self) -> list[Role]:
        return list(
            self.session.scalars(
                select(Role).options(selectinload(Role.permissions)).order_by(Role.key)
            )
        )
