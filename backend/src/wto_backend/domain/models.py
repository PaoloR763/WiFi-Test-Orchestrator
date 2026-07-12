from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from wto_backend.db.base import Base


def uuid_column() -> Mapped[UUID]:
    return mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class VersionMixin:
    version_id: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    __mapper_args__ = {"version_id_col": version_id}


class User(Base, TimestampMixin, VersionMixin):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("username ~ '^[a-z0-9][a-z0-9._-]{2,63}$'", name="username_format"),
        CheckConstraint("char_length(password_hash) <= 512", name="password_hash_length"),
        Index("ix_users_active", "is_active"),
        Index("uq_users_email_present", "email", unique=True, postgresql_where="email IS NOT NULL"),
    )
    id: Mapped[UUID] = uuid_column()
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    email: Mapped[str | None] = mapped_column(String(254))
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    auth_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    roles: Mapped[list[Role]] = relationship(
        secondary="user_roles",
        primaryjoin="User.id == UserRole.user_id",
        secondaryjoin="Role.id == UserRole.role_id",
        back_populates="users",
    )
    sessions: Mapped[list[AuthSession]] = relationship(back_populates="user")


class Role(Base, TimestampMixin, VersionMixin):
    __tablename__ = "roles"
    __table_args__ = (CheckConstraint("key ~ '^[a-z][a-z0-9_]{2,63}$'", name="key_format"),)
    id: Mapped[UUID] = uuid_column()
    key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(String(512), nullable=False)
    is_system: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    users: Mapped[list[User]] = relationship(
        secondary="user_roles",
        primaryjoin="Role.id == UserRole.role_id",
        secondaryjoin="User.id == UserRole.user_id",
        back_populates="roles",
    )
    permissions: Mapped[list[Permission]] = relationship(
        secondary="role_permissions", back_populates="roles"
    )


class Permission(Base, TimestampMixin):
    __tablename__ = "permissions"
    __table_args__ = (
        CheckConstraint("key ~ '^[a-z][a-z0-9_]*\\.[a-z][a-z0-9_]*$'", name="key_format"),
    )
    id: Mapped[UUID] = uuid_column()
    key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(String(512), nullable=False)
    is_system: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    roles: Mapped[list[Role]] = relationship(
        secondary="role_permissions", back_populates="permissions"
    )


class UserRole(Base):
    __tablename__ = "user_roles"
    __table_args__ = (UniqueConstraint("user_id", "role_id", name="uq_user_roles_user_role"),)
    id: Mapped[UUID] = uuid_column()
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role_id: Mapped[UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    assigned_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class RolePermission(Base):
    __tablename__ = "role_permissions"
    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="uq_role_permissions_role_permission"),
    )
    id: Mapped[UUID] = uuid_column()
    role_id: Mapped[UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    permission_id: Mapped[UUID] = mapped_column(
        ForeignKey("permissions.id", ondelete="RESTRICT"), nullable=False, index=True
    )


class AuthSession(Base, VersionMixin):
    __tablename__ = "sessions"
    __table_args__ = (
        CheckConstraint("absolute_expires_at > issued_at", name="absolute_expiry_after_issue"),
        CheckConstraint(
            "inactivity_expires_at <= absolute_expires_at", name="inactivity_before_absolute"
        ),
        Index("ix_sessions_user_active", "user_id", "revoked_at"),
    )
    id: Mapped[UUID] = uuid_column()
    token_family_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), nullable=False, unique=True, default=uuid4
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    auth_version: Mapped[int] = mapped_column(Integer, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    inactivity_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(String(128))
    client_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )
    user: Mapped[User] = relationship(back_populates="sessions")
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(back_populates="session")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    __table_args__ = (
        CheckConstraint("expires_at > issued_at", name="expiry_after_issue"),
        Index("ix_refresh_tokens_session_issued", "session_id", "issued_at"),
    )
    id: Mapped[UUID] = uuid_column()
    session_id: Mapped[UUID] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, unique=True)
    parent_token_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("refresh_tokens.id", ondelete="RESTRICT"), unique=True
    )
    replacement_token_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("refresh_tokens.id", ondelete="RESTRICT"), unique=True
    )
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(String(128))
    session: Mapped[AuthSession] = relationship(back_populates="refresh_tokens")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint("actor_type IN ('user','anonymous','system')", name="actor_type_values"),
        CheckConstraint("outcome IN ('success','failure','denied')", name="outcome_values"),
        CheckConstraint("octet_length(metadata::text) <= 16384", name="metadata_size"),
        Index("ix_audit_logs_occurred_id", "occurred_at", "id"),
        Index("ix_audit_logs_action", "action"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
    )
    id: Mapped[UUID] = uuid_column()
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict, server_default="{}"
    )


class Device(Base, TimestampMixin, VersionMixin):
    __tablename__ = "devices"
    id: Mapped[UUID] = uuid_column()
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Agent(Base, TimestampMixin, VersionMixin):
    __tablename__ = "agents"
    id: Mapped[UUID] = uuid_column()
    device_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="RESTRICT"), index=True
    )
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Capability(Base, TimestampMixin):
    __tablename__ = "capabilities"
    __table_args__ = (UniqueConstraint("key", "version", name="uq_capabilities_key_version"),)
    id: Mapped[UUID] = uuid_column()
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)


class TestDefinition(Base, TimestampMixin, VersionMixin):
    __tablename__ = "test_definitions"
    __table_args__ = (
        UniqueConstraint("name", "revision", name="uq_test_definitions_name_revision"),
    )
    id: Mapped[UUID] = uuid_column()
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    created_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )


class Campaign(Base, TimestampMixin, VersionMixin):
    __tablename__ = "campaigns"
    id: Mapped[UUID] = uuid_column()
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    test_definition_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("test_definitions.id", ondelete="RESTRICT"), index=True
    )
    created_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )


class Execution(Base):
    __tablename__ = "executions"
    id: Mapped[UUID] = uuid_column()
    campaign_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("campaigns.id", ondelete="RESTRICT"), index=True
    )
    agent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agents.id", ondelete="RESTRICT"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class Metric(Base):
    __tablename__ = "metrics"
    id: Mapped[UUID] = uuid_column()
    execution_id: Mapped[UUID] = mapped_column(
        ForeignKey("executions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    metric_key: Mapped[str] = mapped_column(String(128), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Artifact(Base):
    __tablename__ = "artifacts"
    id: Mapped[UUID] = uuid_column()
    execution_id: Mapped[UUID] = mapped_column(
        ForeignKey("executions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"
    __table_args__ = (CheckConstraint("expires_at > created_at", name="expiry_after_creation"),)
    id: Mapped[UUID] = uuid_column()
    token_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, unique=True)
    created_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
