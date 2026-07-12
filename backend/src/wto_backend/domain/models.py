from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
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
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
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
        Index(
            "uq_users_email_present",
            "email",
            unique=True,
            postgresql_where="email IS NOT NULL",
        ),
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
            "inactivity_expires_at <= absolute_expires_at",
            name="inactivity_before_absolute",
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
        CheckConstraint(
            "actor_type IN ('user','agent','anonymous','system')",
            name="actor_type_values",
        ),
        CheckConstraint(
            "(actor_type = 'user' AND actor_id IS NOT NULL AND actor_agent_id IS NULL) OR "
            "(actor_type = 'agent' AND actor_id IS NULL AND actor_agent_id IS NOT NULL) OR "
            "(actor_type IN ('anonymous','system') AND actor_id IS NULL "
            "AND actor_agent_id IS NULL)",
            name="actor_identity",
        ),
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
    actor_agent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agents.id", ondelete="SET NULL"), index=True
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
    platform: Mapped[str | None] = mapped_column(String(16))
    platform_version: Mapped[str | None] = mapped_column(String(64))
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Agent(Base, TimestampMixin, VersionMixin):
    __tablename__ = "agents"
    __table_args__ = (
        Index(
            "uq_agents_installation_id_present",
            "installation_id",
            unique=True,
            postgresql_where="installation_id IS NOT NULL",
        ),
    )
    id: Mapped[UUID] = uuid_column()
    device_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="RESTRICT"), index=True
    )
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    installation_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    protocol_min_version: Mapped[str | None] = mapped_column(String(32))
    protocol_max_version: Mapped[str | None] = mapped_column(String(32))
    protocol_version: Mapped[str | None] = mapped_column(String(32))
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    revocation_reason: Mapped[str | None] = mapped_column(String(128))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Capability(Base, TimestampMixin):
    __tablename__ = "capabilities"
    __table_args__ = (
        CheckConstraint(
            "key ~ '^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$'",
            name="key_format",
        ),
        CheckConstraint("version ~ '^[0-9]+\\.[0-9]+\\.[0-9]+$'", name="version_format"),
        UniqueConstraint("key", "version", name="uq_capabilities_key_version"),
    )
    id: Mapped[UUID] = uuid_column()
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )


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


class EnrollmentToken(Base, VersionMixin):
    __tablename__ = "enrollment_tokens"
    __table_args__ = (CheckConstraint("expires_at > created_at", name="expiry_after_creation"),)
    id: Mapped[UUID] = uuid_column()
    token_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, unique=True)
    digest_key_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    scope: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="agent.enroll",
        server_default="agent.enroll",
    )
    max_uses: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    uses_consumed: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    restrictions: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )
    created_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    revocation_reason: Mapped[str | None] = mapped_column(String(128))


class AgentCredential(Base, VersionMixin):
    __tablename__ = "agent_credentials"
    __table_args__ = (
        UniqueConstraint(
            "agent_id", "credential_version", name="uq_agent_credentials_agent_version"
        ),
        CheckConstraint("octet_length(secret_digest) = 32", name="secret_digest_length"),
        CheckConstraint("state IN ('pending','active','revoked','expired')", name="state_values"),
        Index(
            "uq_agent_credentials_one_active",
            "agent_id",
            unique=True,
            postgresql_where="state = 'active'",
        ),
        Index(
            "uq_agent_credentials_one_pending",
            "agent_id",
            unique=True,
            postgresql_where="state = 'pending'",
        ),
    )
    id: Mapped[UUID] = uuid_column()
    agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    credential_version: Mapped[int] = mapped_column(Integer, nullable=False)
    secret_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    digest_key_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    revocation_reason: Mapped[str | None] = mapped_column(String(128))


class AgentCredentialRotation(Base, VersionMixin):
    __tablename__ = "agent_credential_rotations"
    __table_args__ = (
        CheckConstraint(
            "state IN ('pending','activated','expired','revoked')", name="state_values"
        ),
        Index(
            "uq_agent_credential_rotations_one_pending",
            "agent_id",
            unique=True,
            postgresql_where="state = 'pending'",
        ),
    )
    id: Mapped[UUID] = uuid_column()
    agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    previous_credential_id: Mapped[UUID] = mapped_column(
        ForeignKey("agent_credentials.id", ondelete="RESTRICT"), nullable=False
    )
    pending_credential_id: Mapped[UUID] = mapped_column(
        ForeignKey("agent_credentials.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IdempotencyRecord(Base, VersionMixin):
    __tablename__ = "idempotency_records"
    __table_args__ = (
        UniqueConstraint(
            "principal_type",
            "principal_id",
            "operation_id",
            "idempotency_key",
            name="uq_idempotency_records_scope",
        ),
        CheckConstraint("octet_length(request_fingerprint) = 32", name="fingerprint_length"),
        CheckConstraint("state IN ('pending','completed','failed')", name="state_values"),
        CheckConstraint("octet_length(response_body::text) <= 1048576", name="response_size"),
        Index("ix_idempotency_records_expires_at", "expires_at"),
    )
    id: Mapped[UUID] = uuid_column()
    principal_type: Mapped[str] = mapped_column(String(32), nullable=False)
    principal_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    operation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    request_fingerprint: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_body: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SecretReplay(Base):
    __tablename__ = "secret_replays"
    __table_args__ = (
        CheckConstraint("octet_length(nonce) = 12", name="nonce_length"),
        CheckConstraint("octet_length(ciphertext) <= 65536", name="ciphertext_size"),
        Index("ix_secret_replays_expires_at", "expires_at"),
    )
    id: Mapped[UUID] = uuid_column()
    idempotency_record_id: Mapped[UUID] = mapped_column(
        ForeignKey("idempotency_records.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    encryption_key_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CapabilityManifest(Base):
    __tablename__ = "capability_manifests"
    __table_args__ = (
        UniqueConstraint("agent_id", "manifest_sequence", name="uq_capability_manifests_sequence"),
        CheckConstraint("octet_length(document::text) <= 262144", name="document_size"),
        CheckConstraint("octet_length(document_digest) = 32", name="digest_length"),
        Index("ix_capability_manifests_agent_received", "agent_id", "server_received_at"),
    )
    id: Mapped[UUID] = uuid_column()
    agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    manifest_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    catalog_version: Mapped[str] = mapped_column(String(32), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    server_received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    document_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)


class AgentPresence(Base, VersionMixin):
    __tablename__ = "agent_presence"
    __table_args__ = (
        UniqueConstraint("agent_id", name="uq_agent_presence_agent_id"),
        CheckConstraint("kind IN ('desktop','mobile')", name="kind_values"),
        CheckConstraint("octet_length(payload_digest) = 32", name="payload_digest_length"),
        Index("ix_agent_presence_expires_at", "presence_expires_at"),
    )
    id: Mapped[UUID] = uuid_column()
    agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    boot_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    payload_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    agent_reported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    server_received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    presence_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    manifest_id: Mapped[UUID] = mapped_column(
        ForeignKey("capability_manifests.id", ondelete="RESTRICT"), nullable=False
    )
