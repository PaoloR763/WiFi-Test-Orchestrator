"""Create Phase 03 identity, RBAC, sessions, and append-only audit.

Revision ID: 20260712_0002
Revises: 20260711_0001
Create Date: 2026-07-12 00:00:00+00:00
"""

from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

from wto_backend.config import get_settings

revision: str = "20260712_0002"
down_revision: str | None = "20260711_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def runtime_role() -> str:
    connection = op.get_bind()
    return connection.dialect.identifier_preparer.quote(get_settings().postgres_runtime_role)


def upgrade() -> None:
    op.execute(
        text(
            """
CREATE TABLE users (
  id UUID CONSTRAINT pk_users PRIMARY KEY,
  username VARCHAR(64) CONSTRAINT uq_users_username UNIQUE NOT NULL,
  email VARCHAR(254), password_hash VARCHAR(512) NOT NULL,
  is_active BOOLEAN DEFAULT TRUE NOT NULL,
  must_change_password BOOLEAN DEFAULT FALSE NOT NULL,
  auth_version INTEGER DEFAULT 1 NOT NULL,
  disabled_at TIMESTAMPTZ, last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  version_id INTEGER DEFAULT 1 NOT NULL,
  CONSTRAINT ck_users_username_format CHECK (username ~ '^[a-z0-9][a-z0-9._-]{2,63}$'),
  CONSTRAINT ck_users_password_hash_length CHECK (char_length(password_hash) <= 512),
  CONSTRAINT ck_users_auth_version_positive CHECK (auth_version > 0),
  CONSTRAINT ck_users_version_positive CHECK (version_id > 0)
);
CREATE INDEX ix_users_active ON users (is_active);
CREATE UNIQUE INDEX uq_users_email_present ON users (email) WHERE email IS NOT NULL;

CREATE TABLE roles (
  id UUID CONSTRAINT pk_roles PRIMARY KEY,
  key VARCHAR(64) CONSTRAINT uq_roles_key UNIQUE NOT NULL,
  display_name VARCHAR(128) NOT NULL, description VARCHAR(512) NOT NULL,
  is_system BOOLEAN DEFAULT TRUE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  version_id INTEGER DEFAULT 1 NOT NULL,
  CONSTRAINT ck_roles_key_format CHECK (key ~ '^[a-z][a-z0-9_]{2,63}$'),
  CONSTRAINT ck_roles_version_positive CHECK (version_id > 0)
);
CREATE TABLE permissions (
  id UUID CONSTRAINT pk_permissions PRIMARY KEY,
  key VARCHAR(128) CONSTRAINT uq_permissions_key UNIQUE NOT NULL,
  description VARCHAR(512) NOT NULL, is_system BOOLEAN DEFAULT TRUE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  CONSTRAINT ck_permissions_key_format CHECK (key ~ '^[a-z][a-z0-9_]*\\.[a-z][a-z0-9_]*$')
);
CREATE TABLE user_roles (
  id UUID CONSTRAINT pk_user_roles PRIMARY KEY,
  user_id UUID NOT NULL, role_id UUID NOT NULL, assigned_by_user_id UUID,
  assigned_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  CONSTRAINT uq_user_roles_user_role UNIQUE (user_id, role_id),
  CONSTRAINT fk_user_roles_user_id_users FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_user_roles_role_id_roles FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE RESTRICT,
  CONSTRAINT fk_user_roles_assigned_by_user_id_users FOREIGN KEY (assigned_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX ix_user_roles_user_id ON user_roles (user_id);
CREATE INDEX ix_user_roles_role_id ON user_roles (role_id);
CREATE TABLE role_permissions (
  id UUID CONSTRAINT pk_role_permissions PRIMARY KEY,
  role_id UUID NOT NULL, permission_id UUID NOT NULL,
  CONSTRAINT uq_role_permissions_role_permission UNIQUE (role_id, permission_id),
  CONSTRAINT fk_role_permissions_role_id_roles FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  CONSTRAINT fk_role_permissions_permission_id_permissions FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE RESTRICT
);
CREATE INDEX ix_role_permissions_role_id ON role_permissions (role_id);
CREATE INDEX ix_role_permissions_permission_id ON role_permissions (permission_id);

CREATE TABLE sessions (
  id UUID CONSTRAINT pk_sessions PRIMARY KEY,
  token_family_id UUID CONSTRAINT uq_sessions_token_family_id UNIQUE NOT NULL,
  user_id UUID NOT NULL, auth_version INTEGER NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL, absolute_expires_at TIMESTAMPTZ NOT NULL,
  inactivity_expires_at TIMESTAMPTZ NOT NULL, last_used_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ, revocation_reason VARCHAR(128),
  client_metadata JSONB DEFAULT '{}'::jsonb NOT NULL,
  version_id INTEGER DEFAULT 1 NOT NULL,
  CONSTRAINT fk_sessions_user_id_users FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
  CONSTRAINT ck_sessions_absolute_expiry_after_issue CHECK (absolute_expires_at > issued_at),
  CONSTRAINT ck_sessions_inactivity_before_absolute CHECK (inactivity_expires_at <= absolute_expires_at),
  CONSTRAINT ck_sessions_auth_version_positive CHECK (auth_version > 0),
  CONSTRAINT ck_sessions_version_positive CHECK (version_id > 0)
);
CREATE INDEX ix_sessions_user_id ON sessions (user_id);
CREATE INDEX ix_sessions_user_active ON sessions (user_id, revoked_at);
CREATE TABLE refresh_tokens (
  id UUID CONSTRAINT pk_refresh_tokens PRIMARY KEY,
  session_id UUID NOT NULL, token_digest BYTEA CONSTRAINT uq_refresh_tokens_token_digest UNIQUE NOT NULL,
  parent_token_id UUID CONSTRAINT uq_refresh_tokens_parent_token_id UNIQUE,
  replacement_token_id UUID CONSTRAINT uq_refresh_tokens_replacement_token_id UNIQUE,
  issued_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ, revocation_reason VARCHAR(128),
  CONSTRAINT fk_refresh_tokens_session_id_sessions FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
  CONSTRAINT fk_refresh_tokens_parent_token_id_refresh_tokens FOREIGN KEY (parent_token_id) REFERENCES refresh_tokens(id) ON DELETE RESTRICT,
  CONSTRAINT fk_refresh_tokens_replacement_token_id_refresh_tokens FOREIGN KEY (replacement_token_id) REFERENCES refresh_tokens(id) ON DELETE RESTRICT,
  CONSTRAINT ck_refresh_tokens_digest_length CHECK (octet_length(token_digest) = 32),
  CONSTRAINT ck_refresh_tokens_expiry_after_issue CHECK (expires_at > issued_at)
);
CREATE INDEX ix_refresh_tokens_session_id ON refresh_tokens (session_id);
CREATE INDEX ix_refresh_tokens_session_issued ON refresh_tokens (session_id, issued_at);

CREATE TABLE audit_logs (
  id UUID CONSTRAINT pk_audit_logs PRIMARY KEY,
  actor_type VARCHAR(16) NOT NULL, actor_id UUID,
  action VARCHAR(128) NOT NULL, resource_type VARCHAR(64) NOT NULL, resource_id UUID,
  outcome VARCHAR(16) NOT NULL, occurred_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  correlation_id VARCHAR(128) NOT NULL, metadata JSONB DEFAULT '{}'::jsonb NOT NULL,
  CONSTRAINT fk_audit_logs_actor_id_users FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT ck_audit_logs_actor_type_values CHECK (actor_type IN ('user','anonymous','system')),
  CONSTRAINT ck_audit_logs_outcome_values CHECK (outcome IN ('success','failure','denied')),
  CONSTRAINT ck_audit_logs_metadata_size CHECK (octet_length(metadata::text) <= 16384)
);
CREATE INDEX ix_audit_logs_actor_id ON audit_logs (actor_id);
CREATE INDEX ix_audit_logs_action ON audit_logs (action);
CREATE INDEX ix_audit_logs_occurred_id ON audit_logs (occurred_at, id);
CREATE INDEX ix_audit_logs_resource ON audit_logs (resource_type, resource_id);
CREATE FUNCTION reject_audit_log_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit_logs is append-only for the application and runtime role'; END;
$$;
CREATE TRIGGER trg_audit_logs_append_only BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION reject_audit_log_mutation();
"""
        )
    )
    role = runtime_role()
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON users, roles, permissions, user_roles, "
        f"role_permissions, sessions, refresh_tokens TO {role}"
    )
    op.execute(f"GRANT SELECT, INSERT ON audit_logs TO {role}")
    op.execute(f"REVOKE UPDATE, DELETE ON audit_logs FROM {role}")


def downgrade() -> None:
    op.execute(
        text(
            """
DROP TRIGGER trg_audit_logs_append_only ON audit_logs;
DROP FUNCTION reject_audit_log_mutation();
DROP TABLE audit_logs;
DROP TABLE refresh_tokens;
DROP TABLE sessions;
DROP TABLE role_permissions;
DROP TABLE user_roles;
DROP TABLE permissions;
DROP TABLE roles;
DROP INDEX uq_users_email_present;
DROP TABLE users;
"""
        )
    )
