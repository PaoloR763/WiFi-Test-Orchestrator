"""Add Phase 04 contracts, agent identity, credentials and presence.

Revision ID: 20260712_0004
Revises: 20260712_0003
Create Date: 2026-07-12 01:00:00+00:00
"""

from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

from wto_backend.config import get_settings

revision: str = "20260712_0004"
down_revision: str | None = "20260712_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def runtime_role() -> str:
    connection = op.get_bind()
    return connection.dialect.identifier_preparer.quote(get_settings().postgres_runtime_role)


def upgrade() -> None:
    op.execute(
        text(
            """
ALTER TABLE devices ADD COLUMN platform VARCHAR(16);
ALTER TABLE devices ADD COLUMN platform_version VARCHAR(64);

ALTER TABLE agents ADD COLUMN installation_id UUID;
ALTER TABLE agents ADD COLUMN protocol_min_version VARCHAR(32);
ALTER TABLE agents ADD COLUMN protocol_max_version VARCHAR(32);
ALTER TABLE agents ADD COLUMN protocol_version VARCHAR(32);
ALTER TABLE agents ADD COLUMN revoked_at TIMESTAMPTZ;
ALTER TABLE agents ADD COLUMN revoked_by_user_id UUID;
ALTER TABLE agents ADD COLUMN revocation_reason VARCHAR(128);
ALTER TABLE agents ADD COLUMN last_seen_at TIMESTAMPTZ;
ALTER TABLE agents ADD CONSTRAINT fk_agents_revoked_by_user_id_users
  FOREIGN KEY (revoked_by_user_id) REFERENCES users(id) ON DELETE SET NULL;
CREATE UNIQUE INDEX uq_agents_installation_id_present ON agents(installation_id)
  WHERE installation_id IS NOT NULL;

ALTER TABLE capabilities ADD COLUMN is_active BOOLEAN DEFAULT TRUE NOT NULL;
ALTER TABLE capabilities ADD CONSTRAINT ck_capabilities_key_format
  CHECK (key ~ '^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$');
ALTER TABLE capabilities ADD CONSTRAINT ck_capabilities_version_format
  CHECK (version ~ '^[0-9]+\\.[0-9]+\\.[0-9]+$');

ALTER TABLE enrollment_tokens ADD COLUMN digest_key_version INTEGER DEFAULT 1 NOT NULL;
ALTER TABLE enrollment_tokens ADD COLUMN scope VARCHAR(32) DEFAULT 'agent.enroll' NOT NULL;
ALTER TABLE enrollment_tokens ADD COLUMN max_uses INTEGER DEFAULT 1 NOT NULL;
ALTER TABLE enrollment_tokens ADD COLUMN uses_consumed INTEGER DEFAULT 0 NOT NULL;
ALTER TABLE enrollment_tokens ADD COLUMN restrictions JSONB DEFAULT '{}'::jsonb NOT NULL;
ALTER TABLE enrollment_tokens ADD COLUMN revoked_by_user_id UUID;
ALTER TABLE enrollment_tokens ADD COLUMN revocation_reason VARCHAR(128);
ALTER TABLE enrollment_tokens ADD COLUMN version_id INTEGER DEFAULT 1 NOT NULL;
UPDATE enrollment_tokens SET uses_consumed = 1 WHERE consumed_at IS NOT NULL;
ALTER TABLE enrollment_tokens ADD CONSTRAINT fk_enrollment_tokens_revoked_by_user_id_users
  FOREIGN KEY (revoked_by_user_id) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE enrollment_tokens ADD CONSTRAINT ck_enrollment_tokens_scope_values
  CHECK (scope IN ('agent.enroll','agent.recover'));
ALTER TABLE enrollment_tokens ADD CONSTRAINT ck_enrollment_tokens_single_use
  CHECK (max_uses = 1 AND uses_consumed BETWEEN 0 AND 1);
ALTER TABLE enrollment_tokens ADD CONSTRAINT ck_enrollment_tokens_restrictions_size
  CHECK (octet_length(restrictions::text) <= 4096);
ALTER TABLE enrollment_tokens ADD CONSTRAINT ck_enrollment_tokens_version_positive
  CHECK (version_id > 0);

CREATE TABLE agent_credentials (
  id UUID CONSTRAINT pk_agent_credentials PRIMARY KEY,
  agent_id UUID NOT NULL, credential_version INTEGER NOT NULL,
  secret_digest BYTEA NOT NULL, digest_key_version INTEGER DEFAULT 1 NOT NULL,
  state VARCHAR(16) NOT NULL, issued_at TIMESTAMPTZ NOT NULL,
  activated_at TIMESTAMPTZ, expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ, revoked_by_user_id UUID, revocation_reason VARCHAR(128),
  version_id INTEGER DEFAULT 1 NOT NULL,
  CONSTRAINT fk_agent_credentials_agent_id_agents FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE RESTRICT,
  CONSTRAINT fk_agent_credentials_revoked_by_user_id_users FOREIGN KEY(revoked_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT uq_agent_credentials_agent_version UNIQUE(agent_id, credential_version),
  CONSTRAINT ck_agent_credentials_secret_digest_length CHECK(octet_length(secret_digest) = 32),
  CONSTRAINT ck_agent_credentials_state_values CHECK(state IN ('pending','active','revoked','expired')),
  CONSTRAINT ck_agent_credentials_expiry CHECK(expires_at > issued_at),
  CONSTRAINT ck_agent_credentials_version_positive CHECK(version_id > 0)
);
CREATE INDEX ix_agent_credentials_agent_id ON agent_credentials(agent_id);
CREATE UNIQUE INDEX uq_agent_credentials_one_active ON agent_credentials(agent_id) WHERE state = 'active';
CREATE UNIQUE INDEX uq_agent_credentials_one_pending ON agent_credentials(agent_id) WHERE state = 'pending';

CREATE TABLE agent_credential_rotations (
  id UUID CONSTRAINT pk_agent_credential_rotations PRIMARY KEY,
  agent_id UUID NOT NULL, previous_credential_id UUID NOT NULL,
  pending_credential_id UUID CONSTRAINT uq_agent_credential_rotations_pending_credential_id UNIQUE NOT NULL,
  state VARCHAR(16) NOT NULL, created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL, activated_at TIMESTAMPTZ,
  version_id INTEGER DEFAULT 1 NOT NULL,
  CONSTRAINT fk_agent_credential_rotations_agent_id_agents FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE RESTRICT,
  CONSTRAINT fk_agent_credential_rotations_previous_credential_id_agent_credentials FOREIGN KEY(previous_credential_id) REFERENCES agent_credentials(id) ON DELETE RESTRICT,
  CONSTRAINT fk_agent_credential_rotations_pending_credential_id_agent_credentials FOREIGN KEY(pending_credential_id) REFERENCES agent_credentials(id) ON DELETE RESTRICT,
  CONSTRAINT ck_agent_credential_rotations_state_values CHECK(state IN ('pending','activated','expired','revoked')),
  CONSTRAINT ck_agent_credential_rotations_expiry CHECK(expires_at > created_at),
  CONSTRAINT ck_agent_credential_rotations_version_positive CHECK(version_id > 0)
);
CREATE INDEX ix_agent_credential_rotations_agent_id ON agent_credential_rotations(agent_id);
CREATE UNIQUE INDEX uq_agent_credential_rotations_one_pending ON agent_credential_rotations(agent_id) WHERE state = 'pending';

CREATE TABLE idempotency_records (
  id UUID CONSTRAINT pk_idempotency_records PRIMARY KEY,
  principal_type VARCHAR(32) NOT NULL, principal_id UUID NOT NULL,
  operation_id VARCHAR(128) NOT NULL, idempotency_key UUID NOT NULL,
  request_fingerprint BYTEA NOT NULL, state VARCHAR(16) NOT NULL,
  response_status INTEGER, response_body JSONB,
  created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL, version_id INTEGER DEFAULT 1 NOT NULL,
  CONSTRAINT uq_idempotency_records_scope UNIQUE(principal_type, principal_id, operation_id, idempotency_key),
  CONSTRAINT ck_idempotency_records_fingerprint_length CHECK(octet_length(request_fingerprint) = 32),
  CONSTRAINT ck_idempotency_records_state_values CHECK(state IN ('pending','completed','failed')),
  CONSTRAINT ck_idempotency_records_response_size CHECK(response_body IS NULL OR octet_length(response_body::text) <= 1048576),
  CONSTRAINT ck_idempotency_records_expiry CHECK(expires_at > created_at),
  CONSTRAINT ck_idempotency_records_version_positive CHECK(version_id > 0)
);
CREATE INDEX ix_idempotency_records_expires_at ON idempotency_records(expires_at);

CREATE TABLE secret_replays (
  id UUID CONSTRAINT pk_secret_replays PRIMARY KEY,
  idempotency_record_id UUID CONSTRAINT uq_secret_replays_idempotency_record_id UNIQUE NOT NULL,
  ciphertext BYTEA NOT NULL, nonce BYTEA NOT NULL,
  encryption_key_version INTEGER DEFAULT 1 NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT fk_secret_replays_idempotency_record_id_idempotency_records FOREIGN KEY(idempotency_record_id) REFERENCES idempotency_records(id) ON DELETE CASCADE,
  CONSTRAINT ck_secret_replays_nonce_length CHECK(octet_length(nonce) = 12),
  CONSTRAINT ck_secret_replays_ciphertext_size CHECK(octet_length(ciphertext) <= 65536)
);
CREATE INDEX ix_secret_replays_expires_at ON secret_replays(expires_at);

CREATE TABLE capability_manifests (
  id UUID CONSTRAINT pk_capability_manifests PRIMARY KEY,
  agent_id UUID NOT NULL, manifest_sequence BIGINT NOT NULL,
  schema_version VARCHAR(32) NOT NULL, catalog_version VARCHAR(32) NOT NULL,
  generated_at TIMESTAMPTZ NOT NULL, server_received_at TIMESTAMPTZ NOT NULL,
  document_digest BYTEA NOT NULL, document JSONB NOT NULL,
  CONSTRAINT fk_capability_manifests_agent_id_agents FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE RESTRICT,
  CONSTRAINT uq_capability_manifests_sequence UNIQUE(agent_id, manifest_sequence),
  CONSTRAINT ck_capability_manifests_document_size CHECK(octet_length(document::text) <= 262144),
  CONSTRAINT ck_capability_manifests_digest_length CHECK(octet_length(document_digest) = 32)
);
CREATE INDEX ix_capability_manifests_agent_id ON capability_manifests(agent_id);
CREATE INDEX ix_capability_manifests_agent_received ON capability_manifests(agent_id, server_received_at);

CREATE TABLE agent_presence (
  id UUID CONSTRAINT pk_agent_presence PRIMARY KEY,
  agent_id UUID CONSTRAINT uq_agent_presence_agent_id UNIQUE NOT NULL,
  kind VARCHAR(16) NOT NULL, boot_id UUID NOT NULL, sequence BIGINT NOT NULL,
  payload_digest BYTEA NOT NULL, agent_reported_at TIMESTAMPTZ NOT NULL,
  server_received_at TIMESTAMPTZ NOT NULL, presence_expires_at TIMESTAMPTZ NOT NULL,
  manifest_id UUID NOT NULL, version_id INTEGER DEFAULT 1 NOT NULL,
  CONSTRAINT fk_agent_presence_agent_id_agents FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE RESTRICT,
  CONSTRAINT fk_agent_presence_manifest_id_capability_manifests FOREIGN KEY(manifest_id) REFERENCES capability_manifests(id) ON DELETE RESTRICT,
  CONSTRAINT ck_agent_presence_kind_values CHECK(kind IN ('desktop','mobile')),
  CONSTRAINT ck_agent_presence_payload_digest_length CHECK(octet_length(payload_digest) = 32),
  CONSTRAINT ck_agent_presence_version_positive CHECK(version_id > 0)
);
CREATE INDEX ix_agent_presence_expires_at ON agent_presence(presence_expires_at);

ALTER TABLE audit_logs DROP CONSTRAINT ck_audit_logs_actor_type_values;
ALTER TABLE audit_logs ADD COLUMN actor_agent_id UUID;
ALTER TABLE audit_logs ADD CONSTRAINT fk_audit_logs_actor_agent_id_agents
  FOREIGN KEY(actor_agent_id) REFERENCES agents(id) ON DELETE SET NULL;
ALTER TABLE audit_logs ADD CONSTRAINT ck_audit_logs_actor_type_values
  CHECK(actor_type IN ('user','agent','anonymous','system'));
ALTER TABLE audit_logs ADD CONSTRAINT ck_audit_logs_actor_identity
  CHECK((actor_type='user' AND actor_id IS NOT NULL AND actor_agent_id IS NULL) OR
        (actor_type='agent' AND actor_id IS NULL AND actor_agent_id IS NOT NULL) OR
        (actor_type IN ('anonymous','system') AND actor_id IS NULL AND actor_agent_id IS NULL));
CREATE INDEX ix_audit_logs_actor_agent_id ON audit_logs(actor_agent_id);
"""
        )
    )
    role = runtime_role()
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON agent_credentials, agent_credential_rotations, "
        f"idempotency_records, secret_replays, capability_manifests, agent_presence TO {role}"
    )


def downgrade() -> None:
    op.execute(
        text(
            """
DROP INDEX ix_audit_logs_actor_agent_id;
ALTER TABLE audit_logs DROP CONSTRAINT ck_audit_logs_actor_identity;
ALTER TABLE audit_logs DROP CONSTRAINT ck_audit_logs_actor_type_values;
ALTER TABLE audit_logs DROP CONSTRAINT fk_audit_logs_actor_agent_id_agents;
ALTER TABLE audit_logs DROP COLUMN actor_agent_id;
ALTER TABLE audit_logs ADD CONSTRAINT ck_audit_logs_actor_type_values CHECK(actor_type IN ('user','anonymous','system'));
DROP TABLE agent_presence;
DROP TABLE capability_manifests;
DROP TABLE secret_replays;
DROP TABLE idempotency_records;
DROP TABLE agent_credential_rotations;
DROP TABLE agent_credentials;
ALTER TABLE enrollment_tokens DROP CONSTRAINT ck_enrollment_tokens_version_positive;
ALTER TABLE enrollment_tokens DROP CONSTRAINT ck_enrollment_tokens_restrictions_size;
ALTER TABLE enrollment_tokens DROP CONSTRAINT ck_enrollment_tokens_single_use;
ALTER TABLE enrollment_tokens DROP CONSTRAINT ck_enrollment_tokens_scope_values;
ALTER TABLE enrollment_tokens DROP CONSTRAINT fk_enrollment_tokens_revoked_by_user_id_users;
ALTER TABLE enrollment_tokens DROP COLUMN version_id;
ALTER TABLE enrollment_tokens DROP COLUMN revocation_reason;
ALTER TABLE enrollment_tokens DROP COLUMN revoked_by_user_id;
ALTER TABLE enrollment_tokens DROP COLUMN restrictions;
ALTER TABLE enrollment_tokens DROP COLUMN uses_consumed;
ALTER TABLE enrollment_tokens DROP COLUMN max_uses;
ALTER TABLE enrollment_tokens DROP COLUMN scope;
ALTER TABLE enrollment_tokens DROP COLUMN digest_key_version;
ALTER TABLE capabilities DROP CONSTRAINT ck_capabilities_version_format;
ALTER TABLE capabilities DROP CONSTRAINT ck_capabilities_key_format;
ALTER TABLE capabilities DROP COLUMN is_active;
DROP INDEX uq_agents_installation_id_present;
ALTER TABLE agents DROP CONSTRAINT fk_agents_revoked_by_user_id_users;
ALTER TABLE agents DROP COLUMN last_seen_at;
ALTER TABLE agents DROP COLUMN revocation_reason;
ALTER TABLE agents DROP COLUMN revoked_by_user_id;
ALTER TABLE agents DROP COLUMN revoked_at;
ALTER TABLE agents DROP COLUMN protocol_version;
ALTER TABLE agents DROP COLUMN protocol_max_version;
ALTER TABLE agents DROP COLUMN protocol_min_version;
ALTER TABLE agents DROP COLUMN installation_id;
ALTER TABLE devices DROP COLUMN platform_version;
ALTER TABLE devices DROP COLUMN platform;
"""
        )
    )
