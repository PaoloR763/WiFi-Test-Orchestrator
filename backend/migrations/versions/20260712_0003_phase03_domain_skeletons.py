"""Create minimal Phase 03 continuity skeletons.

Revision ID: 20260712_0003
Revises: 20260712_0002
Create Date: 2026-07-12 00:05:00+00:00
"""

from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

from wto_backend.config import get_settings

revision: str = "20260712_0003"
down_revision: str | None = "20260712_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def runtime_role() -> str:
    connection = op.get_bind()
    return connection.dialect.identifier_preparer.quote(get_settings().postgres_runtime_role)


def upgrade() -> None:
    op.execute(
        text(
            """
CREATE TABLE devices (
  id UUID CONSTRAINT pk_devices PRIMARY KEY, display_name VARCHAR(128) NOT NULL,
  is_active BOOLEAN DEFAULT TRUE NOT NULL, disabled_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL, updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  version_id INTEGER DEFAULT 1 NOT NULL, CONSTRAINT ck_devices_version_positive CHECK (version_id > 0)
);
CREATE TABLE agents (
  id UUID CONSTRAINT pk_agents PRIMARY KEY, device_id UUID, display_name VARCHAR(128) NOT NULL,
  is_active BOOLEAN DEFAULT TRUE NOT NULL, disabled_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL, updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  version_id INTEGER DEFAULT 1 NOT NULL,
  CONSTRAINT fk_agents_device_id_devices FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE RESTRICT,
  CONSTRAINT ck_agents_version_positive CHECK (version_id > 0)
);
CREATE INDEX ix_agents_device_id ON agents(device_id);
CREATE TABLE capabilities (
  id UUID CONSTRAINT pk_capabilities PRIMARY KEY, key VARCHAR(128) NOT NULL, version VARCHAR(32) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL, updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  CONSTRAINT uq_capabilities_key_version UNIQUE(key, version)
);
CREATE TABLE test_definitions (
  id UUID CONSTRAINT pk_test_definitions PRIMARY KEY, name VARCHAR(128) NOT NULL, revision INTEGER NOT NULL,
  created_by_user_id UUID, created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT now() NOT NULL, version_id INTEGER DEFAULT 1 NOT NULL,
  CONSTRAINT fk_test_definitions_created_by_user_id_users FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT uq_test_definitions_name_revision UNIQUE(name, revision),
  CONSTRAINT ck_test_definitions_revision_positive CHECK (revision > 0),
  CONSTRAINT ck_test_definitions_version_positive CHECK (version_id > 0)
);
CREATE TABLE campaigns (
  id UUID CONSTRAINT pk_campaigns PRIMARY KEY, name VARCHAR(128) NOT NULL,
  test_definition_id UUID, created_by_user_id UUID,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL, updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  version_id INTEGER DEFAULT 1 NOT NULL,
  CONSTRAINT fk_campaigns_test_definition_id_test_definitions FOREIGN KEY (test_definition_id) REFERENCES test_definitions(id) ON DELETE RESTRICT,
  CONSTRAINT fk_campaigns_created_by_user_id_users FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT ck_campaigns_version_positive CHECK (version_id > 0)
);
CREATE INDEX ix_campaigns_test_definition_id ON campaigns(test_definition_id);
CREATE TABLE executions (
  id UUID CONSTRAINT pk_executions PRIMARY KEY, campaign_id UUID, agent_id UUID,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  CONSTRAINT fk_executions_campaign_id_campaigns FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE RESTRICT,
  CONSTRAINT fk_executions_agent_id_agents FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE RESTRICT
);
CREATE INDEX ix_executions_campaign_id ON executions(campaign_id);
CREATE INDEX ix_executions_agent_id ON executions(agent_id);
CREATE TABLE metrics (
  id UUID CONSTRAINT pk_metrics PRIMARY KEY, execution_id UUID NOT NULL,
  metric_key VARCHAR(128) NOT NULL, observed_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT fk_metrics_execution_id_executions FOREIGN KEY (execution_id) REFERENCES executions(id) ON DELETE RESTRICT
);
CREATE INDEX ix_metrics_execution_id ON metrics(execution_id);
CREATE TABLE artifacts (
  id UUID CONSTRAINT pk_artifacts PRIMARY KEY, execution_id UUID NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  CONSTRAINT fk_artifacts_execution_id_executions FOREIGN KEY (execution_id) REFERENCES executions(id) ON DELETE RESTRICT
);
CREATE INDEX ix_artifacts_execution_id ON artifacts(execution_id);
CREATE TABLE enrollment_tokens (
  id UUID CONSTRAINT pk_enrollment_tokens PRIMARY KEY, token_digest BYTEA CONSTRAINT uq_enrollment_tokens_token_digest UNIQUE NOT NULL,
  created_by_user_id UUID, created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ,
  CONSTRAINT fk_enrollment_tokens_created_by_user_id_users FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT ck_enrollment_tokens_digest_length CHECK (octet_length(token_digest) = 32),
  CONSTRAINT ck_enrollment_tokens_expiry_after_creation CHECK (expires_at > created_at)
);
"""
        )
    )
    role = runtime_role()
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON devices, agents, capabilities, test_definitions, "
        f"campaigns, executions, metrics, artifacts, enrollment_tokens TO {role}"
    )


def downgrade() -> None:
    op.execute(
        text(
            """
DROP TABLE enrollment_tokens;
DROP TABLE artifacts;
DROP TABLE metrics;
DROP TABLE executions;
DROP TABLE campaigns;
DROP TABLE test_definitions;
DROP TABLE capabilities;
DROP TABLE agents;
DROP TABLE devices;
"""
        )
    )
