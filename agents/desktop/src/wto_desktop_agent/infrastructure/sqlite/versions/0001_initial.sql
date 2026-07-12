CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    checksum TEXT NOT NULL CHECK(length(checksum) = 64),
    applied_at TEXT NOT NULL
);

CREATE TABLE agent_identity (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    installation_id TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    platform TEXT NOT NULL,
    platform_version TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    device_id TEXT,
    agent_id TEXT,
    protocol_version TEXT,
    enrolled_at TEXT,
    revoked_at TEXT,
    enrollment_idempotency_key TEXT NOT NULL,
    enrollment_reported_at TEXT NOT NULL,
    active_credential_id TEXT,
    active_credential_version INTEGER,
    active_credential_fingerprint TEXT,
    active_credential_ref TEXT,
    active_credential_expires_at TEXT,
    previous_credential_id TEXT,
    previous_credential_ref TEXT,
    pending_credential_id TEXT,
    pending_credential_version INTEGER,
    pending_credential_fingerprint TEXT,
    pending_credential_ref TEXT,
    pending_credential_expires_at TEXT,
    rotation_id TEXT,
    rotation_idempotency_key TEXT,
    activation_idempotency_key TEXT,
    rotation_state TEXT NOT NULL DEFAULT 'none'
      CHECK(rotation_state IN ('none','requested','pending_stored','activation_uncertain','activated','revoked')),
    updated_at TEXT NOT NULL
);

CREATE TABLE runtime_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    boot_id TEXT NOT NULL,
    heartbeat_acked_sequence INTEGER NOT NULL DEFAULT -1,
    heartbeat_pending_sequence INTEGER,
    heartbeat_pending_payload TEXT,
    heartbeat_pending_hash TEXT,
    manifest_acked_sequence INTEGER NOT NULL DEFAULT -1,
    clean_shutdown INTEGER NOT NULL DEFAULT 1 CHECK(clean_shutdown IN (0,1)),
    started_at TEXT,
    stopped_at TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE capability_manifests (
    manifest_id TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL UNIQUE,
    payload TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash) = 64),
    server_digest TEXT CHECK(server_digest IS NULL OR length(server_digest) = 64),
    state TEXT NOT NULL CHECK(state IN ('pending','confirmed')),
    created_at TEXT NOT NULL,
    confirmed_at TEXT
);

CREATE TABLE inbox_tasks (
    task_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    task_type TEXT NOT NULL,
    task_type_version TEXT NOT NULL,
    payload TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash) = 64),
    effect_hash TEXT NOT NULL CHECK(length(effect_hash) = 64),
    canonical_task_id TEXT,
    state TEXT NOT NULL CHECK(state IN (
      'received','duplicate','skipped','blocked','rejected','queued','preparing','running',
      'cancel_requested','cleaning_up','completed','failed','cancelled','interrupted')),
    reason TEXT,
    received_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(canonical_task_id) REFERENCES inbox_tasks(task_id) ON DELETE RESTRICT
);
CREATE INDEX ix_inbox_tasks_state ON inbox_tasks(state, received_at);
CREATE INDEX ix_inbox_tasks_idempotency ON inbox_tasks(idempotency_key);

CREATE TABLE idempotency_effects (
    idempotency_key TEXT PRIMARY KEY,
    effect_hash TEXT NOT NULL CHECK(length(effect_hash) = 64),
    canonical_task_id TEXT NOT NULL UNIQUE,
    claimed_at TEXT,
    terminal_state TEXT,
    result_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(canonical_task_id) REFERENCES inbox_tasks(task_id) ON DELETE RESTRICT
);

CREATE TABLE task_attempts (
    attempt_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL UNIQUE,
    attempt_number INTEGER NOT NULL DEFAULT 1 CHECK(attempt_number = 1),
    claimed_at TEXT NOT NULL,
    invoked_at TEXT,
    finished_at TEXT,
    cleanup_requested_at TEXT,
    cleanup_completed_at TEXT,
    cleanup_attempts INTEGER NOT NULL DEFAULT 0,
    last_cleanup_error TEXT,
    FOREIGN KEY(task_id) REFERENCES inbox_tasks(task_id) ON DELETE RESTRICT
);

CREATE TABLE outbox_progress (
    event_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    payload TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash) = 64),
    state TEXT NOT NULL CHECK(state IN ('pending','in_flight','confirmed')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    confirmed_at TEXT,
    last_error TEXT,
    UNIQUE(task_id, sequence),
    FOREIGN KEY(task_id) REFERENCES inbox_tasks(task_id) ON DELETE RESTRICT
);

CREATE TABLE outbox_results (
    result_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL UNIQUE,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash) = 64),
    state TEXT NOT NULL CHECK(state IN ('pending','in_flight','confirmed')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    confirmed_at TEXT,
    last_error TEXT,
    FOREIGN KEY(task_id) REFERENCES inbox_tasks(task_id) ON DELETE RESTRICT
);

CREATE TABLE pending_uploads (
    upload_id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL UNIQUE,
    task_id TEXT NOT NULL,
    relative_path TEXT NOT NULL CHECK(relative_path NOT LIKE '/%' AND relative_path NOT LIKE '%..%'),
    media_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    payload TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash) = 64),
    state TEXT NOT NULL CHECK(state IN ('pending','in_flight','confirmed','failed')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    confirmed_at TEXT,
    last_error TEXT,
    FOREIGN KEY(task_id) REFERENCES inbox_tasks(task_id) ON DELETE RESTRICT
);

CREATE TABLE sync_state (
    channel TEXT PRIMARY KEY CHECK(channel IN ('progress','results','uploads')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT,
    last_success_at TEXT,
    last_error TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE quarantine (
    quarantine_id TEXT PRIMARY KEY,
    source_table TEXT NOT NULL,
    source_key TEXT NOT NULL,
    reason TEXT NOT NULL,
    raw_payload TEXT,
    observed_hash TEXT,
    quarantined_at TEXT NOT NULL
);
