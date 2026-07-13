CREATE TABLE windows_network_operations (
    operation_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    intent_hash TEXT NOT NULL CHECK(length(intent_hash) = 64),
    action TEXT NOT NULL CHECK(action IN ('connect','disconnect','scan')),
    interface_guid TEXT NOT NULL,
    target_profile TEXT,
    previous_profile TEXT,
    state TEXT NOT NULL CHECK(state IN (
      'intent_recorded','running','completed','failed','cancelled','reconciling','rolled_back'
    )),
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    reconciliation_result TEXT,
    last_error TEXT
);
CREATE INDEX ix_windows_network_operations_state
ON windows_network_operations(state, updated_at);
