from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from wto_desktop_agent.domain.errors import DuplicateConflictError
from wto_desktop_agent.domain.models import LocalTaskEnvelope
from wto_desktop_agent.domain.states import TaskState
from wto_desktop_agent.infrastructure.sqlite.store import APPLICATION_ID, SQLiteStore


def task(
    *,
    task_id: str | None = None,
    key: str | None = None,
    parameters: dict | None = None,
) -> LocalTaskEnvelope:
    now = datetime.now(UTC)
    return LocalTaskEnvelope(
        task_id=task_id or str(uuid4()),
        execution_id=str(uuid4()),
        task_type="protocol.contract_check",
        task_type_version="1.0.0",
        issued_at=now,
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        idempotency_key=key or str(uuid4()),
        required_capabilities=["network.http.probe"],
        foreground_requirement="not_required",
        user_interaction_requirement="none",
        parameters=parameters or {},
    )


def test_schema_inventory_pragmas_and_migration(store: SQLiteStore) -> None:
    expected = {
        "schema_migrations",
        "agent_identity",
        "runtime_state",
        "capability_manifests",
        "inbox_tasks",
        "idempotency_effects",
        "task_attempts",
        "outbox_progress",
        "outbox_results",
        "pending_uploads",
        "sync_state",
        "quarantine",
        "windows_network_operations",
    }
    with store.connection() as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert expected <= tables
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert connection.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2


def test_schema_1_is_backed_up_and_migrated_forward_to_schema_2(tmp_path: Path) -> None:
    path = tmp_path / "agent.sqlite3"
    store = SQLiteStore(path)
    store.initialize()
    with store.connection() as connection:
        connection.execute("DROP TABLE windows_network_operations")
        connection.execute("DELETE FROM schema_migrations WHERE version=2")
        connection.execute("PRAGMA user_version=1")

    store.initialize()
    backup = path.with_suffix(path.suffix + ".pre-migrate.bak")
    with store.connection() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert (
            connection.execute(
                "SELECT count(*) FROM sqlite_master "
                "WHERE type='table' AND name='windows_network_operations'"
            ).fetchone()[0]
            == 1
        )
    with store._connect(backup) as connection:
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1


def test_task_id_and_idempotency_deduplication(store: SQLiteStore) -> None:
    first = task()
    assert store.ingest_task(first) == "queued"
    assert store.ingest_task(first) == "duplicate"
    changed = first.model_copy(update={"parameters": {"unexpected": True}})
    with pytest.raises(DuplicateConflictError):
        store.ingest_task(changed)
    duplicate_effect = first.model_copy(update={"task_id": uuid4()})
    assert store.ingest_task(duplicate_effect) == "duplicate"
    assert len(store.rows("idempotency_effects")) == 1
    assert len(store.rows("quarantine")) == 1


def test_concurrent_same_idempotency_key_has_one_canonical_effect(
    store: SQLiteStore,
) -> None:
    original = task()
    duplicates = [original.model_copy(update={"task_id": uuid4()}) for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(store.ingest_task, duplicates))
    assert outcomes.count("queued") == 1
    assert outcomes.count("duplicate") == 7
    assert len(store.rows("idempotency_effects")) == 1


def test_claim_is_unique_and_restart_never_redispatches(store: SQLiteStore) -> None:
    item = task()
    store.ingest_task(item)
    assert store.claim_task(str(item.task_id)) is not None
    assert store.claim_task(str(item.task_id)) is None
    assert store.recover_interrupted() == 1
    assert store.queued_tasks(10) == []
    assert store.rows("inbox_tasks")[0]["state"] == TaskState.INTERRUPTED.value
    attempt = store.rows("task_attempts")[0]
    assert attempt["cleanup_requested_at"] is not None
    assert attempt["cleanup_completed_at"] is None


def test_corrupt_row_is_quarantined(store: SQLiteStore) -> None:
    item = task()
    store.ingest_task(item)
    with store.connection() as connection:
        connection.execute(
            "UPDATE inbox_tasks SET payload=? WHERE task_id=?",
            (json.dumps({"broken": True}), str(item.task_id)),
        )
    assert store.queued_tasks(1) == []
    assert store.rows("inbox_tasks")[0]["state"] == "rejected"
    assert store.rows("quarantine")[0]["reason"] == "corrupt_task_row"


def test_verified_backup_and_failed_migration_restore(tmp_path: Path) -> None:
    path = tmp_path / "agent.sqlite3"
    base = SQLiteStore(path)
    base.initialize()
    base.ensure_identity(
        installation_id=str(uuid4()),
        display_name="agent",
        platform="simulated",
        platform_version="1",
        agent_version="0.1.0",
        enrollment_idempotency_key=str(uuid4()),
        enrollment_reported_at="2026-07-12T12:00:00Z",
    )
    backup = tmp_path / "backup.sqlite3"
    base.create_verified_backup(backup)
    assert backup.exists()

    class BrokenMigrationStore(SQLiteStore):
        def _apply_migrations(self, connection):  # type: ignore[no-untyped-def]
            connection.execute("UPDATE agent_identity SET display_name='corrupted'")
            raise RuntimeError("synthetic migration failure")

    with pytest.raises(RuntimeError):
        BrokenMigrationStore(path).initialize()
    assert SQLiteStore(path).identity()["display_name"] == "agent"  # type: ignore[index]
