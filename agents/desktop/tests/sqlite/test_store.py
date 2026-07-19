from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from wto_desktop_agent.domain.errors import DuplicateConflictError
from wto_desktop_agent.domain.models import LocalTaskEnvelope
from wto_desktop_agent.domain.states import TaskState
from wto_desktop_agent.infrastructure.sqlite.store import (
    APPLICATION_ID,
    SCHEMA_VERSION,
    SQLiteStore,
)


class _ConfigurationFailingConnection:
    def __init__(
        self,
        primary_error: BaseException,
        *,
        close_error: BaseException | None = None,
    ) -> None:
        self.primary_error = primary_error
        self.close_error = close_error
        self.close_calls = 0
        self.executed: list[str] = []
        self.row_factory: object | None = None

    def execute(self, statement: str) -> None:
        self.executed.append(statement)
        if statement == "PRAGMA journal_mode=WAL":
            raise self.primary_error

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


def _downgrade_to_schema_1(store: SQLiteStore) -> None:
    with store.connection() as connection:
        connection.execute("DROP TABLE windows_network_operations")
        connection.execute("DELETE FROM schema_migrations WHERE version=2")
        connection.execute("PRAGMA user_version=1")


def _initialize_store_process(path: str) -> None:
    SQLiteStore(Path(path)).initialize()


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


def test_connect_closes_connection_when_post_connect_configuration_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary_error = RuntimeError("synthetic final PRAGMA failure")
    connection = _ConfigurationFailingConnection(primary_error)

    def connect(*_args: object, **_kwargs: object) -> _ConfigurationFailingConnection:
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)

    with pytest.raises(RuntimeError) as raised:
        SQLiteStore(tmp_path / "agent.sqlite3")._connect()

    assert raised.value is primary_error
    assert connection.executed == [
        "PRAGMA foreign_keys=ON",
        "PRAGMA busy_timeout=5000",
        "PRAGMA synchronous=FULL",
        "PRAGMA journal_mode=WAL",
    ]
    assert connection.close_calls == 1


def test_connect_preserves_configuration_error_when_close_also_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary_error = RuntimeError("synthetic final PRAGMA failure")
    close_error = OSError("synthetic close failure")
    connection = _ConfigurationFailingConnection(
        primary_error,
        close_error=close_error,
    )

    def connect(*_args: object, **_kwargs: object) -> _ConfigurationFailingConnection:
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)

    with pytest.raises(RuntimeError) as raised:
        SQLiteStore(tmp_path / "agent.sqlite3")._connect()

    assert raised.value is primary_error
    assert connection.close_calls == 1
    assert raised.value.__notes__ == ["SQLite connection close also failed: OSError"]


def test_immutable_identity_read_creates_no_sqlite_sidecars(tmp_path: Path) -> None:
    path = tmp_path / "agent.sqlite3"
    store = SQLiteStore(path)
    store.initialize()
    installation_id = str(uuid4())
    store.ensure_identity(
        installation_id=installation_id,
        display_name="immutable-reader",
        platform="linux",
        platform_version="test",
        agent_version="0.1.0",
        enrollment_idempotency_key=str(uuid4()),
        enrollment_reported_at="2026-07-18T00:00:00Z",
    )
    with store.connection() as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    before = {
        item.name: (item.stat().st_mode, item.stat().st_size, item.read_bytes())
        for item in tmp_path.iterdir()
        if item.is_file()
    }

    identity = store.identity_immutable()

    after = {
        item.name: (item.stat().st_mode, item.stat().st_size, item.read_bytes())
        for item in tmp_path.iterdir()
        if item.is_file()
    }
    assert identity is not None
    assert identity["installation_id"] == installation_id
    assert after == before


def test_schema_1_is_backed_up_and_migrated_forward_to_schema_2(tmp_path: Path) -> None:
    path = tmp_path / "agent.sqlite3"
    store = SQLiteStore(path)
    store.initialize()
    _downgrade_to_schema_1(store)

    store.initialize()
    backup = path.with_suffix(path.suffix + ".pre-migrate.bak")
    original_hash = hashlib.sha256(backup.read_bytes()).hexdigest()
    original_inode = backup.stat().st_ino
    with store.connection() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert (
            connection.execute(
                "SELECT count(*) FROM sqlite_master "
                "WHERE type='table' AND name='windows_network_operations'"
            ).fetchone()[0]
            == 1
        )
    with closing(store._connect(backup)) as connection:
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1

    SQLiteStore(path).initialize()
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == original_hash
    assert backup.stat().st_ino == original_inode


def test_schema_2_initialization_never_creates_or_replaces_pre_migration_backup(
    tmp_path: Path,
) -> None:
    path = tmp_path / "agent.sqlite3"
    store = SQLiteStore(path)
    store.initialize()
    backup = path.with_suffix(path.suffix + ".pre-migrate.bak")
    assert not backup.exists()

    shutil.copy2(path, backup)
    original_hash = hashlib.sha256(backup.read_bytes()).hexdigest()
    original_inode = backup.stat().st_ino
    store.initialize()

    assert hashlib.sha256(backup.read_bytes()).hexdigest() == original_hash
    assert backup.stat().st_ino == original_inode
    assert SQLiteStore.verify_backup(backup) == 2


@pytest.mark.parametrize("application_id", [0, APPLICATION_ID + 1])
def test_existing_schema_2_requires_application_identity_without_mutation(
    tmp_path: Path, application_id: int
) -> None:
    path = tmp_path / "agent.sqlite3"
    store = SQLiteStore(path)
    store.initialize()
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(f"PRAGMA application_id={application_id}")
    before = path.read_bytes()

    with pytest.raises(RuntimeError, match="belongs to another application|not claimed"):
        SQLiteStore(path).initialize()

    assert path.read_bytes() == before
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("PRAGMA application_id").fetchone()[0] == application_id
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert not path.with_suffix(path.suffix + ".pre-migrate.bak").exists()


def test_pre_migration_backup_mismatch_blocks_without_overwrite(tmp_path: Path) -> None:
    live = SQLiteStore(tmp_path / "live.sqlite3")
    live.initialize()
    _downgrade_to_schema_1(live)

    other = SQLiteStore(tmp_path / "other.sqlite3")
    other.initialize()
    other.ensure_identity(
        installation_id=str(uuid4()),
        display_name="different",
        platform="simulated",
        platform_version="1",
        agent_version="0.1.0",
        enrollment_idempotency_key=str(uuid4()),
        enrollment_reported_at="2026-07-12T12:00:00Z",
    )
    _downgrade_to_schema_1(other)
    backup = live.path.with_suffix(live.path.suffix + ".pre-migrate.bak")
    other.create_verified_backup(backup)
    original = backup.read_bytes()

    with pytest.raises(RuntimeError, match="does not match"):
        live.initialize()

    assert backup.read_bytes() == original
    with closing(live._connect(live.path)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1


def test_corrupt_pre_migration_backup_blocks_without_overwrite(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    store.initialize()
    _downgrade_to_schema_1(store)
    backup = store.path.with_suffix(store.path.suffix + ".pre-migrate.bak")
    backup.write_bytes(b"not-a-sqlite-database")

    with pytest.raises((RuntimeError, sqlite3.DatabaseError)):
        store.initialize()

    assert backup.read_bytes() == b"not-a-sqlite-database"
    with closing(store._connect(store.path)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1


def test_concurrent_initializers_publish_one_immutable_schema_1_backup(
    tmp_path: Path,
) -> None:
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    store.initialize()
    _downgrade_to_schema_1(store)
    context = multiprocessing.get_context("spawn")
    processes = [
        context.Process(target=_initialize_store_process, args=(str(store.path),)) for _ in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20.0)
        assert not process.is_alive()
        assert process.exitcode == 0

    backup = store.path.with_suffix(store.path.suffix + ".pre-migrate.bak")
    assert SQLiteStore.verify_backup(backup) == 1
    original_hash = hashlib.sha256(backup.read_bytes()).hexdigest()
    original_inode = backup.stat().st_ino
    SQLiteStore(store.path).initialize()
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == original_hash
    assert backup.stat().st_ino == original_inode


def test_explicit_backup_rejects_live_hardlink_and_preserves_existing_destination(
    tmp_path: Path,
) -> None:
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    store.initialize()
    hardlink = tmp_path / "hardlink.sqlite3"
    os.link(store.path, hardlink)
    with pytest.raises(ValueError):
        store.create_verified_backup(hardlink)
    hardlink.unlink()

    destination = tmp_path / "existing.sqlite3"
    destination.write_bytes(b"preserve-me")

    class FailingBackupStore(SQLiteStore):
        def _backup_candidate(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            raise RuntimeError("synthetic backup failure")

    with pytest.raises(RuntimeError, match="synthetic backup failure"):
        FailingBackupStore(store.path).create_verified_backup(destination)
    assert destination.read_bytes() == b"preserve-me"


def test_explicit_backup_cannot_replace_or_alias_the_immutable_pre_migration_backup(
    tmp_path: Path,
) -> None:
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    store.initialize()
    _downgrade_to_schema_1(store)
    store.initialize()
    reserved = store.path.with_suffix(store.path.suffix + ".pre-migrate.bak")
    original_hash = hashlib.sha256(reserved.read_bytes()).hexdigest()
    original_inode = reserved.stat().st_ino

    with pytest.raises(ValueError, match="reserved immutable"):
        store.create_verified_backup(reserved)

    alias = tmp_path / "pre-migration-hardlink.sqlite3"
    os.link(reserved, alias)
    with pytest.raises(ValueError, match="reserved immutable|exactly one filesystem link"):
        store.create_verified_backup(alias)

    assert hashlib.sha256(reserved.read_bytes()).hexdigest() == original_hash
    assert reserved.stat().st_ino == original_inode


def test_explicit_backup_rejects_live_path_and_symlink_destination(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    store.initialize()
    with pytest.raises(ValueError, match="must differ"):
        store.create_verified_backup(store.path)

    target = tmp_path / "existing.sqlite3"
    target.write_bytes(b"preserve-target")
    symlink = tmp_path / "backup-link.sqlite3"
    try:
        symlink.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable on this host")
    with pytest.raises(ValueError, match="regular file"):
        store.create_verified_backup(symlink)
    assert target.read_bytes() == b"preserve-target"


def test_explicit_backup_restores_existing_destination_after_publication_fsync_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    store.initialize()
    destination = tmp_path / "existing.sqlite3"
    original = b"preserve-after-publication-failure"
    destination.write_bytes(original)
    real_fsync_file = store._fsync_file
    failed = False

    def fail_first_destination_fsync(path: Path) -> None:
        nonlocal failed
        if path == destination and not failed:
            failed = True
            raise OSError("synthetic destination fsync failure")
        real_fsync_file(path)

    monkeypatch.setattr(store, "_fsync_file", fail_first_destination_fsync)

    with pytest.raises(OSError, match="synthetic destination fsync failure"):
        store.create_verified_backup(destination)

    assert failed
    assert destination.read_bytes() == original
    assert not list(tmp_path.glob(".existing.sqlite3.previous-*"))


def test_explicit_backup_preserves_existing_destination_when_publication_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    store.initialize()
    destination = tmp_path / "existing.sqlite3"
    original = b"preserve-on-publication-failure"
    destination.write_bytes(original)
    real_replace = os.replace
    failed = False

    def fail_candidate_publication(source: Path | str, target: Path | str) -> None:
        nonlocal failed
        if Path(target) == destination and ".candidate-" in Path(source).name and not failed:
            failed = True
            raise OSError("synthetic publication failure")
        real_replace(source, target)

    monkeypatch.setattr(os, "replace", fail_candidate_publication)

    with pytest.raises(OSError, match="synthetic publication failure"):
        store.create_verified_backup(destination)

    assert failed
    assert destination.read_bytes() == original
    assert not list(tmp_path.glob(".existing.sqlite3.previous-*"))


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
    _downgrade_to_schema_1(base)

    class BrokenMigrationStore(SQLiteStore):
        def _apply_migrations(self, connection):  # type: ignore[no-untyped-def]
            connection.execute("UPDATE agent_identity SET display_name='corrupted'")
            raise RuntimeError("synthetic migration failure")

    with pytest.raises(RuntimeError):
        BrokenMigrationStore(path).initialize()
    assert SQLiteStore(path).identity()["display_name"] == "agent"  # type: ignore[index]
    pre_migration = path.with_suffix(path.suffix + ".pre-migrate.bak")
    original_hash = hashlib.sha256(pre_migration.read_bytes()).hexdigest()
    original_inode = pre_migration.stat().st_ino

    SQLiteStore(path).initialize()

    assert hashlib.sha256(pre_migration.read_bytes()).hexdigest() == original_hash
    assert pre_migration.stat().st_ino == original_inode
