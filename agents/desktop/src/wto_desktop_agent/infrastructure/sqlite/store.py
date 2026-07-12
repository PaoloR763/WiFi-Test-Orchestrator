from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from wto_desktop_agent.domain.errors import DuplicateConflictError, StateConflictError
from wto_desktop_agent.domain.models import LocalTaskEnvelope
from wto_desktop_agent.domain.states import TaskState, ensure_transition
from wto_desktop_agent.infrastructure.contracts import canonical_json

APPLICATION_ID = 0x57544F05
SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def digest(payload: object) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


class SQLiteStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def _connect(self, path: Path | None = None) -> sqlite3.Connection:
        connection = sqlite3.connect(path or self.path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA synchronous=FULL")
        if path is None:
            connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.exists()
        backup = self.path.with_suffix(self.path.suffix + ".pre-migrate.bak")
        if existed:
            self.create_verified_backup(backup)
        try:
            with self.connection() as connection:
                current_application_id = int(
                    connection.execute("PRAGMA application_id").fetchone()[0]
                )
                if current_application_id not in (0, APPLICATION_ID):
                    raise RuntimeError("SQLite application_id belongs to another application")
                connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                self._apply_migrations(connection)
                check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
                if check != "ok":
                    raise RuntimeError("SQLite quick_check failed")
        except Exception:
            if existed and backup.exists():
                failed = self.path.with_name(f"{self.path.name}.migration-failed-{uuid4()}")
                if self.path.exists():
                    shutil.copy2(self.path, failed)
                shutil.copy2(backup, self.path)
            raise

    def _apply_migrations(self, connection: sqlite3.Connection) -> None:
        migration_root = Path(
            str(files("wto_desktop_agent.infrastructure.sqlite").joinpath("versions"))
        )
        for path in sorted(migration_root.glob("*.sql")):
            version = int(path.name.split("_", 1)[0])
            sql = path.read_text(encoding="utf-8")
            checksum = hashlib.sha256(sql.encode("utf-8")).hexdigest()
            try:
                existing = connection.execute(
                    "SELECT checksum FROM schema_migrations WHERE version=?", (version,)
                ).fetchone()
            except sqlite3.OperationalError:
                existing = None
            if existing:
                if str(existing["checksum"]) != checksum:
                    raise RuntimeError(f"SQLite migration checksum mismatch: {path.name}")
                continue
            quoted_name = path.name.replace("'", "''")
            script = (
                "BEGIN IMMEDIATE;\n"
                + sql
                + f"\nINSERT INTO schema_migrations(version,name,checksum,applied_at) VALUES "
                f"({version},'{quoted_name}','{checksum}','{utc_now()}');\n"
                f"PRAGMA user_version={version};\nCOMMIT;"
            )
            connection.executescript(script)
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if user_version != SCHEMA_VERSION:
            raise RuntimeError(f"unsupported SQLite schema version: {user_version}")

    def create_verified_backup(self, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as source, self._connect(destination) as target:
            source.backup(target)
            result = str(target.execute("PRAGMA quick_check").fetchone()[0])
            if result != "ok":
                destination.unlink(missing_ok=True)
                raise RuntimeError("SQLite backup verification failed")

    def identity(self) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM agent_identity WHERE singleton=1").fetchone()
            return dict(row) if row else None

    def ensure_identity(
        self,
        *,
        installation_id: str,
        display_name: str,
        platform: str,
        platform_version: str,
        agent_version: str,
        enrollment_idempotency_key: str,
        enrollment_reported_at: str,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM agent_identity WHERE singleton=1").fetchone()
            if row is None:
                connection.execute(
                    """INSERT INTO agent_identity(
                    singleton,installation_id,display_name,platform,platform_version,agent_version,
                    enrollment_idempotency_key,enrollment_reported_at,updated_at)
                    VALUES(1,?,?,?,?,?,?,?,?)""",
                    (
                        installation_id,
                        display_name,
                        platform,
                        platform_version,
                        agent_version,
                        enrollment_idempotency_key,
                        enrollment_reported_at,
                        now,
                    ),
                )
            connection.commit()
        identity = self.identity()
        assert identity is not None
        return identity

    def update_identity(self, values: dict[str, object]) -> None:
        allowed = {
            "device_id",
            "agent_id",
            "protocol_version",
            "enrolled_at",
            "revoked_at",
            "active_credential_id",
            "active_credential_version",
            "active_credential_fingerprint",
            "active_credential_ref",
            "active_credential_expires_at",
            "previous_credential_id",
            "previous_credential_ref",
            "pending_credential_id",
            "pending_credential_version",
            "pending_credential_fingerprint",
            "pending_credential_ref",
            "pending_credential_expires_at",
            "rotation_id",
            "rotation_idempotency_key",
            "activation_idempotency_key",
            "rotation_state",
        }
        if set(values) - allowed:
            raise ValueError("unsupported identity update")
        assignments = ",".join(f"{name}=?" for name in values) + ",updated_at=?"
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                f"UPDATE agent_identity SET {assignments} WHERE singleton=1",  # noqa: S608
                (*values.values(), utc_now()),
            )
            connection.commit()

    def start_runtime(self, boot_id: str) -> None:
        now = utc_now()
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO runtime_state(singleton,boot_id,clean_shutdown,started_at,updated_at)
                VALUES(1,?,0,?,?) ON CONFLICT(singleton) DO UPDATE SET
                boot_id=excluded.boot_id, clean_shutdown=0, started_at=excluded.started_at,
                stopped_at=NULL, updated_at=excluded.updated_at""",
                (boot_id, now, now),
            )
            connection.commit()

    def stop_runtime(self) -> None:
        now = utc_now()
        with self.connection() as connection:
            connection.execute(
                "UPDATE runtime_state SET clean_shutdown=1,stopped_at=?,updated_at=? "
                "WHERE singleton=1",
                (now, now),
            )

    def runtime_state(self) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM runtime_state WHERE singleton=1").fetchone()
            return dict(row) if row else None

    def pending_manifest(self) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM capability_manifests WHERE state='pending' ORDER BY sequence LIMIT 1"
            ).fetchone()
            return dict(row) if row else None

    def persist_manifest(self, manifest_id: str, sequence: int, payload: dict[str, Any]) -> None:
        encoded = canonical_json(payload).decode("utf-8")
        payload_hash = digest(payload)
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO capability_manifests(
                manifest_id,sequence,payload,payload_hash,state,created_at)
                VALUES(?,?,?,?, 'pending', ?)""",
                (manifest_id, sequence, encoded, payload_hash, utc_now()),
            )
            connection.commit()

    def confirm_manifest(self, manifest_id: str, sequence: int, server_digest: str) -> None:
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE capability_manifests SET state='confirmed',server_digest=?,confirmed_at=? "
                "WHERE manifest_id=? AND sequence=? AND state='pending'",
                (server_digest, utc_now(), manifest_id, sequence),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise StateConflictError("manifest confirmation conflict")
            connection.execute(
                "UPDATE runtime_state SET manifest_acked_sequence=?,updated_at=? WHERE singleton=1",
                (sequence, utc_now()),
            )
            connection.commit()

    def confirmed_manifest(self) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM capability_manifests WHERE state='confirmed' "
                "ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None

    def pending_heartbeat(self) -> dict[str, Any] | None:
        state = self.runtime_state()
        if not state or state["heartbeat_pending_payload"] is None:
            return None
        return cast(dict[str, Any], json.loads(str(state["heartbeat_pending_payload"])))

    def persist_heartbeat(self, sequence: int, payload: dict[str, Any]) -> None:
        encoded = canonical_json(payload).decode("utf-8")
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT heartbeat_pending_sequence FROM runtime_state WHERE singleton=1"
            ).fetchone()
            if row is None or row[0] is not None:
                connection.rollback()
                raise StateConflictError("heartbeat already pending or runtime not started")
            connection.execute(
                "UPDATE runtime_state SET heartbeat_pending_sequence=?,"
                "heartbeat_pending_payload=?,heartbeat_pending_hash=?,updated_at=? "
                "WHERE singleton=1",
                (sequence, encoded, digest(payload), utc_now()),
            )
            connection.commit()

    def confirm_heartbeat(self, sequence: int) -> None:
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE runtime_state SET heartbeat_acked_sequence=?,"
                "heartbeat_pending_sequence=NULL,heartbeat_pending_payload=NULL,"
                "heartbeat_pending_hash=NULL,updated_at=? WHERE singleton=1 "
                "AND heartbeat_pending_sequence=?",
                (sequence, utc_now(), sequence),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise StateConflictError("heartbeat confirmation conflict")
            connection.commit()

    def ingest_task(self, task: LocalTaskEnvelope) -> str:
        payload = task.model_dump(mode="json")
        encoded = canonical_json(payload).decode("utf-8")
        payload_hash = digest(payload)
        effect_hash = digest(task.logical_effect())
        now = utc_now()
        task_id = str(task.task_id)
        idempotency_key = str(task.idempotency_key)
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing_task = connection.execute(
                "SELECT payload_hash,state FROM inbox_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if existing_task:
                if str(existing_task["payload_hash"]) != payload_hash:
                    self._quarantine_in_transaction(
                        connection,
                        "inbox_tasks",
                        task_id,
                        "task_id_payload_conflict",
                        encoded,
                    )
                    connection.commit()
                    raise DuplicateConflictError("task_id was reused with a different payload")
                connection.commit()
                return "duplicate"
            effect = connection.execute(
                "SELECT effect_hash,canonical_task_id FROM idempotency_effects "
                "WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if effect:
                same = str(effect["effect_hash"]) == effect_hash
                state = TaskState.DUPLICATE if same else TaskState.BLOCKED
                reason = "idempotency_duplicate" if same else "idempotency_conflict"
                connection.execute(
                    "INSERT INTO inbox_tasks(task_id,execution_id,idempotency_key,task_type,"
                    "task_type_version,payload,payload_hash,effect_hash,canonical_task_id,state,"
                    "reason,received_at,expires_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        task_id,
                        str(task.execution_id),
                        idempotency_key,
                        task.task_type,
                        task.task_type_version,
                        encoded,
                        payload_hash,
                        effect_hash,
                        str(effect["canonical_task_id"]),
                        state.value,
                        json.dumps({"code": "blocked", "detail": reason}),
                        now,
                        task.expires_at.isoformat(),
                        now,
                    ),
                )
                connection.commit()
                return state.value
            connection.execute(
                """INSERT INTO inbox_tasks(task_id,execution_id,idempotency_key,task_type,
                task_type_version,payload,payload_hash,effect_hash,state,received_at,expires_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    task_id,
                    str(task.execution_id),
                    idempotency_key,
                    task.task_type,
                    task.task_type_version,
                    encoded,
                    payload_hash,
                    effect_hash,
                    TaskState.RECEIVED.value,
                    now,
                    task.expires_at.isoformat(),
                    now,
                ),
            )
            connection.execute(
                """INSERT INTO idempotency_effects(idempotency_key,effect_hash,canonical_task_id,
                created_at,updated_at) VALUES(?,?,?,?,?)""",
                (idempotency_key, effect_hash, task_id, now, now),
            )
            connection.execute(
                "UPDATE inbox_tasks SET state='queued',updated_at=? "
                "WHERE task_id=? AND state='received'",
                (now, task_id),
            )
            connection.commit()
            return TaskState.QUEUED.value

    def queued_tasks(self, limit: int) -> list[LocalTaskEnvelope]:
        result: list[LocalTaskEnvelope] = []
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT task_id,payload,payload_hash FROM inbox_tasks WHERE state='queued' "
                "ORDER BY received_at LIMIT ?",
                (limit,),
            ).fetchall()
            for row in rows:
                raw = str(row["payload"])
                try:
                    payload = json.loads(raw)
                    if digest(payload) != str(row["payload_hash"]):
                        raise ValueError("payload checksum mismatch")
                    result.append(LocalTaskEnvelope.model_validate(payload))
                except (ValueError, json.JSONDecodeError):
                    connection.execute("BEGIN IMMEDIATE")
                    self._quarantine_in_transaction(
                        connection,
                        "inbox_tasks",
                        str(row["task_id"]),
                        "corrupt_task_row",
                        raw,
                    )
                    connection.execute(
                        "UPDATE inbox_tasks SET state='rejected',reason=?,updated_at=? "
                        "WHERE task_id=? AND state='queued'",
                        (
                            json.dumps({"code": "blocked", "detail": "corrupt_row"}),
                            utc_now(),
                            str(row["task_id"]),
                        ),
                    )
                    connection.commit()
        return result

    def claim_task(self, task_id: str) -> str | None:
        now = utc_now()
        attempt_id = str(uuid4())
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT idempotency_key,state FROM inbox_tasks WHERE task_id=?",
                (task_id,),
            ).fetchone()
            if row is None or str(row["state"]) != TaskState.QUEUED.value:
                connection.rollback()
                return None
            cursor = connection.execute(
                "UPDATE idempotency_effects SET claimed_at=?,updated_at=? "
                "WHERE idempotency_key=? AND claimed_at IS NULL",
                (now, now, str(row["idempotency_key"])),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                return None
            connection.execute(
                "UPDATE inbox_tasks SET state='preparing',updated_at=? "
                "WHERE task_id=? AND state='queued'",
                (now, task_id),
            )
            connection.execute(
                "INSERT INTO task_attempts(attempt_id,task_id,claimed_at) VALUES(?,?,?)",
                (attempt_id, task_id, now),
            )
            connection.commit()
        return attempt_id

    def transition(self, task_id: str, current: TaskState, target: TaskState) -> None:
        ensure_transition(current, target)
        with self.connection() as connection:
            cursor = connection.execute(
                "UPDATE inbox_tasks SET state=?,updated_at=? WHERE task_id=? AND state=?",
                (target.value, utc_now(), task_id, current.value),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("task transition compare-and-set failed")

    def mark_invoked(self, task_id: str) -> None:
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE task_attempts SET invoked_at=? WHERE task_id=? AND invoked_at IS NULL",
                (utc_now(), task_id),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise StateConflictError("plugin invocation was already recorded")
            connection.commit()

    def request_cleanup(self, task_id: str) -> None:
        with self.connection() as connection:
            connection.execute(
                "UPDATE task_attempts SET cleanup_requested_at=COALESCE(cleanup_requested_at,?) "
                "WHERE task_id=?",
                (utc_now(), task_id),
            )

    def complete_cleanup(self, task_id: str, error: str | None = None) -> None:
        with self.connection() as connection:
            connection.execute(
                """UPDATE task_attempts SET cleanup_attempts=cleanup_attempts+1,
                cleanup_completed_at=CASE WHEN ? IS NULL THEN ? ELSE cleanup_completed_at END,
                last_cleanup_error=? WHERE task_id=?""",
                (error, utc_now(), error, task_id),
            )

    def finish_with_result(
        self,
        task_id: str,
        current: TaskState,
        target: TaskState,
        payload: dict[str, Any],
    ) -> None:
        ensure_transition(current, target)
        result_id = str(payload["result_id"])
        encoded = canonical_json(payload).decode("utf-8")
        now = utc_now()
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE inbox_tasks SET state=?,updated_at=? WHERE task_id=? AND state=?",
                (target.value, now, task_id, current.value),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise StateConflictError("terminal task transition compare-and-set failed")
            row = connection.execute(
                "SELECT idempotency_key FROM inbox_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            assert row is not None
            result_key = str(uuid4())
            connection.execute(
                "INSERT INTO outbox_results(result_id,task_id,idempotency_key,payload,"
                "payload_hash,state,next_attempt_at) VALUES(?,?,?,?,?,'pending',?)",
                (result_id, task_id, result_key, encoded, digest(payload), now),
            )
            connection.execute(
                "UPDATE idempotency_effects SET terminal_state=?,result_id=?,updated_at=? "
                "WHERE idempotency_key=?",
                (target.value, result_id, now, str(row["idempotency_key"])),
            )
            connection.execute(
                "UPDATE task_attempts SET finished_at=? WHERE task_id=?", (now, task_id)
            )
            connection.commit()

    def queue_progress(self, task_id: str, payload: dict[str, Any]) -> None:
        encoded = canonical_json(payload).decode("utf-8")
        with self.connection() as connection:
            connection.execute(
                """INSERT INTO outbox_progress(event_id,task_id,sequence,payload,payload_hash,
                state,next_attempt_at) VALUES(?,?,?,?,?,'pending',?)""",
                (
                    str(payload["event_id"]),
                    task_id,
                    int(payload["sequence"]),
                    encoded,
                    digest(payload),
                    utc_now(),
                ),
            )

    def pending_outbox(self, table: str) -> list[dict[str, Any]]:
        if table not in {"outbox_progress", "outbox_results", "pending_uploads"}:
            raise ValueError("unknown outbox")
        with self.connection() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    f"SELECT * FROM {table} WHERE state IN ('pending','in_flight') "  # noqa: S608
                    "ORDER BY next_attempt_at"
                )
            ]

    def confirm_outbox(self, table: str, key_name: str, key: str) -> None:
        allowed = {
            "outbox_progress": "event_id",
            "outbox_results": "result_id",
            "pending_uploads": "upload_id",
        }
        if allowed.get(table) != key_name:
            raise ValueError("invalid outbox key")
        with self.connection() as connection:
            connection.execute(
                f"UPDATE {table} SET state='confirmed',confirmed_at=? WHERE {key_name}=?",  # noqa: S608
                (utc_now(), key),
            )

    def recover_interrupted(self) -> int:
        now = utc_now()
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT task_id,state FROM inbox_tasks WHERE state IN "
                "('preparing','running','cancel_requested','cleaning_up')"
            ).fetchall()
            for row in rows:
                connection.execute(
                    "UPDATE inbox_tasks SET state='interrupted',reason=?,updated_at=? "
                    "WHERE task_id=?",
                    (
                        json.dumps({"code": "blocked", "detail": "process_restart"}),
                        now,
                        str(row["task_id"]),
                    ),
                )
                connection.execute(
                    "UPDATE task_attempts SET "
                    "cleanup_requested_at=COALESCE(cleanup_requested_at,?),"
                    "finished_at=COALESCE(finished_at,?) WHERE task_id=?",
                    (now, now, str(row["task_id"])),
                )
            connection.commit()
            return len(rows)

    def rows(self, table: str) -> list[dict[str, Any]]:
        queries = {
            "schema_migrations": "SELECT * FROM schema_migrations",
            "agent_identity": "SELECT * FROM agent_identity",
            "runtime_state": "SELECT * FROM runtime_state",
            "capability_manifests": "SELECT * FROM capability_manifests",
            "inbox_tasks": "SELECT * FROM inbox_tasks",
            "idempotency_effects": "SELECT * FROM idempotency_effects",
            "task_attempts": "SELECT * FROM task_attempts",
            "outbox_progress": "SELECT * FROM outbox_progress",
            "outbox_results": "SELECT * FROM outbox_results",
            "pending_uploads": "SELECT * FROM pending_uploads",
            "sync_state": "SELECT * FROM sync_state",
            "quarantine": "SELECT * FROM quarantine",
        }
        if table not in queries:
            raise ValueError("unknown table")
        with self.connection() as connection:
            return [dict(row) for row in connection.execute(queries[table])]

    def _quarantine_in_transaction(
        self,
        connection: sqlite3.Connection,
        source_table: str,
        source_key: str,
        reason: str,
        raw_payload: str | None,
    ) -> None:
        connection.execute(
            """INSERT INTO quarantine(quarantine_id,source_table,source_key,reason,raw_payload,
            observed_hash,quarantined_at) VALUES(?,?,?,?,?,?,?)""",
            (
                str(uuid4()),
                source_table,
                source_key,
                reason,
                raw_payload,
                hashlib.sha256((raw_payload or "").encode()).hexdigest(),
                utc_now(),
            ),
        )
