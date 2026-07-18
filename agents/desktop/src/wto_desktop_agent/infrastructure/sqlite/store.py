from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from wto_desktop_agent.domain.artifact_paths import (
    ARTIFACT_PRUNE_QUARANTINE_PATH_LENGTH,
    ARTIFACT_PRUNE_QUARANTINE_PATH_PREFIX,
    ARTIFACT_PRUNE_QUARANTINE_PREFIX_LENGTH,
    ARTIFACT_PRUNE_QUARANTINE_TOKEN_LENGTH,
    ARTIFACT_PRUNE_QUARANTINE_TOKEN_OFFSET,
    is_artifact_prune_quarantine_path,
)
from wto_desktop_agent.domain.errors import DuplicateConflictError, StateConflictError
from wto_desktop_agent.domain.models import LocalTaskEnvelope
from wto_desktop_agent.domain.states import TaskState, ensure_transition
from wto_desktop_agent.infrastructure.contracts import canonical_json

APPLICATION_ID = 0x57544F05
SCHEMA_VERSION = 2


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
        with self._initialization_lock():
            existed = self.path.exists()
            migration_backup: Path | None = None
            if existed:
                application_id, version = self._inspect_database(
                    self.path,
                    allowed_versions={0, 1, SCHEMA_VERSION},
                    allow_unclaimed=True,
                )
                if version in {1, SCHEMA_VERSION} and application_id != APPLICATION_ID:
                    raise RuntimeError(
                        f"SQLite schema v{version} is not claimed by this application"
                    )
                if version == 1:
                    migration_backup = self._ensure_pre_migration_backup()
                elif version not in {0, SCHEMA_VERSION}:
                    raise RuntimeError(f"unsupported SQLite schema version: {version}")
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
            except Exception as error:
                if migration_backup is not None:
                    try:
                        self._restore_pre_migration_backup(
                            migration_backup,
                            primary_error=error,
                        )
                    except BaseException as restore_error:
                        error.add_note(
                            "the immutable SQLite pre-migration backup could not be restored: "
                            f"{type(restore_error).__name__}"
                        )
                raise

    @contextmanager
    def _initialization_lock(self) -> Iterator[None]:
        lock_path = self.path.with_suffix(self.path.suffix + ".initialize.lock")
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(lock_path, flags, 0o600)
        locked = False
        primary_error: BaseException | None = None
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise PermissionError("SQLite initialization lock is not a private regular file")
            if os.name == "nt":
                msvcrt_module = cast(Any, __import__("msvcrt"))

                if metadata.st_size < 1:
                    os.write(descriptor, b"\x00")
                    os.fsync(descriptor)
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt_module.locking(descriptor, msvcrt_module.LK_LOCK, 1)
            else:
                fcntl_module = cast(Any, __import__("fcntl"))
                fcntl_module.flock(descriptor, fcntl_module.LOCK_EX)
            locked = True
            yield
        except BaseException as error:
            primary_error = error
            raise
        finally:
            cleanup_error: BaseException | None = None
            if locked:
                try:
                    if os.name == "nt":
                        msvcrt_module = cast(Any, __import__("msvcrt"))

                        os.lseek(descriptor, 0, os.SEEK_SET)
                        msvcrt_module.locking(descriptor, msvcrt_module.LK_UNLCK, 1)
                    else:
                        fcntl_module = cast(Any, __import__("fcntl"))
                        fcntl_module.flock(descriptor, fcntl_module.LOCK_UN)
                except BaseException as unlock_error:
                    if primary_error is None:
                        cleanup_error = unlock_error
                    else:
                        primary_error.add_note(
                            "SQLite initialization lock release also failed: "
                            f"{type(unlock_error).__name__}"
                        )
                finally:
                    try:
                        os.close(descriptor)
                    except BaseException as close_error:
                        if primary_error is None:
                            cleanup_error = cleanup_error or close_error
                            if cleanup_error is not close_error:
                                cleanup_error.add_note(
                                    "SQLite initialization lock close also failed: "
                                    f"{type(close_error).__name__}"
                                )
                        else:
                            primary_error.add_note(
                                "SQLite initialization lock close also failed: "
                                f"{type(close_error).__name__}"
                            )
            else:
                try:
                    os.close(descriptor)
                except BaseException as close_error:
                    if primary_error is None:
                        cleanup_error = close_error
                    else:
                        primary_error.add_note(
                            "SQLite initialization lock close also failed: "
                            f"{type(close_error).__name__}"
                        )
            if primary_error is None and cleanup_error is not None:
                raise cleanup_error

    @staticmethod
    def _validate_regular_database(path: Path, *, purpose: str) -> os.stat_result:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            raise FileNotFoundError(f"{purpose} is unavailable") from None
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{purpose} must be a regular file without symlink traversal")
        if metadata.st_nlink != 1:
            raise ValueError(f"{purpose} must have exactly one filesystem link")
        return metadata

    @classmethod
    def _inspect_database(
        cls,
        path: Path,
        *,
        allowed_versions: set[int],
        allow_unclaimed: bool = False,
        immutable_snapshot: bool = False,
    ) -> tuple[int, int]:
        before = cls._readonly_snapshot(path) if immutable_snapshot else None
        if (
            immutable_snapshot
            and before is not None
            and any(identity is not None for _name, identity in before[1:])
        ):
            raise RuntimeError(
                "SQLite WAL/SHM sidecars indicate a live or transient snapshot; "
                "read-only inspection is inconclusive"
            )
        cls._validate_regular_database(path, purpose="SQLite database")
        absolute = path.absolute()
        immutable_query = "&immutable=1" if immutable_snapshot else ""
        connection = sqlite3.connect(
            f"{absolute.as_uri()}?mode=ro{immutable_query}&cache=private",
            uri=True,
            timeout=1.0,
            isolation_level=None,
        )
        try:
            connection.execute("PRAGMA query_only=ON")
            if int(connection.execute("PRAGMA query_only").fetchone()[0]) != 1:
                raise RuntimeError("SQLite query_only could not be enabled")
            if str(connection.execute("PRAGMA quick_check(1)").fetchone()[0]) != "ok":
                raise RuntimeError("SQLite quick_check failed")
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            if application_id != APPLICATION_ID and not (allow_unclaimed and application_id == 0):
                raise RuntimeError("SQLite database belongs to another application")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in allowed_versions:
                raise RuntimeError(f"unsupported SQLite schema version: {version}")
            return application_id, version
        finally:
            connection.close()
            after = cls._readonly_snapshot(path) if immutable_snapshot else None
            if immutable_snapshot and before != after:
                raise RuntimeError(
                    "SQLite changed during read-only inspection; snapshot is inconclusive"
                )

    @staticmethod
    def _readonly_snapshot(path: Path) -> tuple[tuple[str, tuple[int, ...] | None], ...]:
        result: list[tuple[str, tuple[int, ...] | None]] = []
        for candidate in (
            path,
            path.with_name(path.name + "-wal"),
            path.with_name(path.name + "-shm"),
        ):
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                identity = None
            else:
                identity = (
                    int(metadata.st_dev),
                    int(metadata.st_ino),
                    int(metadata.st_uid),
                    stat.S_IFMT(metadata.st_mode),
                    stat.S_IMODE(metadata.st_mode),
                    int(metadata.st_nlink),
                    int(metadata.st_size),
                    int(metadata.st_mtime_ns),
                    int(metadata.st_ctime_ns),
                )
            result.append((candidate.name, identity))
        return tuple(result)

    def inspect_health(self) -> int:
        """Validate an existing current database without creating or migrating it."""

        _, version = self._inspect_database(
            self.path,
            allowed_versions={SCHEMA_VERSION},
            immutable_snapshot=True,
        )
        return version

    @classmethod
    def _logical_fingerprint(cls, path: Path) -> str:
        cls._inspect_database(path, allowed_versions={1})
        connection = sqlite3.connect(f"{path.absolute().as_uri()}?mode=ro", uri=True)
        result = hashlib.sha256()
        try:
            for statement in connection.iterdump():
                result.update(statement.encode("utf-8"))
                result.update(b"\n")
        finally:
            connection.close()
        return result.hexdigest()

    @staticmethod
    def _fsync_file(path: Path) -> None:
        descriptor = os.open(path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _backup_candidate(
        self,
        destination: Path,
        *,
        allowed_versions: set[int],
        source_path: Path | None = None,
    ) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        candidate = destination.with_name(f".{destination.name}.candidate-{uuid4().hex}")
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(candidate, flags, 0o600)
        os.close(descriptor)
        try:
            source = self._connect(source_path or self.path)
            target: sqlite3.Connection | None = None
            operation_error: BaseException | None = None
            try:
                target = self._connect(candidate)
                source.backup(target)
                result = str(target.execute("PRAGMA quick_check").fetchone()[0])
                if result != "ok":
                    raise RuntimeError("SQLite backup verification failed")
            except BaseException as error:
                operation_error = error
                raise
            finally:
                close_error: BaseException | None = None
                for connection in (target, source):
                    if connection is None:
                        continue
                    try:
                        connection.close()
                    except BaseException as error:
                        if operation_error is not None:
                            operation_error.add_note(
                                "SQLite backup connection close also failed: "
                                f"{type(error).__name__}"
                            )
                        elif close_error is None:
                            close_error = error
                        else:
                            close_error.add_note(
                                "SQLite backup connection close also failed: "
                                f"{type(error).__name__}"
                            )
                if operation_error is None and close_error is not None:
                    raise close_error
            self._fsync_file(candidate)
            self._inspect_database(candidate, allowed_versions=allowed_versions)
            return candidate
        except BaseException:
            candidate.unlink(missing_ok=True)
            raise

    def _ensure_pre_migration_backup(self) -> Path:
        backup = self.path.with_suffix(self.path.suffix + ".pre-migrate.bak")
        candidate = self._backup_candidate(backup, allowed_versions={1})
        try:
            if backup.exists() or backup.is_symlink():
                self._validate_regular_database(backup, purpose="SQLite pre-migration backup")
                self._inspect_database(backup, allowed_versions={1})
                if self._logical_fingerprint(backup) != self._logical_fingerprint(candidate):
                    raise RuntimeError(
                        "SQLite pre-migration backup does not match the live schema v1 database"
                    )
                return backup
            try:
                os.link(candidate, backup, follow_symlinks=False)
            except FileExistsError as error:
                self._validate_regular_database(backup, purpose="SQLite pre-migration backup")
                self._inspect_database(backup, allowed_versions={1})
                if self._logical_fingerprint(backup) != self._logical_fingerprint(candidate):
                    raise RuntimeError(
                        "SQLite pre-migration backup publication conflict"
                    ) from error
                return backup
            self._fsync_file(backup)
            candidate.unlink()
            self._fsync_directory(backup.parent)
            self._validate_regular_database(backup, purpose="SQLite pre-migration backup")
            return backup
        finally:
            candidate.unlink(missing_ok=True)

    def _restore_pre_migration_backup(
        self,
        backup: Path,
        *,
        primary_error: BaseException,
    ) -> None:
        self._inspect_database(backup, allowed_versions={1})
        failed = self.path.with_name(f"{self.path.name}.migration-failed-{uuid4()}")
        if self.path.exists():
            try:
                shutil.copy2(self.path, failed)
            except BaseException as snapshot_error:
                primary_error.add_note(
                    "the failed SQLite migration snapshot could not be retained: "
                    f"{type(snapshot_error).__name__}"
                )
        restored = self._backup_candidate(
            self.path,
            allowed_versions={1},
            source_path=backup,
        )
        try:
            self._remove_sqlite_sidecars(self.path)
            os.replace(restored, self.path)
            self._fsync_directory(self.path.parent)
        finally:
            restored.unlink(missing_ok=True)

    @staticmethod
    def _remove_sqlite_sidecars(path: Path) -> None:
        for suffix in ("-wal", "-shm"):
            Path(f"{path}{suffix}").unlink(missing_ok=True)

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
        source = self.path.absolute()
        destination = destination.absolute()
        pre_migration_backup = self.path.with_suffix(
            self.path.suffix + ".pre-migrate.bak"
        ).absolute()
        if source == destination:
            raise ValueError("SQLite backup and destination must differ")
        if destination.resolve(strict=False) == pre_migration_backup.resolve(strict=False):
            raise ValueError("SQLite pre-migration backup is a reserved immutable destination")
        self._validate_regular_database(source, purpose="SQLite source database")
        if destination.exists() or destination.is_symlink():
            self._validate_regular_database(destination, purpose="SQLite backup destination")
            if os.path.samefile(source, destination):
                raise ValueError("SQLite backup and destination must differ")
            if pre_migration_backup.exists() and os.path.samefile(
                pre_migration_backup, destination
            ):
                raise ValueError("SQLite pre-migration backup is a reserved immutable destination")
        candidate = self._backup_candidate(destination, allowed_versions={1, SCHEMA_VERSION})
        previous: Path | None = None
        published = False
        preserve_previous = False
        try:
            if destination.exists():
                previous = destination.with_name(f".{destination.name}.previous-{uuid4().hex}")
                os.link(destination, previous, follow_symlinks=False)
            try:
                os.replace(candidate, destination)
                published = True
                self._fsync_file(destination)
                self._fsync_directory(destination.parent)
            except BaseException as error:
                if previous is not None:
                    try:
                        os.replace(previous, destination)
                        self._fsync_file(destination)
                        self._fsync_directory(destination.parent)
                        published = False
                    except BaseException as restore_error:
                        preserve_previous = True
                        error.add_note(
                            "the previous SQLite backup destination could not be restored: "
                            f"{type(restore_error).__name__}"
                        )
                raise
        finally:
            candidate.unlink(missing_ok=True)
            if previous is not None and previous.exists() and not preserve_previous:
                try:
                    previous.unlink()
                    if published:
                        self._fsync_directory(destination.parent)
                except OSError:
                    # Publication is already durable. Preserve the prior inode
                    # under its private name rather than turning success into
                    # an ambiguous backup result or deleting data online.
                    pass

    @staticmethod
    def verify_backup(path: Path) -> int:
        _, version = SQLiteStore._inspect_database(
            path,
            allowed_versions={1, SCHEMA_VERSION},
        )
        return version

    def restore_verified_backup(self, source: Path) -> int:
        source = source.absolute()
        self._validate_regular_database(source, purpose="SQLite restore source")
        if self.path.exists() and os.path.samefile(source, self.path):
            raise ValueError("SQLite backup and destination must differ")
        version = self.verify_backup(source)
        rollback = self.path.with_suffix(self.path.suffix + ".pre-restore.bak")
        existed = self.path.exists()
        if existed:
            self.create_verified_backup(rollback)
        try:
            self._remove_sqlite_sidecars(self.path)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, self.path)
            if self.verify_backup(self.path) != version:
                raise RuntimeError("restored SQLite schema differs from verified backup")
        except Exception:
            self._remove_sqlite_sidecars(self.path)
            if existed and rollback.exists():
                shutil.copy2(rollback, self.path)
            raise
        return version

    def begin_windows_operation(
        self,
        *,
        operation_id: str,
        idempotency_key: str,
        action: str,
        interface_guid: str,
        target_profile: str | None,
        previous_profile: str | None,
    ) -> dict[str, Any]:
        intent_hash = digest(
            {
                "action": action,
                "interface_guid": interface_guid,
                "target_profile": target_profile,
            }
        )
        now = utc_now()
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM windows_network_operations WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if existing:
                if str(existing["intent_hash"]) != intent_hash:
                    connection.rollback()
                    raise DuplicateConflictError(
                        "Windows network idempotency key was reused for another intent"
                    )
                connection.commit()
                return dict(existing)
            connection.execute(
                """INSERT INTO windows_network_operations(
                operation_id,idempotency_key,intent_hash,action,interface_guid,target_profile,
                previous_profile,state,started_at,updated_at)
                VALUES(?,?,?,?,?,?,?,'intent_recorded',?,?)""",
                (
                    operation_id,
                    idempotency_key,
                    intent_hash,
                    action,
                    interface_guid,
                    target_profile,
                    previous_profile,
                    now,
                    now,
                ),
            )
            connection.commit()
        return self.windows_operation(idempotency_key)

    def windows_operation(self, idempotency_key: str) -> dict[str, Any]:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM windows_network_operations WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if row is None:
                raise KeyError("Windows network operation is unavailable")
            return dict(row)

    def transition_windows_operation(
        self,
        idempotency_key: str,
        *,
        current: set[str],
        target: str,
        reconciliation_result: str | None = None,
        last_error: str | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        completed_at = (
            now if target in {"completed", "failed", "cancelled", "rolled_back"} else None
        )
        allowed_states = {
            "intent_recorded",
            "running",
            "completed",
            "failed",
            "cancelled",
            "reconciling",
            "rolled_back",
        }
        if not current or not current <= allowed_states:
            raise ValueError("invalid Windows network current state set")
        padded_states = [*sorted(current), *([""] * (7 - len(current)))]
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """UPDATE windows_network_operations SET
                state=?,updated_at=?,completed_at=COALESCE(?,completed_at),
                reconciliation_result=COALESCE(?,reconciliation_result),
                last_error=COALESCE(?,last_error)
                WHERE idempotency_key=? AND state IN (?,?,?,?,?,?,?)""",
                [
                    target,
                    now,
                    completed_at,
                    reconciliation_result,
                    last_error,
                    idempotency_key,
                    *padded_states,
                ],
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise StateConflictError("Windows network operation transition conflict")
            connection.commit()
        return self.windows_operation(idempotency_key)

    def incomplete_windows_operations(self) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                """SELECT * FROM windows_network_operations
                WHERE state IN ('intent_recorded','running','reconciling')
                ORDER BY started_at"""
            ).fetchall()
            return [dict(row) for row in rows]

    def purge_identity(self) -> None:
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM capability_manifests")
            connection.execute("DELETE FROM runtime_state")
            connection.execute("DELETE FROM agent_identity")
            connection.commit()

    def identity(self) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM agent_identity WHERE singleton=1").fetchone()
            return dict(row) if row else None

    def identity_immutable(self) -> dict[str, Any] | None:
        """Read restart-stable identity without creating SQLite WAL/SHM state."""

        uri = f"{self.path.absolute().as_uri()}?mode=ro&immutable=1"
        connection = sqlite3.connect(uri, uri=True)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute("SELECT * FROM agent_identity WHERE singleton=1").fetchone()
            return dict(row) if row else None
        finally:
            connection.close()

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

    def queue_artifact(
        self,
        *,
        task_id: str,
        relative_path: str,
        media_type: str,
        payload: dict[str, Any],
    ) -> None:
        self.ensure_artifact_queued(
            task_id=task_id,
            relative_path=relative_path,
            media_type=media_type,
            payload=payload,
        )

    def ensure_artifact_queued(
        self,
        *,
        task_id: str,
        relative_path: str,
        media_type: str,
        payload: dict[str, Any],
    ) -> bool:
        relative = Path(relative_path)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise ValueError("artifact path must be a safe relative path")
        encoded = canonical_json(payload).decode("utf-8")
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT task_id,relative_path,media_type,size_bytes,sha256,payload "
                "FROM pending_uploads WHERE artifact_id=?",
                (str(payload["artifact_id"]),),
            ).fetchone()
            if existing is not None:
                expected = (
                    task_id,
                    relative.as_posix(),
                    media_type,
                    int(payload["size_bytes"]),
                    str(payload["sha256"]),
                    encoded,
                )
                observed = (
                    str(existing["task_id"]),
                    str(existing["relative_path"]),
                    str(existing["media_type"]),
                    int(existing["size_bytes"]),
                    str(existing["sha256"]),
                    str(existing["payload"]),
                )
                if observed != expected:
                    connection.rollback()
                    raise RuntimeError("artifact idempotency conflict")
                connection.commit()
                return False
            connection.execute(
                """INSERT INTO pending_uploads(
                upload_id,artifact_id,task_id,relative_path,media_type,size_bytes,sha256,
                payload,payload_hash,state,next_attempt_at
                ) VALUES(?,?,?,?,?,?,?,?,?,'pending',?)""",
                (
                    str(uuid4()),
                    str(payload["artifact_id"]),
                    task_id,
                    relative.as_posix(),
                    media_type,
                    int(payload["size_bytes"]),
                    str(payload["sha256"]),
                    encoded,
                    digest(payload),
                    utc_now(),
                ),
            )
            connection.commit()
            return True

    def artifact_upload(self, artifact_id: str) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM pending_uploads WHERE artifact_id=?",
                (artifact_id,),
            ).fetchone()
            return None if row is None else dict(row)

    def artifact_uploads(
        self,
        *,
        states: frozenset[str] = frozenset({"pending", "in_flight", "confirmed", "failed"}),
        limit: int = 10_000,
    ) -> list[dict[str, Any]]:
        if limit <= 0 or limit > 10_000:
            raise ValueError("artifact upload query limit must be between 1 and 10000")
        allowed_states = frozenset({"pending", "in_flight", "confirmed", "failed"})
        if not states or not states <= allowed_states:
            raise ValueError("artifact upload query states are invalid")
        ordered_states = tuple(sorted(states))
        placeholders = ",".join("?" for _ in ordered_states)
        query = (
            f"SELECT * FROM pending_uploads WHERE state IN ({placeholders}) "  # noqa: S608
            "ORDER BY upload_id LIMIT ?"
        )
        parameters: tuple[object, ...] = (*ordered_states, limit)
        with self.connection() as connection:
            return [dict(row) for row in connection.execute(query, parameters)]

    def artifact_upload_count(self, *, states: frozenset[str]) -> int:
        allowed_states = frozenset({"pending", "in_flight", "confirmed", "failed"})
        if not states or not states <= allowed_states:
            raise ValueError("artifact upload count states are invalid")
        ordered_states = tuple(sorted(states))
        placeholders = ",".join("?" for _ in ordered_states)
        with self.connection() as connection:
            row = connection.execute(
                f"SELECT COUNT(*) FROM pending_uploads WHERE state IN ({placeholders})",  # noqa: S608
                ordered_states,
            ).fetchone()
            assert row is not None
            return int(row[0])

    def confirmed_artifacts_for_pruning(
        self,
        *,
        confirmed_before: str | None,
        retain_count: int | None,
        retain_bytes: int | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        if limit <= 0 or limit > 10_000:
            raise ValueError("artifact pruning query limit must be between 1 and 10000")
        if retain_count is not None and retain_count < 0:
            raise ValueError("artifact retain count cannot be negative")
        if retain_bytes is not None and retain_bytes < 0:
            raise ValueError("artifact retain bytes cannot be negative")
        with self.connection() as connection:
            rows = connection.execute(
                """WITH ranked AS (
                    SELECT pending_uploads.*,
                    ROW_NUMBER() OVER (
                        ORDER BY COALESCE(confirmed_at,next_attempt_at) DESC,upload_id DESC
                    ) AS keep_position,
                    SUM(size_bytes) OVER (
                        ORDER BY COALESCE(confirmed_at,next_attempt_at) DESC,upload_id DESC
                        ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
                    ) AS keep_bytes
                    FROM pending_uploads
                    WHERE state='confirmed' AND NOT (
                        typeof(relative_path)='text'
                        AND length(CAST(relative_path AS BLOB))=?
                        AND instr(CAST(relative_path AS BLOB),X'00')=0
                        AND substr(CAST(relative_path AS BLOB),1,?) = CAST(? AS BLOB)
                        AND CAST(
                            substr(CAST(relative_path AS BLOB),?,?) AS TEXT
                        ) NOT GLOB '*[^0-9a-f]*'
                    )
                )
                SELECT * FROM ranked
                WHERE ((? IS NOT NULL AND COALESCE(confirmed_at,next_attempt_at) < ?)
                    OR (? IS NOT NULL AND keep_position > ?)
                    OR (? IS NOT NULL AND keep_bytes > ?))
                ORDER BY COALESCE(confirmed_at,next_attempt_at),upload_id LIMIT ?""",
                (
                    ARTIFACT_PRUNE_QUARANTINE_PATH_LENGTH,
                    ARTIFACT_PRUNE_QUARANTINE_PREFIX_LENGTH,
                    ARTIFACT_PRUNE_QUARANTINE_PATH_PREFIX,
                    ARTIFACT_PRUNE_QUARANTINE_TOKEN_OFFSET,
                    ARTIFACT_PRUNE_QUARANTINE_TOKEN_LENGTH,
                    confirmed_before,
                    confirmed_before,
                    retain_count,
                    retain_count,
                    retain_bytes,
                    retain_bytes,
                    limit,
                ),
            ).fetchall()
            return [dict(row) for row in rows]

    def delete_confirmed_artifact(self, upload_id: str) -> bool:
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "DELETE FROM pending_uploads WHERE upload_id=? AND state='confirmed'",
                (upload_id,),
            )
            connection.commit()
            return cursor.rowcount == 1

    def update_confirmed_artifact_path(
        self,
        upload_id: str,
        *,
        expected_relative_path: str,
        quarantine_relative_path: str,
    ) -> bool:
        for value in (expected_relative_path, quarantine_relative_path):
            relative = Path(value)
            if (
                relative.is_absolute()
                or len(relative.parts) != 2
                or relative.parts[0] != "outbox"
                or relative.parts[1] in {"", ".", ".."}
                or relative.as_posix() != value
            ):
                raise ValueError("artifact quarantine path must be a safe outbox path")
        if not is_artifact_prune_quarantine_path(quarantine_relative_path):
            raise ValueError("artifact quarantine path has an invalid prefix")
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE pending_uploads SET relative_path=? "
                "WHERE upload_id=? AND state='confirmed' AND relative_path=?",
                (quarantine_relative_path, upload_id, expected_relative_path),
            )
            connection.commit()
            return cursor.rowcount == 1

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
            "windows_network_operations": "SELECT * FROM windows_network_operations",
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
