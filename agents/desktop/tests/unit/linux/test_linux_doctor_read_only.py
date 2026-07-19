from __future__ import annotations

import json
import os
import sqlite3
import stat
import threading
import time
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Literal, cast

import pytest

from wto_desktop_agent.application.doctor import DoctorService
from wto_desktop_agent.config import AgentSettings
from wto_desktop_agent.domain.models import DoctorCheck
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.platforms.linux import secret_store as secret_store_module
from wto_desktop_agent.platforms.linux.doctor import (
    LinuxReadOnlyDoctor,
    _capture_marker_check,
)
from wto_desktop_agent.platforms.linux.secret_store import (
    LinuxEncryptedFileSecretStore,
    inspect_encrypted_file_secret_store_read_only,
    inspect_secret_service_read_only,
)

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX read-only identities")


def _snapshot(root: Path) -> dict[str, tuple[int, int, int, int, bytes | None]]:
    if not root.exists():
        return {}
    result: dict[str, tuple[int, int, int, int, bytes | None]] = {}
    for path in (root, *sorted(root.rglob("*"))):
        metadata = path.lstat()
        content = path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None
        result[str(path.relative_to(root))] = (
            int(metadata.st_ino),
            stat.S_IMODE(metadata.st_mode),
            int(metadata.st_size),
            int(metadata.st_mtime_ns),
            content,
        )
    return result


def _settings(
    state: Path,
    artifacts: Path,
    *,
    linux_secret_backend: Literal[
        "auto", "secret_service", "encrypted_file"
    ] = "secret_service",  # noqa: S107
) -> AgentSettings:
    return AgentSettings(
        environment="test",
        server_url="http://testserver",
        state_dir=state,
        artifacts_dir=artifacts,
        node_role="capture_node",
        linux_secret_backend=linux_secret_backend,
    )


def test_doctor_does_not_create_missing_state_or_artifacts(tmp_path: Path) -> None:
    state = tmp_path / "missing-state"
    artifacts = tmp_path / "missing-artifacts"
    checks = LinuxReadOnlyDoctor(_settings(state, artifacts)).run()
    assert not state.exists()
    assert not artifacts.exists()
    assert {check.name: check.status for check in checks}["artifact_state"] == "DEGRADED"


def test_repeated_doctor_preserves_bytes_inodes_modes_and_mtimes(tmp_path: Path) -> None:
    state = tmp_path / "state"
    artifacts = tmp_path / "artifacts"
    for directory in (
        state,
        state / "secrets",
        state / "capture-journal",
        state / "capture-markers",
        artifacts,
        artifacts / "outbox",
        artifacts / "outbox" / "intents",
    ):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
    intent = artifacts / "outbox" / "intents" / f"intent-{'a' * 48}.json"
    intent.write_text("{}", encoding="utf-8")
    os.chmod(intent, 0o600)
    journal = state / "capture-journal" / ("20000000-0000-4000-8000-000000000091.json")
    journal.write_text("{}", encoding="utf-8")
    os.chmod(journal, 0o600)

    before_state = _snapshot(state)
    before_artifacts = _snapshot(artifacts)
    first = LinuxReadOnlyDoctor(_settings(state, artifacts)).run()
    second = LinuxReadOnlyDoctor(_settings(state, artifacts)).run()

    assert _snapshot(state) == before_state
    assert _snapshot(artifacts) == before_artifacts
    assert [check.model_dump() for check in first] == [check.model_dump() for check in second]
    by_name = {check.name: check for check in first}
    assert by_name["capture_interface_recovery"].status == "BLOCKED"
    assert by_name["artifact_state"].status == "DEGRADED"


@pytest.mark.parametrize(
    ("verification_status", "expected_detail"),
    [
        ("partial", "verification_pending=1"),
        ("unavailable", "unavailable=1"),
        ("mismatch", "rollback_mismatch=1"),
    ],
)
def test_doctor_reports_durable_rollback_verification_state_read_only(
    tmp_path: Path,
    verification_status: str,
    expected_detail: str,
) -> None:
    state = tmp_path / "state"
    marker_root = state / "capture-markers"
    marker_root.mkdir(parents=True, mode=0o700)
    os.chmod(state, 0o700)
    os.chmod(marker_root, 0o700)
    marker = marker_root / "30000000-0000-4000-8000-000000000091.jsonl"
    marker.write_text(
        json.dumps(
            {
                "state": "ROLLBACK_VERIFICATION_PENDING",
                "details": {"rollback": {"verification_status": verification_status}},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(marker, 0o600)
    before = _snapshot(state)

    check = _capture_marker_check(state)

    assert check.status == "BLOCKED"
    assert expected_detail in check.detail
    assert _snapshot(state) == before


def test_sqlite_health_inspection_does_not_create_or_change_sidecars(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    store = SQLiteStore(state / "agent.sqlite3")
    store.initialize()
    before = _snapshot(state)
    assert store.inspect_health() == 2
    assert store.inspect_health() == 2
    assert _snapshot(state) == before


def test_composed_doctor_reports_schema_v1_without_migration_or_backup(tmp_path: Path) -> None:
    state = tmp_path / "state"
    artifacts = tmp_path / "artifacts"
    state.mkdir(mode=0o700)
    artifacts.mkdir(mode=0o700)
    store = SQLiteStore(state / "agent.sqlite3")
    store.initialize()
    with store.connection() as connection:
        connection.execute("DROP TABLE windows_network_operations")
        connection.execute("DELETE FROM schema_migrations WHERE version=2")
        connection.execute("PRAGMA user_version=1")
    settings = _settings(state, artifacts)
    before_state = _snapshot(state)
    before_artifacts = _snapshot(artifacts)

    checks = DoctorService(
        settings,
        store,
        None,
        diagnostic_checks=LinuxReadOnlyDoctor(settings).run(),
    ).run()

    assert {check.name: check for check in checks}["sqlite"].status == "BLOCKED"
    assert _snapshot(state) == before_state
    assert _snapshot(artifacts) == before_artifacts
    assert not (state / "agent.sqlite3.pre-migrate.bak").exists()


def test_sqlite_concurrent_snapshot_change_is_inconclusive_and_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    store = SQLiteStore(state / "agent.sqlite3")
    store.initialize()
    before = _snapshot(state)
    real_snapshot = SQLiteStore._readonly_snapshot
    calls = 0

    def changing_snapshot(path: Path) -> tuple[tuple[str, tuple[int, ...] | None], ...]:
        nonlocal calls
        calls += 1
        observed = real_snapshot(path)
        if calls == 1:
            return observed
        name, identity = observed[0]
        assert identity is not None
        changed = (*identity[:-1], identity[-1] + 1)
        return ((name, changed), *observed[1:])

    monkeypatch.setattr(SQLiteStore, "_readonly_snapshot", staticmethod(changing_snapshot))

    with pytest.raises(RuntimeError, match="snapshot is inconclusive"):
        store.inspect_health()
    assert _snapshot(state) == before


def test_sqlite_live_wal_and_shm_are_inconclusive_and_unchanged(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    store = SQLiteStore(state / "agent.sqlite3")
    store.initialize()
    writer = sqlite3.connect(store.path)
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("CREATE TABLE doctor_concurrent_probe(value INTEGER NOT NULL)")
        before = _snapshot(state)
        assert (state / "agent.sqlite3-wal").is_file()
        assert (state / "agent.sqlite3-shm").is_file()

        with pytest.raises(RuntimeError, match="inspection is inconclusive"):
            store.inspect_health()

        assert _snapshot(state) == before
    finally:
        writer.rollback()
        writer.close()


def test_doctor_blocks_artifact_intermediate_symlink_without_touching_target(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    artifacts = tmp_path / "artifacts"
    outside = tmp_path / "outside"
    state.mkdir(mode=0o700)
    artifacts.mkdir(mode=0o700)
    (outside / "intents").mkdir(parents=True, mode=0o700)
    os.chmod(outside, 0o700)
    os.chmod(outside / "intents", 0o700)
    (artifacts / "outbox").symlink_to(outside, target_is_directory=True)
    before = _snapshot(tmp_path)

    checks = LinuxReadOnlyDoctor(_settings(state, artifacts)).run()

    assert {check.name: check for check in checks}["artifact_state"].status == "BLOCKED"
    assert _snapshot(tmp_path) == before


class _ReadOnlyCollection:
    def __init__(self, events: list[str], *, locked: object = False) -> None:
        self._events = events
        self._locked = locked

    def is_locked(self) -> object:
        self._events.append("is_locked")
        return self._locked

    def _forbidden(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("Secret Service mutator or secret reader was called")

    create_item = _forbidden
    search_items = _forbidden
    get_secret = _forbidden
    unlock = _forbidden
    lock = _forbidden
    prompt = _forbidden


class _ReadOnlyConnection:
    def __init__(self, events: list[str]) -> None:
        self._events = events
        self._closed = False

    def close(self) -> None:
        if self._closed:
            raise AssertionError("Secret Service connection was closed twice")
        self._closed = True
        self._events.append("close")


def _install_secret_service(
    monkeypatch: pytest.MonkeyPatch,
    collection_factory: Callable[[list[str]], object],
) -> list[str]:
    events: list[str] = []

    def dbus_init() -> object:
        events.append("dbus_init")
        return _ReadOnlyConnection(events)

    def read_alias(connection: object, alias: str) -> object:
        del connection
        events.append(f"read_alias:{alias}")
        return collection_factory(events)

    fake_module = SimpleNamespace(
        dbus_init=dbus_init,
        get_collection_by_alias=read_alias,
        create_collection=lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("CreateCollection was called")
        ),
    )
    real_import = __import__("importlib").import_module

    def import_module(name: str) -> object:
        if name == "secretstorage":
            return fake_module
        return real_import(name)

    monkeypatch.setattr(
        "wto_desktop_agent.platforms.linux.secret_store.importlib.import_module",
        import_module,
    )
    return events


@pytest.mark.parametrize("backend", ["secret_service", "auto"])
def test_doctor_dispatches_default_and_auto_only_to_secret_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: Literal["secret_service", "auto"],
) -> None:
    state = tmp_path / "state"
    artifacts = tmp_path / "artifacts"
    (state / "secrets").mkdir(parents=True, mode=0o700)
    os.chmod(state / "secrets", 0o777)  # noqa: S103 - deliberately unsafe fixture
    events = _install_secret_service(
        monkeypatch,
        lambda observed: _ReadOnlyCollection(observed),
    )
    settings = _settings(state, artifacts, linux_secret_backend=backend)
    before = _snapshot(state)

    check = {item.name: item for item in LinuxReadOnlyDoctor(settings).run()}["secret_store"]

    assert check.status == "OK"
    assert "state=available" in check.detail
    assert events == ["dbus_init", "read_alias:default", "is_locked", "close"]
    assert _snapshot(state) == before


def test_secret_service_read_only_inspector_reports_locked_without_mutators(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _install_secret_service(
        monkeypatch,
        lambda observed: _ReadOnlyCollection(observed, locked=True),
    )

    check = inspect_secret_service_read_only(
        total_timeout_seconds=0.25,
        operation_timeout_seconds=0.1,
    )

    assert check.status == "BLOCKED"
    assert check.detail == "backend=secret_service state=locked"
    assert events == ["dbus_init", "read_alias:default", "is_locked", "close"]


def test_secret_service_read_only_inspector_classifies_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def blocked_collection(events: list[str]) -> _ReadOnlyCollection:
        collection = _ReadOnlyCollection(events)

        def blocked() -> bool:
            events.append("is_locked")
            time.sleep(0.2)
            return False

        collection.is_locked = blocked  # type: ignore[method-assign]
        return collection

    events = _install_secret_service(monkeypatch, blocked_collection)

    check = inspect_secret_service_read_only(
        total_timeout_seconds=0.05,
        operation_timeout_seconds=0.02,
    )

    assert check.detail == "backend=secret_service state=timeout"
    assert events == ["dbus_init", "read_alias:default", "is_locked", "close"]
    # The timed-out daemon worker is bounded by a global gate until it exits;
    # wait so this test cannot contaminate a later inspection.
    time.sleep(0.21)


def test_secret_service_late_connection_after_timeout_is_closed_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    closed = threading.Event()

    class _LateConnection:
        def close(self) -> None:
            events.append("close")
            closed.set()

    def delayed_init() -> _LateConnection:
        events.append("dbus_init")
        time.sleep(0.05)
        return _LateConnection()

    fake_module = SimpleNamespace(
        dbus_init=delayed_init,
        get_collection_by_alias=lambda _connection, _alias: None,
    )
    monkeypatch.setattr(
        "wto_desktop_agent.platforms.linux.secret_store.importlib.import_module",
        lambda _name: fake_module,
    )

    check = inspect_secret_service_read_only(
        total_timeout_seconds=0.02,
        operation_timeout_seconds=0.01,
    )

    assert check.detail == "backend=secret_service state=timeout"
    assert closed.wait(0.25)
    assert events == ["dbus_init", "close"]


def test_secret_service_read_only_inspector_classifies_permission_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class AccessDenied(RuntimeError):
        def get_dbus_name(self) -> str:
            return "org.freedesktop.DBus.Error.AccessDenied"

    events: list[str] = []
    fake_module = SimpleNamespace(
        dbus_init=lambda: (_ for _ in ()).throw(AccessDenied()),
        get_collection_by_alias=lambda connection, alias: None,
    )
    monkeypatch.setattr(
        "wto_desktop_agent.platforms.linux.secret_store.importlib.import_module",
        lambda name: fake_module,
    )

    check = inspect_secret_service_read_only(
        total_timeout_seconds=0.25,
        operation_timeout_seconds=0.1,
    )

    assert check.detail == "backend=secret_service state=permission_denied"
    assert events == []


@pytest.mark.parametrize(
    ("loaded", "expected"),
    [
        (ModuleNotFoundError("secretstorage"), "service_unavailable"),
        (SimpleNamespace(dbus_init=lambda: object()), "not_safely_inspectable"),
    ],
)
def test_secret_service_read_only_inspector_handles_absent_or_unsafe_api(
    monkeypatch: pytest.MonkeyPatch,
    loaded: object,
    expected: str,
) -> None:
    def import_module(name: str) -> object:
        assert name == "secretstorage"
        if isinstance(loaded, BaseException):
            raise loaded
        return loaded

    monkeypatch.setattr(
        "wto_desktop_agent.platforms.linux.secret_store.importlib.import_module",
        import_module,
    )

    check = inspect_secret_service_read_only(
        total_timeout_seconds=0.25,
        operation_timeout_seconds=0.1,
    )

    assert check.detail == f"backend=secret_service state={expected}"


def test_secret_service_read_only_inspector_classifies_missing_daemon(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ServiceUnknown(RuntimeError):
        def get_dbus_name(self) -> str:
            return "org.freedesktop.DBus.Error.ServiceUnknown"

    events: list[str] = []
    fake_module = SimpleNamespace(
        dbus_init=lambda: _ReadOnlyConnection(events),
        get_collection_by_alias=lambda _connection, _alias: (_ for _ in ()).throw(ServiceUnknown()),
    )
    monkeypatch.setattr(
        "wto_desktop_agent.platforms.linux.secret_store.importlib.import_module",
        lambda _name: fake_module,
    )

    check = inspect_secret_service_read_only(
        total_timeout_seconds=0.25,
        operation_timeout_seconds=0.1,
    )

    assert check.detail == "backend=secret_service state=service_unavailable"
    assert events == ["close"]


@pytest.mark.parametrize(
    ("collection", "expected"),
    [
        (None, "collection_unavailable"),
        (_ReadOnlyCollection([], locked="invalid"), "malformed_response"),
    ],
)
def test_secret_service_read_only_inspector_fails_closed_on_bad_alias_response(
    monkeypatch: pytest.MonkeyPatch,
    collection: object,
    expected: str,
) -> None:
    _install_secret_service(monkeypatch, lambda events: collection)

    check = inspect_secret_service_read_only(
        total_timeout_seconds=0.25,
        operation_timeout_seconds=0.1,
    )

    assert check.detail == f"backend=secret_service state={expected}"


def test_encrypted_file_doctor_is_descriptor_read_only_and_never_constructs_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    artifacts = tmp_path / "artifacts"
    store = LinuxEncryptedFileSecretStore(state)
    store.close()
    settings = _settings(state, artifacts, linux_secret_backend="encrypted_file")
    before = _snapshot(state)
    master_inode = int((state / "secrets" / ".master-key").stat().st_ino)
    read_inodes: list[int] = []
    real_pread = cast(
        Callable[[int, int, int], bytes] | None,
        getattr(os, "pread", None),
    )
    assert real_pread is not None

    def observed_pread(descriptor: int, size: int, offset: int) -> bytes:
        read_inodes.append(int(os.fstat(descriptor).st_ino))
        return real_pread(descriptor, size, offset)

    def forbidden_constructor(self: object, *args: object, **kwargs: object) -> None:
        del self, args, kwargs
        raise AssertionError("Doctor instantiated the production SecretStore")

    monkeypatch.setattr(LinuxEncryptedFileSecretStore, "__init__", forbidden_constructor)
    monkeypatch.setattr(
        "wto_desktop_agent.platforms.linux.secret_store._PREAD",
        observed_pread,
    )
    check = {item.name: item for item in LinuxReadOnlyDoctor(settings).run()}["secret_store"]

    assert check.status == "OK"
    assert check.detail == "backend=encrypted_file state=healthy"
    assert master_inode not in read_inodes
    assert _snapshot(state) == before


def test_encrypted_file_doctor_reports_missing_and_manual_recovery_read_only(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    artifacts = tmp_path / "artifacts"
    settings = _settings(state, artifacts, linux_secret_backend="encrypted_file")
    missing = {item.name: item for item in LinuxReadOnlyDoctor(settings).run()}["secret_store"]
    assert missing.status == "DEGRADED"
    assert missing.detail == "backend=encrypted_file state=missing"
    assert not state.exists()

    store = LinuxEncryptedFileSecretStore(state)
    store.close()
    marker = state / "secrets" / ".store-manual-recovery"
    marker.write_bytes(LinuxEncryptedFileSecretStore._poison_payload)
    os.chmod(marker, 0o600)
    before = _snapshot(state)

    blocked = {item.name: item for item in LinuxReadOnlyDoctor(settings).run()}["secret_store"]

    assert blocked.status == "BLOCKED"
    assert blocked.detail == "backend=encrypted_file state=manual_recovery"
    assert _snapshot(state) == before


def _prepare_secret_store_health_state(state: Path, scenario: str) -> None:
    store = LinuxEncryptedFileSecretStore(state)
    try:
        if scenario == "healthy":
            return
        token = "a" * 32
        current = store._read_store_state()
        mutating = store._persist_store_state(
            current,
            state=secret_store_module._StoreHealth.MUTATING,
            reason="put",
            operation_token=token,
        )
        if scenario == "poisoned":
            store._persist_store_state(
                mutating,
                state=secret_store_module._StoreHealth.POISONED,
                reason="write_failed",
                operation_token=token,
            )
        elif scenario in {"mutating_finalizing", "healthy_finalizing"}:
            store._persist_completion_guard_finalizing(mutating)
            if scenario == "healthy_finalizing":
                store._persist_store_state(
                    mutating,
                    state=secret_store_module._StoreHealth.HEALTHY,
                    reason="healthy",
                    operation_token=token,
                )
    finally:
        store.close()


@pytest.mark.parametrize(
    ("scenario", "expected_state"),
    [
        ("mutating", "mutating"),
        ("poisoned", "poisoned"),
        ("mutating_finalizing", "mutating_finalizing"),
        ("healthy_finalizing", "completion_guard_finalizing"),
    ],
)
def test_encrypted_file_read_only_doctor_reports_durable_health_states(
    tmp_path: Path,
    scenario: str,
    expected_state: str,
) -> None:
    state = tmp_path / scenario
    _prepare_secret_store_health_state(state, scenario)
    before = _snapshot(state)

    check = inspect_encrypted_file_secret_store_read_only(state)

    assert check.status == "BLOCKED"
    assert check.detail == f"backend=encrypted_file state={expected_state}"
    assert _snapshot(state) == before


def test_encrypted_file_read_only_doctor_blocks_marker_created_during_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    _prepare_secret_store_health_state(state, "healthy")
    marker = state / "secrets" / LinuxEncryptedFileSecretStore._poison_name
    real_pread = secret_store_module._PREAD
    assert real_pread is not None
    injected = False

    def create_marker_after_read(descriptor: int, size: int, offset: int) -> bytes:
        nonlocal injected
        payload = real_pread(descriptor, size, offset)
        if not injected:
            injected = True
            marker.write_bytes(LinuxEncryptedFileSecretStore._poison_payload)
            marker.chmod(0o600)
        return payload

    monkeypatch.setattr(secret_store_module, "_PREAD", create_marker_after_read)

    check = inspect_encrypted_file_secret_store_read_only(state)

    assert marker.is_file()
    assert check.status == "BLOCKED"
    assert check.detail == "backend=encrypted_file state=concurrent_change"


def test_encrypted_file_read_only_doctor_blocks_root_replacement_during_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    replacement_state = tmp_path / "replacement-state"
    _prepare_secret_store_health_state(state, "healthy")
    _prepare_secret_store_health_state(replacement_state, "healthy")
    root = state / "secrets"
    displaced = state / "displaced-secrets"
    replacement = replacement_state / "secrets"
    real_pread = secret_store_module._PREAD
    assert real_pread is not None
    injected = False

    def replace_root_after_read(descriptor: int, size: int, offset: int) -> bytes:
        nonlocal injected
        payload = real_pread(descriptor, size, offset)
        if not injected:
            injected = True
            root.rename(displaced)
            replacement.rename(root)
        return payload

    monkeypatch.setattr(secret_store_module, "_PREAD", replace_root_after_read)

    check = inspect_encrypted_file_secret_store_read_only(state)

    assert root.is_dir()
    assert displaced.is_dir()
    assert check.status == "BLOCKED"
    assert check.detail == "backend=encrypted_file state=concurrent_change"


def test_doctor_unknown_backend_fails_closed_and_test_fake_is_explicitly_injected(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    artifacts = tmp_path / "artifacts"
    settings = _settings(state, artifacts).model_copy(update={"linux_secret_backend": "unknown"})
    unknown = {item.name: item for item in LinuxReadOnlyDoctor(settings).run()}["secret_store"]
    assert unknown.status == "BLOCKED"
    assert unknown.detail == "backend=unknown state=unknown_backend"

    fake_settings = settings.model_copy(update={"linux_secret_backend": "fake"})
    doctor = LinuxReadOnlyDoctor(
        fake_settings,
        secret_backend_inspectors={
            "fake": lambda _: DoctorCheck(
                name="secret_store",
                status="OK",
                detail="backend=fake state=available",
            )
        },
    )
    fake = {item.name: item for item in doctor.run()}["secret_store"]
    assert fake.status == "OK"
    assert fake.detail == "backend=fake state=available"
