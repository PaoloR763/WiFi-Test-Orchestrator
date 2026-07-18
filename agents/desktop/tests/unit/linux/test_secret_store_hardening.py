from __future__ import annotations

import asyncio
import errno
import hashlib
import multiprocessing
import os
import queue as queue_module
import stat
import threading
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from wto_desktop_agent.config import AgentSettings, load_settings
from wto_desktop_agent.domain.errors import (
    MutationCommitIndeterminateError,
    SecureStoreUnavailableError,
)
from wto_desktop_agent.platforms.linux.adapter import (
    LinuxPlatformAdapter,
    UnavailableLinuxSecretStore,
)
from wto_desktop_agent.platforms.linux.secret_store import (
    LinuxEncryptedFileSecretStore,
    LinuxSecretServiceStore,
)
from wto_desktop_agent.platforms.linux.secure_fs import (
    SecureFilesystemUnavailableError,
)


def _blocking_process_put(
    state_dir: str,
    value: str,
    entered: Any,
    release: Any,
    results: Any,
) -> None:
    store = LinuxEncryptedFileSecretStore(Path(state_dir))
    validate = store._validate_published_secret

    def blocked(*args: object, **kwargs: object) -> None:
        entered.set()
        release.wait(5.0)
        validate(*args, **kwargs)  # type: ignore[arg-type]

    store._validate_published_secret = blocked  # type: ignore[method-assign]
    try:
        store.put("credential.active", value)
        results.put(("ok", value))
    except BaseException as error:
        results.put(("error", type(error).__name__))
    finally:
        store.close()


def _process_put(state_dir: str, value: str, results: Any) -> None:
    store = LinuxEncryptedFileSecretStore(Path(state_dir))
    try:
        store.put("credential.active", value)
        results.put(("ok", value))
    except BaseException as error:
        results.put(("error", type(error).__name__))
    finally:
        store.close()


def _process_master_key(state_dir: str, start: Any, results: Any) -> None:
    start.wait(5.0)
    store = LinuxEncryptedFileSecretStore(Path(state_dir))
    try:
        results.put(hashlib.sha256(store._master_key).hexdigest())
    finally:
        store.close()


def _blocking_process_get(
    state_dir: str,
    entered: Any,
    release: Any,
    results: Any,
) -> None:
    store = LinuxEncryptedFileSecretStore(Path(state_dir))
    read_file = store._read_file

    def blocked(name: str, maximum_bytes: int) -> bytes:
        if name.startswith("secret-"):
            entered.set()
            if not release.wait(10.0):
                raise TimeoutError("reader release barrier expired")
        return read_file(name, maximum_bytes)

    store._read_file = blocked  # type: ignore[method-assign]
    try:
        results.put(("reader", "ok", store.get("credential.active")))
    except BaseException as error:
        results.put(("reader", "error", type(error).__name__, str(error)))
    finally:
        store.close()


def _observed_process_put(
    state_dir: str,
    value: str,
    store_ready: Any,
    start_operation: Any,
    operation_started: Any,
    attempted: Any,
    acquired: Any,
    completed: Any,
    entered: Any,
    exchange_called: Any,
    results: Any,
    lock_timeout: float = 5.0,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    store: LinuxEncryptedFileSecretStore | None = None
    try:
        store = LinuxEncryptedFileSecretStore(
            Path(state_dir),
            process_lock_timeout_seconds=lock_timeout,
            process_lock_retry_seconds=0.005,
        )
        store_ready.set()
        if not start_operation.wait(10.0):
            raise TimeoutError("start_operation barrier expired")
        fcntl = module.importlib.import_module("fcntl")
        real_fcntl_flock = fcntl.flock
        real_exchange = module.rename_exchange

        def observed_flock(descriptor: int, operation: int) -> None:
            target_attempt = descriptor == store._lock_fd and operation == (
                fcntl.LOCK_EX | fcntl.LOCK_NB
            )
            if target_attempt and not attempted.is_set():
                attempted.set()
            real_fcntl_flock(descriptor, operation)
            if target_attempt and not acquired.is_set():
                acquired.set()

        def observed_exchange(*args: object, **kwargs: object) -> None:
            exchange_called.set()
            real_exchange(*args, **kwargs)  # type: ignore[arg-type]

        put_locked = store._put_locked

        def observed_put(key: str, requested: str, name: str) -> None:
            entered.set()
            put_locked(key, requested, name)

        store._put_locked = observed_put  # type: ignore[method-assign]
        fcntl.flock = observed_flock
        module.rename_exchange = observed_exchange
        operation_started.set()
        try:
            store.put("credential.active", value)
        except BaseException as error:
            outcome: tuple[object, ...] = (
                "writer",
                "error",
                type(error).__name__,
                str(error),
            )
        else:
            outcome = ("writer", "ok", value)
        finally:
            module.rename_exchange = real_exchange
            fcntl.flock = real_fcntl_flock
            completed.set()
        results.put((*outcome, store.doctor().status))
    except BaseException as error:
        doctor = store.doctor().status if store is not None else "UNAVAILABLE"
        results.put(("writer", "error", type(error).__name__, str(error), doctor))
    finally:
        if store is not None:
            store.close()


def _observed_process_delete(
    state_dir: str,
    store_ready: Any,
    start_operation: Any,
    operation_started: Any,
    attempted: Any,
    acquired: Any,
    completed: Any,
    entered: Any,
    results: Any,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    store: LinuxEncryptedFileSecretStore | None = None
    try:
        store = LinuxEncryptedFileSecretStore(Path(state_dir))
        store_ready.set()
        if not start_operation.wait(10.0):
            raise TimeoutError("start_operation barrier expired")
        fcntl = module.importlib.import_module("fcntl")
        real_fcntl_flock = fcntl.flock

        def observed_flock(descriptor: int, operation: int) -> None:
            target_attempt = descriptor == store._lock_fd and operation == (
                fcntl.LOCK_EX | fcntl.LOCK_NB
            )
            if target_attempt and not attempted.is_set():
                attempted.set()
            real_fcntl_flock(descriptor, operation)
            if target_attempt and not acquired.is_set():
                acquired.set()

        delete_locked = store._delete_locked

        def observed_delete(name: str) -> None:
            entered.set()
            delete_locked(name)

        store._delete_locked = observed_delete  # type: ignore[method-assign]
        fcntl.flock = observed_flock
        operation_started.set()
        try:
            store.delete("credential.active")
        except BaseException as error:
            outcome = ("deleter", "error", type(error).__name__, str(error))
        else:
            outcome = ("deleter", "ok")
        finally:
            fcntl.flock = real_fcntl_flock
            completed.set()
        results.put((*outcome, store.doctor().status))
    except BaseException as error:
        doctor = store.doctor().status if store is not None else "UNAVAILABLE"
        results.put(("deleter", "error", type(error).__name__, str(error), doctor))
    finally:
        if store is not None:
            store.close()


def _observed_process_get(
    state_dir: str,
    store_ready: Any,
    start_operation: Any,
    operation_started: Any,
    attempted: Any,
    acquired: Any,
    completed: Any,
    results: Any,
) -> None:
    import fcntl

    store: LinuxEncryptedFileSecretStore | None = None
    try:
        store = LinuxEncryptedFileSecretStore(Path(state_dir))
        store_ready.set()
        if not start_operation.wait(10.0):
            raise TimeoutError("start_operation barrier expired")
        real_flock = fcntl.flock

        def observed_flock(descriptor: int, operation: int) -> None:
            target_attempt = descriptor == store._lock_fd and operation == (
                fcntl.LOCK_EX | fcntl.LOCK_NB
            )
            if target_attempt and not attempted.is_set():
                attempted.set()
            real_flock(descriptor, operation)
            if target_attempt and not acquired.is_set():
                acquired.set()

        fcntl.flock = observed_flock
        operation_started.set()
        try:
            value = store.get("credential.active")
        except BaseException as error:
            outcome: tuple[object, ...] = (
                "reader_observer",
                "error",
                type(error).__name__,
                str(error),
            )
        else:
            outcome = ("reader_observer", "ok", value)
        finally:
            fcntl.flock = real_flock
            completed.set()
        results.put(outcome)
    except BaseException as error:
        results.put(("reader_observer", "error", type(error).__name__, str(error)))
    finally:
        if store is not None:
            store.close()


def _observed_master_key_constructor(
    state_dir: str,
    attempted: Any,
    acquired: Any,
    results: Any,
) -> None:
    import fcntl

    real_flock = fcntl.flock

    def observed_flock(descriptor: int, operation: int) -> None:
        target_attempt = operation == (fcntl.LOCK_EX | fcntl.LOCK_NB)
        if target_attempt and not attempted.is_set():
            attempted.set()
        real_flock(descriptor, operation)
        if target_attempt and not acquired.is_set():
            acquired.set()

    store: LinuxEncryptedFileSecretStore | None = None
    fcntl.flock = observed_flock
    try:
        store = LinuxEncryptedFileSecretStore(Path(state_dir))
        results.put(("constructor_observer", "ok", store.doctor().status))
    except BaseException as error:
        results.put(("constructor_observer", "error", type(error).__name__, str(error)))
    finally:
        fcntl.flock = real_flock
        if store is not None:
            store.close()


def _blocking_master_key_initialization(
    state_dir: str,
    entered: Any,
    release: Any,
    results: Any,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    real_create = LinuxEncryptedFileSecretStore._create_file

    def blocked_create(
        instance: LinuxEncryptedFileSecretStore,
        name: str,
        data: bytes,
    ) -> Any:
        if name == ".master-key":
            assert instance._read_store_state().state is module._StoreHealth.MUTATING
            entered.set()
            if not release.wait(10.0):
                raise TimeoutError("master-key release barrier expired")
        return real_create(instance, name, data)

    LinuxEncryptedFileSecretStore._create_file = blocked_create
    store: LinuxEncryptedFileSecretStore | None = None
    try:
        store = LinuxEncryptedFileSecretStore(Path(state_dir))
        results.put(("initializer", "ok", store.doctor().status))
    except BaseException as error:
        results.put(("initializer", "error", type(error).__name__, str(error)))
    finally:
        LinuxEncryptedFileSecretStore._create_file = real_create
        if store is not None:
            store.close()


def _process_hold_store_lock(
    state_dir: str,
    entered: Any,
    release: Any,
    results: Any,
) -> None:
    store = LinuxEncryptedFileSecretStore(Path(state_dir))
    try:
        with store._operation_lock:
            with store._process_shared_lock():
                entered.set()
                if not release.wait(10.0):
                    raise TimeoutError("holder release barrier expired")
        results.put(("holder", "ok"))
    except BaseException as error:
        results.put(("holder", "error", type(error).__name__, str(error)))
    finally:
        store.close()


def _rollback_process_put(
    state_dir: str,
    exchanged: Any,
    release: Any,
    results: Any,
    fail_inverse_exchange: bool,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    store = LinuxEncryptedFileSecretStore(Path(state_dir))
    real_exchange = module.rename_exchange
    exchange_calls = 0

    def controlled_exchange(*args: object, **kwargs: object) -> None:
        nonlocal exchange_calls
        exchange_calls += 1
        if fail_inverse_exchange and exchange_calls > 1:
            raise OSError("controlled inverse exchange failure")
        real_exchange(*args, **kwargs)  # type: ignore[arg-type]

    def reject_after_exchange(*args: object, **kwargs: object) -> None:
        del args, kwargs
        exchanged.set()
        if not release.wait(10.0):
            raise TimeoutError("rollback release barrier expired")
        raise SecureStoreUnavailableError("controlled final validation failure")

    module.rename_exchange = controlled_exchange
    store._validate_published_secret = reject_after_exchange  # type: ignore[method-assign]
    try:
        store.put("credential.active", "NEW_A")
        results.put(("rollback", "unexpected_success", exchange_calls))
    except BaseException as error:
        results.put(
            (
                "rollback",
                "error",
                type(error).__name__,
                str(error),
                exchange_calls,
                store.doctor().status,
            )
        )
    finally:
        module.rename_exchange = real_exchange
        store.close()


def _poison_persistence_failure_process(
    state_dir: str,
    fatal: Any,
    release: Any,
    results: Any,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    store = LinuxEncryptedFileSecretStore(Path(state_dir))
    real_exchange = module.rename_exchange
    real_pwrite = module._PWRITE
    real_open = module.os.open
    exchange_calls = 0
    poison_partial = False

    def controlled_exchange(*args: object, **kwargs: object) -> None:
        nonlocal exchange_calls
        exchange_calls += 1
        if exchange_calls > 1:
            raise OSError("controlled inverse exchange failure")
        real_exchange(*args, **kwargs)  # type: ignore[arg-type]

    def reject_final(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise SecureStoreUnavailableError("controlled final validation failure")

    def enospc_pwrite(descriptor: int, payload: bytes, offset: int) -> int:
        nonlocal poison_partial
        assert real_pwrite is not None
        if descriptor == store._state_fd:
            slot_index = offset // store._state_slot_size
            decoded = store._decode_state_slot(slot_index, payload)
            if decoded is not None and decoded.state is module._StoreHealth.POISONED:
                poison_partial = True
                partial = max(1, len(payload) // 2)
                return real_pwrite(descriptor, payload[:partial], offset)
            if poison_partial:
                raise OSError(errno.ENOSPC, "controlled partial poison failure")
        return real_pwrite(descriptor, payload, offset)

    def fail_marker_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if path == store._poison_name and flags & os.O_CREAT:
            raise OSError(errno.ENOSPC, "controlled marker allocation failure")
        return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    module.rename_exchange = controlled_exchange
    module._PWRITE = enospc_pwrite
    module.os.open = fail_marker_open
    store._validate_published_secret = reject_final  # type: ignore[method-assign]
    try:
        store.put("credential.active", "NEW_A")
        results.put(("fatal", "unexpected_success"))
    except BaseException as error:
        results.put(("fatal", "error", type(error).__name__, str(error)))
        fatal.set()
        release.wait(10.0)
    finally:
        module.rename_exchange = real_exchange
        module._PWRITE = real_pwrite
        module.os.open = real_open
        store.close()


class _SecretItem:
    def __init__(self, block: Any) -> None:
        self._block = block

    def get_secret(self) -> bytes:
        self._block("get_secret")
        return b"stored-value"

    def delete(self) -> None:
        self._block("delete")


class _SecretCollection:
    def __init__(self, block: Any) -> None:
        self._block = block
        self._item = _SecretItem(block)

    def is_locked(self) -> bool:
        self._block("locked")
        return False

    def search_items(self, attributes: dict[str, str]) -> list[_SecretItem]:
        del attributes
        self._block("search")
        return [self._item]

    def create_item(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        self._block("create")


def _install_secretstorage(
    monkeypatch: pytest.MonkeyPatch,
    *,
    blocked_stage: str | None,
) -> tuple[threading.Event, threading.Event]:
    from wto_desktop_agent.platforms.linux import secret_store as module

    entered = threading.Event()
    release = threading.Event()

    def block(stage: str) -> None:
        if stage == blocked_stage:
            entered.set()
            release.wait(2.0)

    collection = _SecretCollection(block)

    def dbus_init() -> object:
        block("dbus_init")
        return object()

    def get_collection_by_alias(
        connection: object,
        alias: str,
    ) -> _SecretCollection:
        del connection
        assert alias == "default"
        block("collection")
        return collection

    fake = SimpleNamespace(
        dbus_init=dbus_init,
        get_collection_by_alias=get_collection_by_alias,
    )
    real_import = module.importlib.import_module

    def import_module(name: str) -> Any:
        return fake if name == "secretstorage" else real_import(name)

    monkeypatch.setattr(module.importlib, "import_module", import_module)
    return entered, release


def _settings(tmp_path: Path, **overrides: object) -> AgentSettings:
    values: dict[str, object] = {
        "environment": "test",
        "server_url": "http://testserver",
        "state_dir": tmp_path,
        "linux_secret_service_total_timeout_seconds": 0.25,
        "linux_secret_service_operation_timeout_seconds": 0.1,
    }
    values.update(overrides)
    return AgentSettings.model_validate(values)


def test_phase05_toml_without_backend_remains_secret_service_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "phase05.toml"
    state = tmp_path / "state"
    config.write_text(
        "[agent]\n"
        'environment="test"\n'
        'server_url="http://testserver"\n'
        f'state_dir="{state.as_posix()}"\n',
        encoding="utf-8",
    )
    settings = load_settings(config)
    assert settings.linux_secret_backend == "secret_service"
    store = LinuxPlatformAdapter._secret_store(settings)
    assert isinstance(store, LinuxSecretServiceStore)

    from wto_desktop_agent.platforms.linux import secret_store as module

    real_import = module.importlib.import_module

    def missing(name: str) -> Any:
        if name == "secretstorage":
            raise ModuleNotFoundError(name)
        return real_import(name)

    monkeypatch.setattr(module.importlib, "import_module", missing)
    with pytest.raises(SecureStoreUnavailableError):
        store.get("credential.active")
    assert not (state / "secrets" / ".master-key").exists()


def test_auto_is_fail_closed_and_unknown_backend_is_invalid(tmp_path: Path) -> None:
    store = LinuxPlatformAdapter._secret_store(_settings(tmp_path, linux_secret_backend="auto"))
    assert isinstance(store, LinuxSecretServiceStore)
    assert not (tmp_path / "secrets" / ".master-key").exists()
    with pytest.raises(ValidationError):
        _settings(tmp_path, linux_secret_backend="unknown")


def test_unavailable_adapter_preserves_commit_indeterminate_reason() -> None:
    store = UnavailableLinuxSecretStore(MutationCommitIndeterminateError())

    assert store.secure
    with pytest.raises(MutationCommitIndeterminateError):
        store.put("credential.active", "must-not-retry")
    with pytest.raises(MutationCommitIndeterminateError):
        store.get("credential.active")
    assert store.doctor().detail == "BLOCKED_MUTATION_COMMIT_INDETERMINATE"


def test_secret_service_uses_non_creating_default_alias_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    aliases: list[str] = []
    forbidden_calls: list[str] = []
    collection = _SecretCollection(lambda stage: None)

    def get_collection_by_alias(connection: object, alias: str) -> _SecretCollection:
        del connection
        aliases.append(alias)
        return collection

    def forbidden(name: str) -> Any:
        def invoke(*args: object, **kwargs: object) -> None:
            del args, kwargs
            forbidden_calls.append(name)
            raise AssertionError(f"forbidden Secret Service operation: {name}")

        return invoke

    fake = SimpleNamespace(
        dbus_init=lambda: object(),
        get_collection_by_alias=get_collection_by_alias,
        get_default_collection=forbidden("get_default_collection"),
        create_collection=forbidden("create_collection"),
        unlock_objects=forbidden("unlock_objects"),
        prompt=forbidden("prompt"),
    )
    real_import = module.importlib.import_module
    monkeypatch.setattr(
        module.importlib,
        "import_module",
        lambda name: fake if name == "secretstorage" else real_import(name),
    )

    store = LinuxSecretServiceStore()
    assert store.get("credential.active") == "stored-value"
    assert aliases == ["default"]
    assert forbidden_calls == []


def test_secret_service_missing_default_alias_fails_without_creation_or_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    class ItemNotFoundException(Exception):
        pass

    alias_calls = 0
    forbidden_calls: list[str] = []

    def missing_alias(connection: object, alias: str) -> None:
        del connection
        nonlocal alias_calls
        alias_calls += 1
        assert alias == "default"
        raise ItemNotFoundException("no default collection")

    def forbidden(name: str) -> Any:
        def invoke(*args: object, **kwargs: object) -> None:
            del args, kwargs
            forbidden_calls.append(name)
            raise AssertionError(f"forbidden Secret Service operation: {name}")

        return invoke

    fake = SimpleNamespace(
        dbus_init=lambda: object(),
        get_collection_by_alias=missing_alias,
        get_default_collection=forbidden("get_default_collection"),
        create_collection=forbidden("create_collection"),
        unlock_objects=forbidden("unlock_objects"),
        prompt=forbidden("prompt"),
        exceptions=SimpleNamespace(ItemNotFoundException=ItemNotFoundException),
    )
    real_import = module.importlib.import_module
    monkeypatch.setattr(
        module.importlib,
        "import_module",
        lambda name: fake if name == "secretstorage" else real_import(name),
    )

    store = LinuxSecretServiceStore()
    with pytest.raises(SecureStoreUnavailableError) as raised:
        store.get("credential.active")
    assert isinstance(raised.value.__cause__, ItemNotFoundException)
    with pytest.raises(SecureStoreUnavailableError, match="backend is unavailable"):
        store.get("credential.active")
    assert alias_calls == 1
    assert forbidden_calls == []


def test_secret_service_locked_default_alias_never_attempts_unlock_or_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    forbidden_calls: list[str] = []

    class LockedCollection(_SecretCollection):
        def is_locked(self) -> bool:
            return True

    def forbidden(name: str) -> Any:
        def invoke(*args: object, **kwargs: object) -> None:
            del args, kwargs
            forbidden_calls.append(name)
            raise AssertionError(f"forbidden Secret Service operation: {name}")

        return invoke

    collection = LockedCollection(lambda stage: None)

    def locked_alias(connection: object, alias: str) -> LockedCollection:
        del connection
        assert alias == "default"
        return collection

    fake = SimpleNamespace(
        dbus_init=lambda: object(),
        get_collection_by_alias=locked_alias,
        get_default_collection=forbidden("get_default_collection"),
        create_collection=forbidden("create_collection"),
        unlock_objects=forbidden("unlock_objects"),
        prompt=forbidden("prompt"),
    )
    real_import = module.importlib.import_module
    monkeypatch.setattr(
        module.importlib,
        "import_module",
        lambda name: fake if name == "secretstorage" else real_import(name),
    )

    store = LinuxSecretServiceStore()
    with pytest.raises(SecureStoreUnavailableError, match="interactive unlock is not attempted"):
        store.get("credential.active")
    assert forbidden_calls == []


def test_deb_configs_explicitly_select_encrypted_file() -> None:
    root = Path(__file__).parents[3] / "packaging" / "linux" / "config"
    for filename in ("wto-agent.toml", "capture-node.toml"):
        document = tomllib.loads((root / filename).read_text(encoding="utf-8"))
        assert document["agent"]["linux_secret_backend"] == "encrypted_file"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stage,operation",
    [
        ("dbus_init", "get"),
        ("collection", "get"),
        ("search", "get"),
        ("get_secret", "get"),
        ("create", "put"),
        ("delete", "delete"),
    ],
)
async def test_adapter_secret_service_times_out_each_blocking_stage_without_stalling_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    operation: str,
) -> None:
    entered, release = _install_secretstorage(monkeypatch, blocked_stage=stage)
    store = LinuxPlatformAdapter._secret_store(_settings(tmp_path))
    assert isinstance(store, LinuxSecretServiceStore)
    ticks = 0
    stop = asyncio.Event()

    async def ticker() -> None:
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            await asyncio.sleep(0.005)

    async def invoke() -> object:
        if operation == "put":
            return await store.aput("credential.active", "sensitive-value")
        if operation == "delete":
            return await store.adelete("credential.active")
        return await store.aget("credential.active")

    progress = asyncio.create_task(ticker())
    started = time.monotonic()
    try:
        with pytest.raises(SecureStoreUnavailableError) as captured:
            await invoke()
    finally:
        release.set()
        stop.set()
        await progress
    assert entered.is_set()
    assert time.monotonic() - started < 0.5
    assert ticks >= 3
    assert "sensitive-value" not in str(captured.value)


@pytest.mark.parametrize("operation", ["put", "delete"])
def test_secret_service_mutation_timeout_is_indeterminate_even_if_side_effect_is_late(
    operation: str,
) -> None:
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    values = {"credential.active": b"stored-value"} if operation == "delete" else {}

    class LateItem:
        def delete(self) -> None:
            entered.set()
            release.wait(2.0)
            values.pop("credential.active", None)
            finished.set()

    class LateCollection:
        def create_item(
            self,
            _label: str,
            attributes: dict[str, str],
            value: bytes,
            *,
            replace: bool,
        ) -> None:
            assert replace
            entered.set()
            release.wait(2.0)
            values[attributes["key"]] = bytes(value)
            finished.set()

        def search_items(self, _attributes: dict[str, str]) -> list[LateItem]:
            return [LateItem()]

    store = LinuxSecretServiceStore(
        total_timeout_seconds=0.1,
        operation_timeout_seconds=0.05,
    )
    store._collection = LateCollection()
    try:
        with pytest.raises(MutationCommitIndeterminateError):
            if operation == "put":
                store.put("credential.active", "late-value")
            else:
                store.delete("credential.active")
        assert entered.is_set()
    finally:
        release.set()
    assert finished.wait(1.0)
    expected = b"late-value" if operation == "put" else None
    assert values.get("credential.active") == expected
    with pytest.raises(MutationCommitIndeterminateError):
        store.get("credential.active")
    assert store.doctor().detail == "BLOCKED_MUTATION_COMMIT_INDETERMINATE"


@pytest.mark.asyncio
async def test_secret_service_cancelled_mutation_is_indeterminate_if_worker_continues() -> None:
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    values: dict[str, bytes] = {}

    class LateCollection:
        def create_item(
            self,
            _label: str,
            attributes: dict[str, str],
            value: bytes,
            *,
            replace: bool,
        ) -> None:
            assert replace
            entered.set()
            release.wait(2.0)
            values[attributes["key"]] = bytes(value)
            finished.set()

    store = LinuxSecretServiceStore(
        total_timeout_seconds=1.0,
        operation_timeout_seconds=0.5,
    )
    store._collection = LateCollection()
    task = asyncio.create_task(store.aput("credential.active", "late-cancelled-value"))
    assert await asyncio.to_thread(entered.wait, 0.5)
    task.cancel()
    try:
        with pytest.raises(MutationCommitIndeterminateError):
            await task
    finally:
        release.set()
    assert await asyncio.to_thread(finished.wait, 1.0)
    assert values["credential.active"] == b"late-cancelled-value"
    with pytest.raises(MutationCommitIndeterminateError):
        await store.aget("credential.active")


def test_secret_service_total_budget_covers_all_initialization_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    collection = _SecretCollection(lambda stage: time.sleep(0.045))
    fake = SimpleNamespace(
        dbus_init=lambda: (time.sleep(0.045), object())[1],
        get_collection_by_alias=lambda connection, alias: (
            time.sleep(0.045),
            collection,
        )[1],
    )
    real_import = module.importlib.import_module
    monkeypatch.setattr(
        module.importlib,
        "import_module",
        lambda name: fake if name == "secretstorage" else real_import(name),
    )
    store = LinuxSecretServiceStore(
        total_timeout_seconds=0.1,
        operation_timeout_seconds=0.08,
    )
    started = time.monotonic()
    with pytest.raises(SecureStoreUnavailableError):
        store.get("credential.active")
    assert time.monotonic() - started < 0.25


@pytest.mark.asyncio
async def test_secret_service_cancellation_is_not_reported_as_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered, release = _install_secretstorage(monkeypatch, blocked_stage="search")
    store = LinuxPlatformAdapter._secret_store(_settings(tmp_path))
    assert isinstance(store, LinuxSecretServiceStore)
    task = asyncio.create_task(store.aget("credential.active"))
    assert await asyncio.to_thread(entered.wait, 0.2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    await asyncio.sleep(0.02)
    with pytest.raises(SecureStoreUnavailableError):
        await store.aget("credential.active")


@pytest.mark.skipif(os.name != "posix", reason="descriptor and ownership semantics require POSIX")
def test_explicit_encrypted_file_round_trip_and_concurrent_initialization(
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    barrier = threading.Barrier(2)

    def initialize() -> bytes:
        barrier.wait()
        store = LinuxEncryptedFileSecretStore(tmp_path)
        try:
            return store._master_key
        finally:
            store.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(initialize)
        second = executor.submit(initialize)
        keys = {first.result(timeout=5), second.result(timeout=5)}
    assert len(keys) == 1
    assert (tmp_path / "secrets" / ".master-key").stat().st_nlink == 1

    store = LinuxPlatformAdapter._secret_store(
        _settings(tmp_path, linux_secret_backend="encrypted_file")
    )
    assert isinstance(store, LinuxEncryptedFileSecretStore)
    store.put("credential.active", "value")
    assert store.get("credential.active") == "value"
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="flock semantics require POSIX")
def test_process_shared_lock_serializes_real_updates_across_processes(
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    initial = LinuxEncryptedFileSecretStore(tmp_path)
    initial.put("credential.active", "initial")
    initial.close()
    context = multiprocessing.get_context("spawn")
    entered = context.Event()
    release = context.Event()
    results = context.Queue()
    first = context.Process(
        target=_blocking_process_put,
        args=(str(tmp_path), "first", entered, release, results),
    )
    second = context.Process(
        target=_process_put,
        args=(str(tmp_path), "second", results),
    )
    first.start()
    assert entered.wait(5.0)
    second.start()
    try:
        with pytest.raises(queue_module.Empty):
            results.get(timeout=0.2)
    finally:
        release.set()
    outcomes = {results.get(timeout=10.0), results.get(timeout=10.0)}
    first.join(10.0)
    second.join(10.0)

    assert first.exitcode == 0
    assert second.exitcode == 0
    assert outcomes == {("ok", "first"), ("ok", "second")}
    final = LinuxEncryptedFileSecretStore(tmp_path)
    assert final.get("credential.active") == "second"
    final.close()


@pytest.mark.skipif(os.name != "posix", reason="flock semantics require POSIX")
def test_master_key_initialization_is_serialized_across_processes(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o700)
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(target=_process_master_key, args=(str(tmp_path), start, results))
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    start.set()
    digests = {results.get(timeout=10.0), results.get(timeout=10.0)}
    for process in processes:
        process.join(10.0)
        assert process.exitcode == 0

    assert len(digests) == 1
    keys = list((tmp_path / "secrets").glob(".master-key"))
    assert len(keys) == 1
    assert not list((tmp_path / "secrets").glob(".pending-*"))


@pytest.mark.skipif(os.name != "posix", reason="flock semantics require POSIX")
def test_master_key_initializer_exposes_exact_attempted_and_acquired_boundaries(
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    context = multiprocessing.get_context("spawn")
    initializer_entered = context.Event()
    initializer_release = context.Event()
    writer_attempted = context.Event()
    writer_acquired = context.Event()
    results = context.Queue()
    initializer = context.Process(
        target=_blocking_master_key_initialization,
        args=(str(tmp_path), initializer_entered, initializer_release, results),
    )
    observer = context.Process(
        target=_observed_master_key_constructor,
        args=(str(tmp_path), writer_attempted, writer_acquired, results),
    )
    initializer.start()
    assert initializer_entered.wait(5.0)
    lock_path = tmp_path / "secrets" / ".store.lock"
    lock_identity = lock_path.stat(follow_symlinks=False)
    observer.start()
    assert writer_attempted.wait(5.0)
    assert not writer_acquired.is_set()
    current_lock = lock_path.stat(follow_symlinks=False)
    assert (current_lock.st_dev, current_lock.st_ino) == (
        lock_identity.st_dev,
        lock_identity.st_ino,
    )
    initializer_release.set()
    outcomes = {results.get(timeout=10.0), results.get(timeout=10.0)}
    initializer.join(10.0)
    observer.join(10.0)
    assert initializer.exitcode == observer.exitcode == 0
    assert ("initializer", "ok", "OK") in outcomes
    assert ("constructor_observer", "ok", "OK") in outcomes
    assert writer_acquired.is_set()
    final_lock = lock_path.stat(follow_symlinks=False)
    assert (final_lock.st_dev, final_lock.st_ino) == (
        lock_identity.st_dev,
        lock_identity.st_ino,
    )


@pytest.mark.skipif(os.name != "posix", reason="flock semantics require POSIX")
def test_startup_signal_does_not_count_as_an_attempt_to_acquire_flock(
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    initial = LinuxEncryptedFileSecretStore(tmp_path)
    initial.put("credential.active", "old")
    initial.close()
    context = multiprocessing.get_context("spawn")
    holder_entered = context.Event()
    holder_release = context.Event()
    startup_signal = context.Event()
    proceed = context.Event()
    operation_started = context.Event()
    actual_attempted = context.Event()
    actual_acquired = context.Event()
    completed = context.Event()
    writer_entered = context.Event()
    writer_exchange = context.Event()
    results = context.Queue()
    holder = context.Process(
        target=_process_hold_store_lock,
        args=(str(tmp_path), holder_entered, holder_release, results),
    )
    writer = context.Process(
        target=_observed_process_put,
        args=(
            str(tmp_path),
            "new",
            startup_signal,
            proceed,
            operation_started,
            actual_attempted,
            actual_acquired,
            completed,
            writer_entered,
            writer_exchange,
            results,
        ),
    )
    writer.start()
    assert startup_signal.wait(5.0)
    assert not actual_attempted.is_set()
    assert not actual_acquired.is_set()
    holder.start()
    assert holder_entered.wait(5.0)
    proceed.set()
    assert operation_started.wait(5.0)
    assert actual_attempted.wait(5.0)
    assert not actual_acquired.is_set()
    holder_release.set()
    outcomes = {results.get(timeout=10.0), results.get(timeout=10.0)}
    holder.join(10.0)
    writer.join(10.0)
    assert holder.exitcode == writer.exitcode == 0
    assert ("holder", "ok") in outcomes
    assert ("writer", "ok", "new", "DEGRADED") in outcomes
    assert actual_acquired.is_set()
    assert completed.is_set()
    assert writer_entered.is_set()
    assert writer_exchange.is_set()


@pytest.mark.skipif(os.name != "posix", reason="flock semantics require POSIX")
def test_delete_exposes_exact_attempted_and_acquired_flock_boundaries(
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    initial = LinuxEncryptedFileSecretStore(tmp_path)
    initial.put("credential.active", "old")
    initial.close()
    lock_path = tmp_path / "secrets" / ".store.lock"
    lock_identity = lock_path.stat(follow_symlinks=False)
    context = multiprocessing.get_context("spawn")
    holder_entered = context.Event()
    holder_release = context.Event()
    delete_attempted = context.Event()
    delete_acquired = context.Event()
    store_ready = context.Event()
    start_operation = context.Event()
    operation_started = context.Event()
    completed = context.Event()
    delete_entered = context.Event()
    results = context.Queue()
    holder = context.Process(
        target=_process_hold_store_lock,
        args=(str(tmp_path), holder_entered, holder_release, results),
    )
    deleter = context.Process(
        target=_observed_process_delete,
        args=(
            str(tmp_path),
            store_ready,
            start_operation,
            operation_started,
            delete_attempted,
            delete_acquired,
            completed,
            delete_entered,
            results,
        ),
    )
    deleter.start()
    assert store_ready.wait(5.0)
    assert not delete_attempted.is_set()
    holder.start()
    assert holder_entered.wait(5.0)
    start_operation.set()
    assert operation_started.wait(5.0)
    assert delete_attempted.wait(5.0)
    assert not delete_acquired.is_set()
    assert not delete_entered.is_set()
    locked_identity = lock_path.stat(follow_symlinks=False)
    assert (locked_identity.st_dev, locked_identity.st_ino) == (
        lock_identity.st_dev,
        lock_identity.st_ino,
    )
    holder_release.set()
    outcomes = {results.get(timeout=10.0), results.get(timeout=10.0)}
    holder.join(10.0)
    deleter.join(10.0)
    assert holder.exitcode == deleter.exitcode == 0
    assert ("holder", "ok") in outcomes
    assert any(outcome[:2] == ("deleter", "ok") for outcome in outcomes)
    assert delete_acquired.is_set()
    assert completed.is_set()
    assert delete_entered.is_set()
    final = LinuxEncryptedFileSecretStore(tmp_path)
    assert final.get("credential.active") is None
    final.close()
    final_identity = lock_path.stat(follow_symlinks=False)
    assert (final_identity.st_dev, final_identity.st_ino) == (
        lock_identity.st_dev,
        lock_identity.st_ino,
    )


@pytest.mark.skipif(os.name != "posix", reason="flock semantics require POSIX")
def test_get_exposes_only_the_operation_flock_boundaries(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o700)
    initial = LinuxEncryptedFileSecretStore(tmp_path)
    initial.put("credential.active", "old")
    initial.close()
    context = multiprocessing.get_context("spawn")
    store_ready = context.Event()
    start_operation = context.Event()
    operation_started = context.Event()
    attempted = context.Event()
    acquired = context.Event()
    completed = context.Event()
    holder_entered = context.Event()
    holder_release = context.Event()
    results = context.Queue()
    reader = context.Process(
        target=_observed_process_get,
        args=(
            str(tmp_path),
            store_ready,
            start_operation,
            operation_started,
            attempted,
            acquired,
            completed,
            results,
        ),
    )
    holder = context.Process(
        target=_process_hold_store_lock,
        args=(str(tmp_path), holder_entered, holder_release, results),
    )

    reader.start()
    assert store_ready.wait(5.0)
    assert not attempted.is_set()
    assert not acquired.is_set()
    holder.start()
    assert holder_entered.wait(5.0)
    start_operation.set()
    assert operation_started.wait(5.0)
    assert attempted.wait(5.0)
    assert not acquired.is_set()
    assert not completed.is_set()
    holder_release.set()
    outcomes = {results.get(timeout=10.0), results.get(timeout=10.0)}
    reader.join(10.0)
    holder.join(10.0)

    assert reader.exitcode == holder.exitcode == 0
    assert acquired.is_set()
    assert completed.is_set()
    assert ("holder", "ok") in outcomes
    assert ("reader_observer", "ok", "old") in outcomes


@pytest.mark.skipif(os.name != "posix", reason="flock semantics require POSIX")
def test_process_lock_timeout_is_bounded_between_store_instances(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o700)
    first = LinuxEncryptedFileSecretStore(tmp_path)
    second = LinuxEncryptedFileSecretStore(
        tmp_path,
        process_lock_timeout_seconds=0.05,
        process_lock_retry_seconds=0.005,
    )
    entered = threading.Event()
    release = threading.Event()

    def hold_lock() -> None:
        with first._operation_lock:
            with first._process_shared_lock():
                entered.set()
                release.wait(2.0)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    assert entered.wait(1.0)
    started = time.monotonic()
    try:
        with pytest.raises(SecureStoreUnavailableError, match="timed out"):
            second.get("credential.active")
        assert time.monotonic() - started < 0.5
    finally:
        release.set()
        holder.join(2.0)
        first.close()
        second.close()


@pytest.mark.skipif(os.name != "posix", reason="flock semantics require POSIX")
def test_put_and_delete_are_serialized_between_store_instances(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    os.chmod(tmp_path, 0o700)
    first = LinuxEncryptedFileSecretStore(tmp_path)
    second = LinuxEncryptedFileSecretStore(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    delete_finished = threading.Event()
    validate = first._validate_published_secret

    def blocked_validate(*args: object, **kwargs: object) -> None:
        entered.set()
        release.wait(2.0)
        validate(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(first, "_validate_published_secret", blocked_validate)
    writer = threading.Thread(target=first.put, args=("credential.active", "value"))

    def delete() -> None:
        second.delete("credential.active")
        delete_finished.set()

    deleter = threading.Thread(target=delete)
    writer.start()
    assert entered.wait(1.0)
    deleter.start()
    assert not delete_finished.wait(0.1)
    release.set()
    writer.join(2.0)
    deleter.join(2.0)

    assert delete_finished.is_set()
    assert first.get("credential.active") is None
    assert list((tmp_path / "secrets").glob(".secret-quarantine-*"))
    first.close()
    second.close()


@pytest.mark.skipif(os.name != "posix", reason="flock semantics require POSIX")
def test_unlock_failure_is_secondary_to_operation_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    secrets_root = tmp_path / "secrets"
    secrets_root.mkdir(mode=0o700)
    master_key = secrets_root / ".master-key"
    master_key.write_bytes(os.urandom(32))
    os.chmod(master_key, 0o600)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    fcntl = module.importlib.import_module("fcntl")
    real_flock = store._flock

    def controlled_flock(descriptor: int, operation: int) -> None:
        if operation == fcntl.LOCK_UN:
            raise OSError("controlled unlock failure")
        real_flock(descriptor, operation)

    def fail_put(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("primary put failure")

    monkeypatch.setattr(store, "_flock", controlled_flock)
    monkeypatch.setattr(store, "_put_locked", fail_put)
    with pytest.raises(RuntimeError, match="primary put failure") as raised:
        store.put("credential.active", "value")

    assert any("unlock failure" in note for note in raised.value.__notes__)
    monkeypatch.setattr(store, "_flock", real_flock)
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="lockfile metadata requires POSIX")
@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink", "permissions"])
def test_process_lockfile_rejects_unsafe_metadata(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    os.chmod(tmp_path, 0o700)
    secrets_root = tmp_path / "secrets"
    secrets_root.mkdir(mode=0o700)
    outside = tmp_path / "outside-lock"
    outside.write_bytes(b"")
    os.chmod(outside, 0o600)
    lockfile = secrets_root / ".store.lock"
    if unsafe_kind == "symlink":
        lockfile.symlink_to(outside)
    elif unsafe_kind == "hardlink":
        os.link(outside, lockfile)
    else:
        lockfile.write_bytes(b"")
        os.chmod(lockfile, 0o640)

    with pytest.raises(SecureStoreUnavailableError):
        LinuxEncryptedFileSecretStore(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="state-file durability requires POSIX")
def test_store_state_is_preallocated_with_two_valid_healthy_slots(
    tmp_path: Path,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    secrets_root = tmp_path / "secrets"
    secrets_root.mkdir(mode=0o700)
    master_key = secrets_root / ".master-key"
    master_key.write_bytes(os.urandom(32))
    os.chmod(master_key, 0o600)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    state_path = tmp_path / "secrets" / ".store-state"
    guard_path = tmp_path / "secrets" / ".store-completion-guard"
    lock_path = tmp_path / "secrets" / ".store.lock"
    metadata = state_path.stat(follow_symlinks=False)
    guard_metadata = guard_path.stat(follow_symlinks=False)
    slots = store._read_store_state_slots()
    guard_slots = store._read_completion_guard_slots()

    assert stat.S_ISREG(metadata.st_mode)
    assert metadata.st_uid == os.geteuid()
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_nlink == 1
    assert metadata.st_size == store._state_file_size == 512
    assert all(slot is not None for slot in slots)
    assert {slot.sequence for slot in slots if slot is not None} == {0, 1}
    assert all(slot.state is module._StoreHealth.HEALTHY for slot in slots if slot is not None)
    assert stat.S_ISREG(guard_metadata.st_mode)
    assert guard_metadata.st_uid == os.geteuid()
    assert stat.S_IMODE(guard_metadata.st_mode) == 0o600
    assert guard_metadata.st_nlink == 1
    assert guard_metadata.st_size == store._completion_guard_file_size == 512
    assert all(slot is not None for slot in guard_slots)
    assert {slot.sequence for slot in guard_slots if slot is not None} == {0, 1}
    assert all(
        slot.state is module._CompletionGuardState.IDLE for slot in guard_slots if slot is not None
    )
    assert lock_path.stat().st_size == 0
    store.put("credential.active", "secret-must-not-appear-in-state")
    assert b"secret-must-not-appear-in-state" not in state_path.read_bytes()
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="state-file durability requires POSIX")
def test_store_state_rejects_single_healthy_slot_when_peer_is_corrupt(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    state_path = tmp_path / "secrets" / ".store-state"
    store.close()
    descriptor = os.open(state_path, os.O_RDWR | int(getattr(os, "O_NOFOLLOW", 0)))
    try:
        latest_offset = 0
        original = os.pread(descriptor, 1, latest_offset + 10)
        os.pwrite(descriptor, bytes([original[0] ^ 1]), latest_offset + 10)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

    recovered = LinuxEncryptedFileSecretStore(tmp_path)
    current = recovered._read_store_state()
    slots = recovered._read_store_state_slots()
    assert current.slot_index == -1
    assert current.reason == "state_corrupt"
    assert sum(slot is not None for slot in slots) == 1
    with pytest.raises(SecureStoreUnavailableError, match="state is corrupt"):
        recovered.get("credential.active")
    assert recovered.doctor().detail.startswith("BLOCKED_STATE_CORRUPT")
    recovered.close()


@pytest.mark.skipif(os.name != "posix", reason="state-file durability requires POSIX")
def test_store_state_with_both_slots_corrupt_fails_closed_and_blocks_doctor(
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    state_path = tmp_path / "secrets" / ".store-state"
    store.close()
    descriptor = os.open(state_path, os.O_RDWR | int(getattr(os, "O_NOFOLLOW", 0)))
    try:
        os.pwrite(descriptor, b"\0" * LinuxEncryptedFileSecretStore._state_file_size, 0)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

    blocked = LinuxEncryptedFileSecretStore(tmp_path)
    with pytest.raises(SecureStoreUnavailableError, match="state is corrupt"):
        blocked.get("credential.active")
    with pytest.raises(SecureStoreUnavailableError, match="state is corrupt"):
        blocked.put("credential.active", "must-not-run")
    with pytest.raises(SecureStoreUnavailableError, match="state is corrupt"):
        blocked.delete("credential.active")
    assert blocked.doctor().status == "BLOCKED"
    blocked.close()


def _replace_store_state_slots(
    store: LinuxEncryptedFileSecretStore,
    first: bytes,
    second: bytes,
) -> None:
    store._pwrite_all(store._state_fd, first, 0)
    store._pwrite_all(store._state_fd, second, store._state_slot_size)
    os.fsync(store._state_fd)


def _replace_completion_guard_slots(
    store: LinuxEncryptedFileSecretStore,
    first: bytes,
    second: bytes,
) -> None:
    store._pwrite_all(store._completion_guard_fd, first, 0)
    store._pwrite_all(
        store._completion_guard_fd,
        second,
        store._completion_guard_slot_size,
    )
    os.fsync(store._completion_guard_fd)


@pytest.mark.skipif(os.name != "posix", reason="guard durability requires POSIX")
@pytest.mark.parametrize(
    ("variant", "expected_reason"),
    [
        ("equal", "completion_guard_ambiguous"),
        ("gap", "completion_guard_sequence_invalid"),
        ("invalid_transition", "completion_guard_transition_invalid"),
    ],
)
def test_completion_guard_rejects_ambiguous_slot_pairs(
    tmp_path: Path,
    variant: str,
    expected_reason: str,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    state = store._read_store_state()
    token = state.operation_token
    if variant == "equal":
        records = (
            (10, module._CompletionGuardState.IDLE),
            (10, module._CompletionGuardState.IDLE),
        )
    elif variant == "gap":
        records = (
            (10, module._CompletionGuardState.FINALIZING),
            (12, module._CompletionGuardState.IDLE),
        )
    else:
        records = (
            (10, module._CompletionGuardState.IDLE),
            (11, module._CompletionGuardState.IDLE),
        )
    encoded = tuple(
        store._encode_completion_guard_slot(
            sequence=sequence,
            state=guard_state,
            store_sequence=state.sequence,
            operation_token=token,
        )
        for sequence, guard_state in records
    )
    _replace_completion_guard_slots(store, encoded[0], encoded[1])
    store.close()

    blocked = LinuxEncryptedFileSecretStore(tmp_path)
    guard = blocked._read_completion_guard()
    assert guard.slot_index == -1
    assert guard.reason == expected_reason
    assert expected_reason.upper() in blocked.doctor().detail
    with pytest.raises(SecureStoreUnavailableError):
        blocked.get("credential.active")
    blocked.close()


@pytest.mark.skipif(os.name != "posix", reason="guard durability requires POSIX")
def test_completion_guard_rejects_one_valid_slot_and_one_corrupt_slot(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    guard_path = tmp_path / "secrets" / ".store-completion-guard"
    store.close()
    descriptor = os.open(guard_path, os.O_RDWR | int(getattr(os, "O_NOFOLLOW", 0)))
    try:
        byte = os.pread(descriptor, 1, 10)
        os.pwrite(descriptor, bytes([byte[0] ^ 1]), 10)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

    blocked = LinuxEncryptedFileSecretStore(tmp_path)
    assert blocked._read_completion_guard().reason == "completion_guard_corrupt"
    assert blocked.doctor().detail == "BLOCKED_COMPLETION_GUARD_CORRUPT"
    blocked.close()


@pytest.mark.skipif(os.name != "posix", reason="guard durability requires POSIX")
def test_completion_guard_token_must_match_the_healthy_store_state(tmp_path: Path) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    state = store._read_store_state()
    wrong_token = "f" * 32 if state.operation_token != "f" * 32 else "e" * 32
    first = store._encode_completion_guard_slot(
        sequence=20,
        state=module._CompletionGuardState.FINALIZING,
        store_sequence=state.sequence,
        operation_token=wrong_token,
    )
    second = store._encode_completion_guard_slot(
        sequence=21,
        state=module._CompletionGuardState.IDLE,
        store_sequence=state.sequence,
        operation_token=wrong_token,
    )
    _replace_completion_guard_slots(store, first, second)
    store.close()

    blocked = LinuxEncryptedFileSecretStore(tmp_path)
    assert blocked.doctor().detail == "BLOCKED_COMPLETION_GUARD_INCOMPATIBLE"
    with pytest.raises(SecureStoreUnavailableError, match="completion_guard_incompatible"):
        blocked.get("credential.active")
    blocked.close()


@pytest.mark.skipif(os.name != "posix", reason="guard durability requires POSIX")
@pytest.mark.parametrize(
    ("missing_name", "expected_detail"),
    [
        (".store-completion-guard", "BLOCKED_COMPLETION_GUARD_MISSING"),
        (".store-state", "BLOCKED_STORE_STATE_MISSING"),
    ],
)
def test_existing_store_never_bootstraps_a_missing_completion_file_online(
    tmp_path: Path,
    missing_name: str,
    expected_detail: str,
) -> None:
    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    store.close()
    missing_path = tmp_path / "secrets" / missing_name
    missing_path.unlink()

    blocked = LinuxEncryptedFileSecretStore(tmp_path)
    assert not missing_path.exists()
    assert blocked.doctor().detail == expected_detail
    with pytest.raises(SecureStoreUnavailableError):
        blocked.put("credential.active", "must-not-run")
    blocked.close()


@pytest.mark.skipif(os.name != "posix", reason="guard durability requires POSIX")
@pytest.mark.parametrize("durable_state", ["MUTATING", "HEALTHY"])
def test_restart_blocks_every_finalizing_guard_state(
    tmp_path: Path,
    durable_state: str,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    with store._operation_lock:
        with store._process_shared_lock():
            mutating = store._persist_store_mutating("put")
            finalizing = store._persist_completion_guard_finalizing(mutating)
            if durable_state == "HEALTHY":
                store._persist_store_healthy(mutating)
    assert finalizing.state is module._CompletionGuardState.FINALIZING
    store.close()

    blocked = LinuxEncryptedFileSecretStore(tmp_path)
    assert blocked._read_store_state().state is getattr(module._StoreHealth, durable_state)
    assert blocked._read_completion_guard().state is module._CompletionGuardState.FINALIZING
    expected = (
        "BLOCKED_MUTATING_FINALIZING"
        if durable_state == "MUTATING"
        else "BLOCKED_COMPLETION_FINALIZING"
    )
    assert blocked.doctor().detail.startswith(expected)
    with pytest.raises(SecureStoreUnavailableError, match="manual recovery|finalizing"):
        blocked.get("credential.active")
    blocked.close()


@pytest.mark.skipif(os.name != "posix", reason="state-file durability requires POSIX")
@pytest.mark.parametrize(
    ("first", "second", "reason", "doctor_detail"),
    [
        (
            (7, "HEALTHY", "healthy", ""),
            (7, "HEALTHY", "healthy", ""),
            "state_ambiguous",
            "BLOCKED_STATE_CORRUPT",
        ),
        (
            (7, "HEALTHY", "healthy", ""),
            (8, "POISONED", "invalid_direct_poison", "1" * 32),
            "state_transition_invalid",
            "BLOCKED_STATE_CORRUPT",
        ),
        (
            (7, "HEALTHY", "healthy", ""),
            (9, "MUTATING", "put", "2" * 32),
            "state_sequence_invalid",
            "BLOCKED_STATE_CORRUPT",
        ),
    ],
)
def test_store_state_rejects_ambiguous_or_invalid_transitions(
    tmp_path: Path,
    first: tuple[int, str, str, str],
    second: tuple[int, str, str, str],
    reason: str,
    doctor_detail: str,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)

    def encode(record: tuple[int, str, str, str]) -> bytes:
        sequence, state, state_reason, token = record
        return store._encode_state_slot(
            sequence=sequence,
            state=getattr(module._StoreHealth, state),
            reason=state_reason,
            operation_token=token,
        )

    _replace_store_state_slots(store, encode(first), encode(second))
    store.close()

    blocked = LinuxEncryptedFileSecretStore(tmp_path)
    current = blocked._read_store_state()
    assert current.slot_index == -1
    assert current.reason == reason
    assert blocked.doctor().detail.startswith(doctor_detail)
    with pytest.raises(SecureStoreUnavailableError):
        blocked.get("credential.active")
    blocked.close()


@pytest.mark.skipif(os.name != "posix", reason="state-file durability requires POSIX")
@pytest.mark.parametrize(
    ("latest_state", "latest_reason", "expected_detail"),
    [
        ("MUTATING", "put", "BLOCKED_MUTATING"),
        ("POISONED", "exchange_rollback_unproven", "BLOCKED_POISONED"),
    ],
)
def test_restart_never_promotes_mutating_or_poisoned_to_healthy(
    tmp_path: Path,
    latest_state: str,
    latest_reason: str,
    expected_detail: str,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    with store._operation_lock:
        with store._process_shared_lock():
            mutating = store._persist_store_mutating("put")
            if latest_state == "POISONED":
                store._persist_store_poisoned(latest_reason)
    store.close()

    blocked = LinuxEncryptedFileSecretStore(tmp_path)
    assert blocked._read_store_state().state is getattr(module._StoreHealth, latest_state)
    assert blocked._read_store_state().sequence >= mutating.sequence
    assert blocked.doctor().detail.startswith(expected_detail)
    with pytest.raises(SecureStoreUnavailableError, match="manual recovery"):
        blocked.put("credential.active", "must-not-run")
    blocked.close()


@pytest.mark.skipif(os.name != "posix", reason="state-file durability requires POSIX")
def test_master_key_creation_starts_only_after_mutating_is_durable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    observed: list[module._StoreStateSlot] = []
    real_create = LinuxEncryptedFileSecretStore._create_file

    def observed_create(
        instance: LinuxEncryptedFileSecretStore,
        name: str,
        data: bytes,
    ) -> Any:
        state = instance._read_store_state()
        guard = instance._read_completion_guard()
        observed.append(state)
        assert state.state is module._StoreHealth.MUTATING
        assert state.reason == "master_key_init"
        assert guard.state is module._CompletionGuardState.FINALIZING
        assert guard.store_sequence == state.sequence + 1
        assert guard.operation_token == state.operation_token
        return real_create(instance, name, data)

    monkeypatch.setattr(LinuxEncryptedFileSecretStore, "_create_file", observed_create)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    assert len(observed) == 1
    assert store._read_store_state().state is module._StoreHealth.HEALTHY
    assert store._read_store_state().sequence == observed[0].sequence + 1
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="guard durability requires POSIX")
def test_finalizing_failure_prevents_the_secret_mutation(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    mutation_called = False

    def reject_finalizing(mutating: object) -> Any:
        del mutating
        raise SecureStoreUnavailableError("controlled FINALIZING readback failure")

    def forbidden_put(*args: object, **kwargs: object) -> None:
        del args, kwargs
        nonlocal mutation_called
        mutation_called = True

    store._persist_completion_guard_finalizing = reject_finalizing  # type: ignore[method-assign]
    store._put_locked = forbidden_put  # type: ignore[method-assign]
    with pytest.raises(SecureStoreUnavailableError, match="finalizing_failed"):
        store.put("credential.active", "must-not-run")

    assert not mutation_called
    assert store.doctor().status == "BLOCKED"
    store.close()
    restarted = LinuxEncryptedFileSecretStore(tmp_path)
    assert restarted.doctor().status == "BLOCKED"
    restarted.close()


@pytest.mark.skipif(os.name != "posix", reason="guard durability requires POSIX")
def test_healthy_readback_failure_leaves_finalizing_and_never_restores_mutating(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    transitions: list[module._StoreHealth] = []
    real_persist_state = store._persist_store_state
    real_persist_healthy = store._persist_store_healthy

    def track_state(*args: object, **kwargs: object) -> Any:
        transitions.append(kwargs["state"])  # type: ignore[arg-type]
        return real_persist_state(*args, **kwargs)  # type: ignore[arg-type]

    def write_healthy_then_fail(mutating: Any) -> Any:
        real_persist_healthy(mutating)
        raise SecureStoreUnavailableError("controlled post-HEALTHY readback failure")

    monkeypatch.setattr(store, "_persist_store_state", track_state)
    monkeypatch.setattr(store, "_persist_store_healthy", write_healthy_then_fail)
    with pytest.raises(SecureStoreUnavailableError, match="mutation_not_committed"):
        store.put("credential.active", "durable-but-unconfirmed")

    assert transitions == [module._StoreHealth.MUTATING, module._StoreHealth.HEALTHY]
    assert store._read_store_state().state is module._StoreHealth.HEALTHY
    assert store._read_completion_guard().state is module._CompletionGuardState.FINALIZING
    monkeypatch.undo()
    store.close()

    restarted = LinuxEncryptedFileSecretStore(tmp_path)
    assert restarted.doctor().detail == "BLOCKED_COMPLETION_FINALIZING"
    second = LinuxEncryptedFileSecretStore(tmp_path)
    assert second.doctor().detail == "BLOCKED_COMPLETION_FINALIZING"
    with pytest.raises(SecureStoreUnavailableError, match="finalizing"):
        second.get("credential.active")
    second.close()
    restarted.close()


@pytest.mark.skipif(os.name != "posix", reason="guard durability requires POSIX")
def test_idle_clear_failure_blocks_restart_after_healthy_is_durable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)

    def reject_idle(*args: object, **kwargs: object) -> Any:
        del args, kwargs
        raise SecureStoreUnavailableError("controlled IDLE clear failure")

    monkeypatch.setattr(store, "_persist_completion_guard_idle", reject_idle)
    with pytest.raises(SecureStoreUnavailableError, match="mutation_not_committed"):
        store.put("credential.active", "durable-but-unconfirmed")
    assert store._read_store_state().state is module._StoreHealth.HEALTHY
    assert store._read_completion_guard().state is module._CompletionGuardState.FINALIZING
    monkeypatch.undo()
    store.close()

    restarted = LinuxEncryptedFileSecretStore(tmp_path)
    assert restarted.doctor().detail == "BLOCKED_COMPLETION_FINALIZING"
    restarted.close()


@pytest.mark.skipif(os.name != "posix", reason="guard durability requires POSIX")
def test_partial_idle_slot_write_is_not_recovered_from_the_other_valid_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    real_pwrite = module._PWRITE
    assert real_pwrite is not None
    partial_written = False

    def partial_idle_write(descriptor: int, payload: bytes, offset: int) -> int:
        nonlocal partial_written
        slot = store._decode_completion_guard_slot(
            offset // store._completion_guard_slot_size,
            payload,
        )
        if (
            not partial_written
            and descriptor == store._completion_guard_fd
            and slot is not None
            and slot.state is module._CompletionGuardState.IDLE
            and slot.operation_token
        ):
            partial_written = True
            real_pwrite(descriptor, payload[:64], offset)
            raise OSError(errno.ENOSPC, "controlled partial IDLE slot write")
        return real_pwrite(descriptor, payload, offset)

    monkeypatch.setattr(module, "_PWRITE", partial_idle_write)
    with pytest.raises(MutationCommitIndeterminateError):
        store.put("credential.active", "partially-confirmed")

    assert partial_written
    assert store._read_store_state().state is module._StoreHealth.HEALTHY
    assert store._read_completion_guard().reason == "completion_guard_corrupt"
    monkeypatch.undo()
    store.close()

    restarted = LinuxEncryptedFileSecretStore(tmp_path)
    assert restarted.doctor().detail == "BLOCKED_COMPLETION_GUARD_CORRUPT"
    with pytest.raises(SecureStoreUnavailableError, match="completion_guard_corrupt"):
        restarted.get("credential.active")
    restarted.close()


@pytest.mark.skipif(os.name != "posix", reason="guard durability requires POSIX")
def test_verified_idle_is_the_commit_even_when_the_caller_observes_a_later_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    real_idle = store._persist_completion_guard_idle

    def commit_then_fail(*args: object, **kwargs: object) -> Any:
        real_idle(*args, **kwargs)
        raise RuntimeError("controlled post-commit return failure")

    def reject_logging(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("controlled logging failure")

    monkeypatch.setattr(store, "_persist_completion_guard_idle", commit_then_fail)
    monkeypatch.setattr(module._LOGGER, "error", reject_logging)
    store.put("credential.active", "committed")

    assert store._fatal_reason is None
    assert store._read_store_state().state is module._StoreHealth.HEALTHY
    assert store._read_completion_guard().state is module._CompletionGuardState.IDLE
    monkeypatch.undo()
    assert store.get("credential.active") == "committed"
    store.close()

    restarted = LinuxEncryptedFileSecretStore(tmp_path)
    assert restarted.get("credential.active") == "committed"
    assert restarted.doctor().status == "OK"
    restarted.close()


@pytest.mark.skipif(os.name != "posix", reason="guard durability requires POSIX")
def test_idle_readback_failure_is_revalidated_under_the_same_flock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    real_pread = module._PREAD
    real_pwrite = module._PWRITE
    assert real_pread is not None and real_pwrite is not None
    idle_written = False
    readback_failed = False

    def observe_idle_write(descriptor: int, payload: bytes, offset: int) -> int:
        nonlocal idle_written
        result = real_pwrite(descriptor, payload, offset)
        slot = store._decode_completion_guard_slot(
            offset // store._completion_guard_slot_size,
            payload,
        )
        if (
            descriptor == store._completion_guard_fd
            and slot is not None
            and slot.state is module._CompletionGuardState.IDLE
            and slot.operation_token
        ):
            idle_written = True
        return result

    def fail_first_idle_readback(descriptor: int, size: int, offset: int) -> bytes:
        nonlocal readback_failed
        if idle_written and not readback_failed and descriptor == store._completion_guard_fd:
            readback_failed = True
            raise OSError(errno.EIO, "controlled transient IDLE readback failure")
        return real_pread(descriptor, size, offset)

    monkeypatch.setattr(module, "_PWRITE", observe_idle_write)
    monkeypatch.setattr(module, "_PREAD", fail_first_idle_readback)
    store.put("credential.active", "committed-after-revalidation")

    assert readback_failed
    assert store._fatal_reason is None
    assert store.get("credential.active") == "committed-after-revalidation"
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="guard durability requires POSIX")
def test_unreadable_idle_after_fsync_has_an_indeterminate_non_retryable_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    real_pread = module._PREAD
    real_pwrite = module._PWRITE
    assert real_pread is not None and real_pwrite is not None
    guard_inode = os.fstat(store._completion_guard_fd).st_ino
    idle_written = False

    def observe_idle_write(descriptor: int, payload: bytes, offset: int) -> int:
        nonlocal idle_written
        result = real_pwrite(descriptor, payload, offset)
        slot = store._decode_completion_guard_slot(
            offset // store._completion_guard_slot_size,
            payload,
        )
        if (
            descriptor == store._completion_guard_fd
            and slot is not None
            and slot.state is module._CompletionGuardState.IDLE
            and slot.operation_token
        ):
            idle_written = True
        return result

    def reject_guard_readback(descriptor: int, size: int, offset: int) -> bytes:
        if idle_written and os.fstat(descriptor).st_ino == guard_inode:
            raise OSError(errno.EIO, "controlled persistent IDLE readback failure")
        return real_pread(descriptor, size, offset)

    monkeypatch.setattr(module, "_PWRITE", observe_idle_write)
    monkeypatch.setattr(module, "_PREAD", reject_guard_readback)
    with pytest.raises(MutationCommitIndeterminateError) as raised:
        store.put("credential.active", "possibly-committed")

    assert str(raised.value) == "mutation_commit_indeterminate"
    assert store._fatal_reason == "mutation_commit_indeterminate"
    assert store.doctor().detail == "BLOCKED_MUTATION_COMMIT_INDETERMINATE"
    with pytest.raises(MutationCommitIndeterminateError):
        store.put("credential.active", "must-not-retry")
    monkeypatch.undo()
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="flock requires POSIX")
@pytest.mark.parametrize("operation", ["put", "delete"])
def test_post_commit_unlock_failure_preserves_success_and_disables_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    import fcntl

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    store.put("credential.active", "committed")
    real_flock = store._flock
    lock_descriptor = store._lock_fd
    unlock_attempts = 0

    def fail_target_unlock(descriptor: int, flags: int) -> None:
        nonlocal unlock_attempts
        if descriptor == lock_descriptor and flags == fcntl.LOCK_UN:
            unlock_attempts += 1
            raise OSError(errno.EIO, "controlled post-commit unlock failure")
        real_flock(descriptor, flags)

    monkeypatch.setattr(store, "_flock", fail_target_unlock)
    if operation == "put":
        store.put("credential.active", "updated")
    else:
        store.delete("credential.active")

    assert unlock_attempts == 1
    assert store._lock_fd == -1
    assert store.doctor().detail == "BLOCKED_POST_COMMIT_UNLOCK_FAILED"
    with pytest.raises(SecureStoreUnavailableError, match="post_commit_unlock_failed"):
        store.get("credential.active")
    monkeypatch.undo()
    store.close()

    restarted = LinuxEncryptedFileSecretStore(tmp_path)
    expected = "updated" if operation == "put" else None
    assert restarted.get("credential.active") == expected
    restarted.close()


@pytest.mark.skipif(os.name != "posix", reason="descriptor close semantics require POSIX")
def test_applied_put_close_failure_preserves_success_and_disables_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    real_close = store._close_open_file
    close_failures = 0

    def close_then_fail(
        opened: Any,
        *,
        primary_error: BaseException | None = None,
    ) -> None:
        nonlocal close_failures
        real_close(opened, primary_error=primary_error)
        if opened is not None and primary_error is None and close_failures == 0:
            close_failures += 1
            raise OSError(errno.EIO, "controlled applied put close failure")

    monkeypatch.setattr(store, "_close_open_file", close_then_fail)
    store.put("credential.active", "committed-before-close-failure")

    assert close_failures == 1
    assert store.doctor().detail == "BLOCKED_POST_COMMIT_CLOSE_FAILED"
    with pytest.raises(SecureStoreUnavailableError, match="post_commit_close_failed"):
        store.get("credential.active")
    monkeypatch.undo()
    store.close()

    restarted = LinuxEncryptedFileSecretStore(tmp_path)
    assert restarted.get("credential.active") == "committed-before-close-failure"
    restarted.close()


@pytest.mark.skipif(os.name != "posix", reason="descriptor close semantics require POSIX")
def test_applied_delete_close_failure_preserves_success_and_disables_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    store.put("credential.active", "delete-me")
    real_close = module.close_descriptor
    target_context = f"secret file {store._name('credential.active')}"
    close_failures = 0

    def close_then_fail(
        descriptor: int,
        *,
        primary_error: BaseException | None = None,
        context: str = "descriptor",
    ) -> None:
        nonlocal close_failures
        real_close(descriptor, primary_error=primary_error, context=context)
        if context == target_context and primary_error is None and close_failures == 0:
            close_failures += 1
            raise OSError(errno.EIO, "controlled applied delete close failure")

    monkeypatch.setattr(module, "close_descriptor", close_then_fail)
    store.delete("credential.active")

    assert close_failures == 1
    assert store.doctor().detail == "BLOCKED_POST_COMMIT_CLOSE_FAILED"
    with pytest.raises(SecureStoreUnavailableError, match="post_commit_close_failed"):
        store.get("credential.active")
    monkeypatch.undo()
    store.close()

    restarted = LinuxEncryptedFileSecretStore(tmp_path)
    assert restarted.get("credential.active") is None
    restarted.close()


@pytest.mark.skipif(os.name != "posix", reason="flock requires POSIX")
def test_post_commit_unlock_failure_retains_exclusive_lock_until_descriptor_closes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import fcntl

    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    retained_descriptor = store._lock_fd
    real_flock = store._flock
    real_close_descriptor = module.close_descriptor
    mutation_calls = 0
    real_put = store._put_locked

    def count_put(*args: object, **kwargs: object) -> None:
        nonlocal mutation_calls
        mutation_calls += 1
        real_put(*args, **kwargs)  # type: ignore[arg-type]

    def fail_unlock(descriptor: int, flags: int) -> None:
        if descriptor == retained_descriptor and flags == fcntl.LOCK_UN:
            raise OSError(errno.EIO, "controlled retained unlock failure")
        real_flock(descriptor, flags)

    def fail_retained_close(
        descriptor: int,
        *,
        primary_error: BaseException | None = None,
        context: str = "descriptor",
    ) -> None:
        if descriptor == retained_descriptor:
            raise OSError(errno.EIO, "controlled retained close failure")
        real_close_descriptor(
            descriptor,
            primary_error=primary_error,
            context=context,
        )

    monkeypatch.setattr(store, "_put_locked", count_put)
    monkeypatch.setattr(store, "_flock", fail_unlock)
    monkeypatch.setattr(module, "close_descriptor", fail_retained_close)
    store.put("credential.active", "committed-once")

    assert mutation_calls == 1
    assert store.doctor().detail == "BLOCKED_POST_COMMIT_UNLOCK_FAILED"
    with pytest.raises(SecureStoreUnavailableError, match="process lock timed out"):
        LinuxEncryptedFileSecretStore(
            tmp_path,
            process_lock_timeout_seconds=0.05,
            process_lock_retry_seconds=0.005,
        )

    monkeypatch.undo()
    store.close()
    os.close(retained_descriptor)

    restarted = LinuxEncryptedFileSecretStore(tmp_path)
    assert restarted.get("credential.active") == "committed-once"
    restarted.close()


@pytest.mark.skipif(os.name != "posix", reason="state-file durability requires POSIX")
def test_create_update_and_delete_run_between_mutating_and_healthy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    observed: list[tuple[str, module._StoreStateSlot]] = []
    real_create = store._create_open_file
    real_exchange = module.rename_exchange
    real_quarantine = store._quarantine_identity

    def observed_create(name: str, data: bytes) -> Any:
        state = store._read_store_state()
        observed.append(("create", state))
        assert state.state is module._StoreHealth.MUTATING
        return real_create(name, data)

    store._create_open_file = observed_create  # type: ignore[method-assign]
    store.put("credential.active", "old")
    assert store._read_store_state().state is module._StoreHealth.HEALTHY

    def observed_exchange(*args: object, **kwargs: object) -> None:
        state = store._read_store_state()
        observed.append(("update", state))
        assert state.state is module._StoreHealth.MUTATING
        real_exchange(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(module, "rename_exchange", observed_exchange)
    store.put("credential.active", "new")
    assert store._read_store_state().state is module._StoreHealth.HEALTHY

    def observed_quarantine(*args: object, **kwargs: object) -> Any:
        if kwargs.get("context") == "deleted_secret":
            state = store._read_store_state()
            observed.append(("delete", state))
            assert state.state is module._StoreHealth.MUTATING
        return real_quarantine(*args, **kwargs)

    store._quarantine_identity = observed_quarantine  # type: ignore[method-assign]
    store.delete("credential.active")
    assert store._read_store_state().state is module._StoreHealth.HEALTHY
    assert {operation for operation, _state in observed} >= {"create", "update", "delete"}
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="state-file durability requires POSIX")
def test_exchange_is_not_called_when_mutating_readback_is_not_confirmed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    store.put("credential.active", "old")
    exchange_called = False

    def reject_mutating(reason: str) -> Any:
        del reason
        raise SecureStoreUnavailableError("controlled MUTATING readback failure")

    def forbidden_exchange(*args: object, **kwargs: object) -> None:
        del args, kwargs
        nonlocal exchange_called
        exchange_called = True

    monkeypatch.setattr(store, "_persist_store_mutating", reject_mutating)
    monkeypatch.setattr(module, "rename_exchange", forbidden_exchange)
    with pytest.raises(SecureStoreUnavailableError, match="MUTATING readback"):
        store.put("credential.active", "new")
    assert not exchange_called
    assert store.get("credential.active") == "old"
    assert store._read_store_state().state is module._StoreHealth.HEALTHY
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="state-file durability requires POSIX")
def test_durable_poison_uses_state_slot_even_when_optional_marker_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    lock_inode = (tmp_path / "secrets" / ".store.lock").stat().st_ino
    real_open = module.os.open

    def fail_marker_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if path == store._poison_name and flags & os.O_CREAT:
            raise OSError(errno.ENOSPC, "controlled marker allocation failure")
        return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(module.os, "open", fail_marker_open)
    primary = SecureStoreUnavailableError("controlled rollback failure")
    with store._operation_lock:
        with store._process_shared_lock():
            mutating = store._persist_store_mutating("put")
            store._persist_completion_guard_finalizing(mutating)
            store._mark_store_poisoned(primary, "exchange_rollback_unproven")

    current = store._read_store_state()
    assert current.state is module._StoreHealth.POISONED
    assert current.sequence == mutating.sequence + 1
    assert current.operation_token == mutating.operation_token
    assert store._read_completion_guard().state is module._CompletionGuardState.FINALIZING
    assert any("marker creation" in note for note in primary.__notes__)
    assert not (tmp_path / "secrets" / ".store-manual-recovery").exists()
    assert (tmp_path / "secrets" / ".store.lock").stat().st_ino == lock_inode
    assert (tmp_path / "secrets" / ".store.lock").stat().st_size == 0
    with pytest.raises(SecureStoreUnavailableError, match="store_poisoned|manual recovery"):
        store.get("credential.active")
    second = LinuxEncryptedFileSecretStore(tmp_path)
    assert second.doctor().status == "BLOCKED"
    with pytest.raises(SecureStoreUnavailableError, match="manual recovery"):
        second.put("credential.active", "must-not-run")
    second.close()
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="state-file durability requires POSIX")
@pytest.mark.parametrize("failure_mode", ["pwrite", "fsync", "readback"])
def test_poison_persistence_failure_releases_flock_and_restart_stays_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    real_pwrite = module._PWRITE
    real_pread = module._PREAD
    real_fsync = module.os.fsync
    assert real_pwrite is not None
    assert real_pread is not None
    poison_written = False

    with store._operation_lock:
        with store._process_shared_lock():
            mutating = store._persist_store_mutating("put")

    def controlled_pwrite(descriptor: int, payload: bytes, offset: int) -> int:
        nonlocal poison_written
        if descriptor == store._state_fd and failure_mode == "pwrite":
            raise OSError(errno.ENOSPC, "controlled state write failure")
        written = real_pwrite(descriptor, payload, offset)
        if descriptor == store._state_fd:
            poison_written = True
        return written

    def controlled_fsync(descriptor: int) -> None:
        if descriptor == store._state_fd and failure_mode == "fsync":
            raise OSError(errno.ENOSPC, "controlled state fsync failure")
        real_fsync(descriptor)

    def controlled_pread(descriptor: int, size: int, offset: int) -> bytes:
        payload = real_pread(descriptor, size, offset)
        if (
            descriptor == store._state_fd
            and failure_mode == "readback"
            and poison_written
            and size == store._state_slot_size
        ):
            return bytes([payload[0] ^ 1]) + payload[1:]
        return payload

    monkeypatch.setattr(module, "_PWRITE", controlled_pwrite)
    monkeypatch.setattr(module.os, "fsync", controlled_fsync)
    monkeypatch.setattr(module, "_PREAD", controlled_pread)
    primary = SecureStoreUnavailableError("controlled rollback failure")
    with store._operation_lock:
        with store._process_shared_lock(allow_poisoned=True):
            store._mark_store_poisoned(primary, "exchange_rollback_unproven")

    assert store._fatal_reason == "poison_persistence_failed"
    assert any("POISONED persistence fail" in note for note in primary.__notes__)
    with pytest.raises(SecureStoreUnavailableError, match="poison_persistence_failed"):
        store.get("credential.active")
    with pytest.raises(SecureStoreUnavailableError, match="poison_persistence_failed"):
        store.put("credential.active", "must-not-run")
    store.close()

    monkeypatch.setattr(module, "_PWRITE", real_pwrite)
    monkeypatch.setattr(module.os, "fsync", real_fsync)
    monkeypatch.setattr(module, "_PREAD", real_pread)
    restarted = LinuxEncryptedFileSecretStore(
        tmp_path,
        process_lock_timeout_seconds=0.05,
        process_lock_retry_seconds=0.005,
    )
    state = restarted._read_store_state()
    assert state.state is not module._StoreHealth.HEALTHY
    assert state.sequence >= mutating.sequence
    assert restarted.doctor().status == "BLOCKED"
    with pytest.raises(SecureStoreUnavailableError):
        restarted.put("credential.active", "must-not-run")
    restarted.close()


def _secret_path(root: Path, key: str = "credential.active") -> Path:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return root / "secrets" / f"secret-{digest}"


@pytest.mark.skipif(os.name != "posix", reason="logical quarantine semantics require POSIX")
def test_encrypted_store_delete_removes_active_name_and_retains_exact_inode(
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    store.put("credential.active", "value")
    secret = _secret_path(tmp_path)
    expected_inode = secret.stat().st_ino

    store.delete("credential.active")

    assert store.get("credential.active") is None
    quarantined = list((tmp_path / "secrets").glob(".secret-quarantine-*"))
    assert len(quarantined) == 1
    assert quarantined[0].stat().st_ino == expected_inode
    assert any("physical_delete_pending" in issue for issue in store.recovery_issues)
    assert store.doctor().status == "DEGRADED"
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="hardlink and symlink semantics require POSIX")
@pytest.mark.parametrize("target", ["master", "secret"])
def test_encrypted_store_rejects_hardlinks(tmp_path: Path, target: str) -> None:
    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    store.put("credential.active", "value")
    path = tmp_path / "secrets" / ".master-key" if target == "master" else _secret_path(tmp_path)
    os.link(path, tmp_path / "secrets" / f"{target}-alias")
    with pytest.raises(SecureStoreUnavailableError):
        store.get("credential.active")
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="symlink semantics require POSIX")
def test_encrypted_store_rejects_symlink_and_bad_permissions(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    store.put("credential.active", "value")
    secret = _secret_path(tmp_path)
    secret.unlink()
    target = tmp_path / "outside"
    target.write_bytes(b"not-a-secret")
    os.chmod(target, 0o600)
    secret.symlink_to(target)
    with pytest.raises(SecureStoreUnavailableError):
        store.get("credential.active")
    secret.unlink()
    store.put("credential.active", "value")
    os.chmod(_secret_path(tmp_path), 0o640)
    with pytest.raises(SecureStoreUnavailableError):
        store.get("credential.active")
    store.close()


@pytest.mark.skipif(
    os.name != "posix" or getattr(os, "geteuid", lambda: 1)() != 0,
    reason="owner mismatch test requires a disposable root container",
)
def test_encrypted_store_rejects_wrong_owner(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    store.put("credential.active", "value")
    os.chown(_secret_path(tmp_path), 1, -1)
    with pytest.raises(SecureStoreUnavailableError):
        store.get("credential.active")
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="atomic replacement semantics require POSIX")
def test_reader_and_writer_serialize_across_processes_without_concurrent_replacement(
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    initial = LinuxEncryptedFileSecretStore(tmp_path)
    initial.put("credential.active", "old")
    active_before = _secret_path(tmp_path).stat(follow_symlinks=False)
    initial.close()
    context = multiprocessing.get_context("spawn")
    reader_entered = context.Event()
    release = context.Event()
    writer_ready = context.Event()
    start_writer = context.Event()
    writer_started = context.Event()
    writer_attempted = context.Event()
    writer_acquired = context.Event()
    writer_completed = context.Event()
    writer_entered = context.Event()
    writer_exchange = context.Event()
    results = context.Queue()
    reader = context.Process(
        target=_blocking_process_get,
        args=(str(tmp_path), reader_entered, release, results),
    )
    writer = context.Process(
        target=_observed_process_put,
        args=(
            str(tmp_path),
            "new",
            writer_ready,
            start_writer,
            writer_started,
            writer_attempted,
            writer_acquired,
            writer_completed,
            writer_entered,
            writer_exchange,
            results,
            5.0,
        ),
    )
    writer.start()
    assert writer_ready.wait(5.0)
    assert not writer_attempted.is_set()
    reader.start()
    assert reader_entered.wait(5.0)
    start_writer.set()
    assert writer_started.wait(5.0)
    assert writer_attempted.wait(5.0)
    try:
        assert not writer_acquired.is_set()
        assert not writer_entered.wait(0.25)
        active_while_locked = _secret_path(tmp_path).stat(follow_symlinks=False)
        assert (active_while_locked.st_dev, active_while_locked.st_ino) == (
            active_before.st_dev,
            active_before.st_ino,
        )
        with pytest.raises(queue_module.Empty):
            results.get(timeout=0.1)
    finally:
        release.set()
    outcomes = {results.get(timeout=10.0), results.get(timeout=10.0)}
    reader.join(10.0)
    writer.join(10.0)

    assert not reader.is_alive()
    assert not writer.is_alive()
    assert reader.exitcode == 0
    assert writer.exitcode == 0
    assert ("reader", "ok", "old") in outcomes
    assert ("writer", "ok", "new", "DEGRADED") in outcomes
    assert writer_entered.is_set()
    assert writer_acquired.is_set()
    assert writer_completed.is_set()
    assert writer_exchange.is_set()
    final = LinuxEncryptedFileSecretStore(tmp_path)
    assert final.get("credential.active") == "new"
    assert not list((tmp_path / "secrets").glob(".pending-*"))
    assert list((tmp_path / "secrets").glob(".secret-quarantine-*"))
    assert (tmp_path / "secrets" / ".store-state").stat().st_size == final._state_file_size
    final.close()


@pytest.mark.skipif(os.name != "posix", reason="flock timeout semantics require POSIX")
def test_process_writer_times_out_behind_reader_without_modifying_filesystem(
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    initial = LinuxEncryptedFileSecretStore(tmp_path)
    initial.put("credential.active", "old")
    active_before = _secret_path(tmp_path).stat(follow_symlinks=False)
    initial.close()
    context = multiprocessing.get_context("spawn")
    holder_entered = context.Event()
    holder_release = context.Event()
    writer_ready = context.Event()
    start_writer = context.Event()
    writer_started = context.Event()
    writer_attempted = context.Event()
    writer_acquired = context.Event()
    writer_completed = context.Event()
    writer_entered = context.Event()
    writer_exchange = context.Event()
    results = context.Queue()
    holder = context.Process(
        target=_process_hold_store_lock,
        args=(str(tmp_path), holder_entered, holder_release, results),
    )
    writer = context.Process(
        target=_observed_process_put,
        args=(
            str(tmp_path),
            "new",
            writer_ready,
            start_writer,
            writer_started,
            writer_attempted,
            writer_acquired,
            writer_completed,
            writer_entered,
            writer_exchange,
            results,
            0.1,
        ),
    )
    writer.start()
    assert writer_ready.wait(5.0)
    assert not writer_attempted.is_set()
    holder.start()
    assert holder_entered.wait(5.0)
    start_writer.set()
    assert writer_started.wait(5.0)
    assert writer_attempted.wait(5.0)
    assert not writer_acquired.is_set()
    writer_result = results.get(timeout=5.0)
    assert writer_completed.is_set()
    holder_release.set()
    holder_result = results.get(timeout=5.0)
    holder.join(10.0)
    writer.join(10.0)

    assert writer_result[0:3] == ("writer", "error", "SecureStoreUnavailableError")
    assert "timed out" in writer_result[3]
    assert holder_result == ("holder", "ok")
    assert not writer_entered.is_set()
    assert not writer_acquired.is_set()
    assert not writer_exchange.is_set()
    assert holder.exitcode == writer.exitcode == 0
    active_after = _secret_path(tmp_path).stat(follow_symlinks=False)
    assert (active_after.st_dev, active_after.st_ino) == (
        active_before.st_dev,
        active_before.st_ino,
    )
    final = LinuxEncryptedFileSecretStore(tmp_path)
    assert final.get("credential.active") == "old"
    assert not list((tmp_path / "secrets").glob(".pending-*"))
    final.close()


@pytest.mark.skipif(os.name != "posix", reason="filesystem integrity semantics require POSIX")
def test_encrypted_store_corruption_fsync_and_error_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    fsync_calls: list[int] = []
    real_fsync = module.os.fsync

    def observed_fsync(descriptor: int) -> None:
        fsync_calls.append(descriptor)
        real_fsync(descriptor)

    monkeypatch.setattr(module.os, "fsync", observed_fsync)
    store.put("credential.active", "value")
    assert len(fsync_calls) >= 2
    secret = _secret_path(tmp_path)
    payload = bytearray(secret.read_bytes())
    payload[-1] ^= 0x01
    secret.write_bytes(payload)
    os.chmod(secret, 0o600)
    with pytest.raises(SecureStoreUnavailableError):
        store.get("credential.active")

    def failed_publication(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("controlled replacement failure")

    monkeypatch.setattr(module, "rename_noreplace", failed_publication)
    with pytest.raises(SecureStoreUnavailableError):
        store.put("credential.other", "value")
    assert not list((tmp_path / "secrets").glob(".pending-*"))
    assert list((tmp_path / "secrets").glob(".secret-quarantine-*"))
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="descriptor close semantics require POSIX")
def test_encrypted_store_read_error_survives_descriptor_close_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    store.put("credential.active", "value")
    real_close = module.os.close
    target_descriptor: int | None = None

    def fail_read(descriptor: int, size: int) -> bytes:
        nonlocal target_descriptor
        del size
        target_descriptor = descriptor
        raise OSError("primary secret read failure")

    def close_then_fail(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor == target_descriptor:
            raise OSError("secondary secret close failure")

    monkeypatch.setattr(module.os, "read", fail_read)
    monkeypatch.setattr(module.os, "close", close_then_fail)

    with pytest.raises(OSError, match="primary secret read failure") as raised:
        store._read_file(_secret_path(tmp_path).name, 4096)

    assert any("secondary secret close failure" in note for note in raised.value.__notes__)
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="logical quarantine semantics require POSIX")
def test_encrypted_store_delete_never_removes_replacement_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    store.put("credential.active", "value")
    secret = _secret_path(tmp_path)
    replacement_content = b"foreign-file-must-survive"
    replacement = tmp_path / "secrets" / ".foreign-secret"
    replacement.write_bytes(replacement_content)
    os.chmod(replacement, 0o600)
    real_quarantine = module.logical_quarantine
    swapped = False

    def swap_before_quarantine(
        identity: object,
        *,
        quarantine_prefix: str,
        primary_error: BaseException | None = None,
    ) -> object:
        nonlocal swapped
        if not swapped and getattr(identity, "relative_name", "").startswith("secret-"):
            swapped = True
            os.replace(replacement, secret)
        return real_quarantine(  # type: ignore[arg-type]
            identity,
            quarantine_prefix=quarantine_prefix,
            primary_error=primary_error,
        )

    monkeypatch.setattr(module, "logical_quarantine", swap_before_quarantine)

    with pytest.raises(SecureStoreUnavailableError, match="deletion failed"):
        store.delete("credential.active")

    assert swapped
    assert secret.read_bytes() == replacement_content
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="logical quarantine semantics require POSIX")
def test_new_master_key_cleanup_preserves_a_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    os.chmod(tmp_path, 0o700)
    replacement_key = b"r" * 32
    primary = SecureStoreUnavailableError("primary master key read failure")
    real_read = LinuxEncryptedFileSecretStore._read_file
    master_reads = 0

    def replace_then_fail(
        self: LinuxEncryptedFileSecretStore,
        name: str,
        maximum_bytes: int,
    ) -> bytes:
        nonlocal master_reads
        if name != ".master-key":
            return real_read(self, name, maximum_bytes)
        master_reads += 1
        if master_reads == 1:
            return real_read(self, name, maximum_bytes)
        replacement = self._root / ".replacement-master"
        replacement.write_bytes(replacement_key)
        os.chmod(replacement, 0o600)
        os.replace(replacement, self._root / name)
        raise primary

    monkeypatch.setattr(LinuxEncryptedFileSecretStore, "_read_file", replace_then_fail)

    with pytest.raises(SecureStoreUnavailableError) as raised:
        LinuxEncryptedFileSecretStore(tmp_path)

    assert raised.value is primary
    assert (tmp_path / "secrets" / ".master-key").read_bytes() == replacement_key
    assert any("manual filesystem recovery" in note for note in primary.__notes__)


@pytest.mark.skipif(os.name != "posix", reason="logical quarantine semantics require POSIX")
def test_failed_secret_put_leaves_replaced_temporary_for_manual_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    real_rename = module.rename_noreplace
    foreign_content = b"foreign-temporary"

    def replace_temporary_then_fail(
        source_dir_fd: int,
        source: str,
        destination_dir_fd: int,
        destination: str,
    ) -> None:
        del destination, destination_dir_fd
        os.rename(
            source,
            ".expected-temporary",
            src_dir_fd=source_dir_fd,
            dst_dir_fd=source_dir_fd,
        )
        foreign = store._root / ".foreign-temporary"
        foreign.write_bytes(foreign_content)
        os.chmod(foreign, 0o600)
        real_rename(
            source_dir_fd,
            foreign.name,
            source_dir_fd,
            source,
        )
        raise OSError("controlled secret publication failure")

    monkeypatch.setattr(module, "rename_noreplace", replace_temporary_then_fail)

    with pytest.raises(SecureStoreUnavailableError, match="write failed") as raised:
        store.put("credential.other", "value")

    temporaries = list((tmp_path / "secrets").glob(".pending-*"))
    assert len(temporaries) == 1
    assert temporaries[0].read_bytes() == foreign_content
    assert any("manual filesystem recovery" in note for note in raised.value.__notes__)
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="secret publication requires POSIX")
def test_new_secret_final_must_match_retained_temporary_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    real_publish = module.rename_noreplace
    observed = False

    def replace_before_publish(
        source_dir_fd: int,
        source: str,
        destination_dir_fd: int,
        destination: str,
    ) -> None:
        nonlocal observed
        if not source.startswith(".pending-"):
            real_publish(source_dir_fd, source, destination_dir_fd, destination)
            return
        observed = True
        payload = (store._root / source).read_bytes()
        os.rename(
            source,
            ".retained-original-temporary",
            src_dir_fd=source_dir_fd,
            dst_dir_fd=source_dir_fd,
        )
        replacement = os.open(
            source,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=source_dir_fd,
        )
        try:
            os.write(replacement, payload)
            os.fsync(replacement)
        finally:
            os.close(replacement)
        real_publish(source_dir_fd, source, destination_dir_fd, destination)

    monkeypatch.setattr(module, "rename_noreplace", replace_before_publish)

    with pytest.raises(SecureStoreUnavailableError, match="retained temporary identity"):
        store.put("credential.active", "value")

    assert observed
    assert (store._root / ".retained-original-temporary").exists()
    assert _secret_path(tmp_path).exists()
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="secret publication requires POSIX")
def test_secret_update_uses_exchange_and_quarantines_previous_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    store.put("credential.active", "old")
    old_inode = _secret_path(tmp_path).stat().st_ino
    real_exchange = module.rename_exchange
    exchanges: list[tuple[str, str]] = []

    def tracked_exchange(
        source_dir_fd: int,
        source: str,
        destination_dir_fd: int,
        destination: str,
    ) -> None:
        exchanges.append((source, destination))
        real_exchange(source_dir_fd, source, destination_dir_fd, destination)

    monkeypatch.setattr(module, "rename_exchange", tracked_exchange)
    store.put("credential.active", "new")

    quarantined = list((tmp_path / "secrets").glob(".secret-quarantine-*"))
    assert exchanges
    assert store.get("credential.active") == "new"
    assert any(path.stat().st_ino == old_inode for path in quarantined)
    assert store.doctor().status == "DEGRADED"
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="secret publication requires POSIX")
def test_secret_update_rolls_back_when_final_validation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    store.put("credential.active", "old")

    def reject_final(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise SecureStoreUnavailableError("controlled final validation failure")

    monkeypatch.setattr(store, "_validate_published_secret", reject_final)
    with pytest.raises(SecureStoreUnavailableError, match="controlled final validation"):
        store.put("credential.active", "new")

    assert store.get("credential.active") == "old"
    assert list((tmp_path / "secrets").glob(".secret-quarantine-*"))
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="multiprocess rollback requires POSIX")
def test_verified_exchange_rollback_holds_flock_until_second_process_can_update(
    tmp_path: Path,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    initial = LinuxEncryptedFileSecretStore(tmp_path)
    initial.put("credential.active", "OLD")
    old_identity = _secret_path(tmp_path).stat(follow_symlinks=False)
    initial.close()
    context = multiprocessing.get_context("spawn")
    exchanged = context.Event()
    release = context.Event()
    writer_ready = context.Event()
    start_writer = context.Event()
    writer_started = context.Event()
    writer_attempted = context.Event()
    writer_acquired = context.Event()
    writer_completed = context.Event()
    writer_entered = context.Event()
    writer_exchange = context.Event()
    results = context.Queue()
    rollback = context.Process(
        target=_rollback_process_put,
        args=(str(tmp_path), exchanged, release, results, False),
    )
    writer = context.Process(
        target=_observed_process_put,
        args=(
            str(tmp_path),
            "NEW_B",
            writer_ready,
            start_writer,
            writer_started,
            writer_attempted,
            writer_acquired,
            writer_completed,
            writer_entered,
            writer_exchange,
            results,
            5.0,
        ),
    )
    writer.start()
    assert writer_ready.wait(5.0)
    assert not writer_attempted.is_set()
    rollback.start()
    assert exchanged.wait(5.0)
    exchanged_identity = _secret_path(tmp_path).stat(follow_symlinks=False)
    assert (exchanged_identity.st_dev, exchanged_identity.st_ino) != (
        old_identity.st_dev,
        old_identity.st_ino,
    )
    start_writer.set()
    assert writer_started.wait(5.0)
    assert writer_attempted.wait(5.0)
    try:
        assert not writer_acquired.is_set()
        assert not writer_entered.wait(0.25)
        assert not writer_exchange.is_set()
        still_exchanged = _secret_path(tmp_path).stat(follow_symlinks=False)
        assert (still_exchanged.st_dev, still_exchanged.st_ino) == (
            exchanged_identity.st_dev,
            exchanged_identity.st_ino,
        )
    finally:
        release.set()
    outcomes = {results.get(timeout=10.0), results.get(timeout=10.0)}
    rollback.join(10.0)
    writer.join(10.0)

    assert not rollback.is_alive()
    assert not writer.is_alive()
    assert rollback.exitcode == writer.exitcode == 0
    rollback_result = next(result for result in outcomes if result[0] == "rollback")
    writer_result = next(result for result in outcomes if result[0] == "writer")
    assert rollback_result[1:5] == (
        "error",
        "SecureStoreUnavailableError",
        "controlled final validation failure",
        2,
    )
    assert writer_result == ("writer", "ok", "NEW_B", "DEGRADED")
    assert writer_entered.is_set()
    assert writer_acquired.is_set()
    assert writer_completed.is_set()
    assert writer_exchange.is_set()
    final = LinuxEncryptedFileSecretStore(tmp_path)
    assert final.get("credential.active") == "NEW_B"
    assert final._read_store_state().state is module._StoreHealth.HEALTHY
    assert not (tmp_path / "secrets" / ".store-manual-recovery").exists()
    assert not list((tmp_path / "secrets").glob(".pending-*"))
    final.close()


@pytest.mark.skipif(os.name != "posix", reason="multiprocess rollback requires POSIX")
def test_unverified_exchange_rollback_poisons_before_waiting_process_enters(
    tmp_path: Path,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    initial = LinuxEncryptedFileSecretStore(tmp_path)
    initial.put("credential.active", "OLD")
    initial.close()
    context = multiprocessing.get_context("spawn")
    exchanged = context.Event()
    release = context.Event()
    writer_ready = context.Event()
    start_writer = context.Event()
    writer_started = context.Event()
    writer_attempted = context.Event()
    writer_acquired = context.Event()
    writer_completed = context.Event()
    writer_entered = context.Event()
    writer_exchange = context.Event()
    results = context.Queue()
    rollback = context.Process(
        target=_rollback_process_put,
        args=(str(tmp_path), exchanged, release, results, True),
    )
    writer = context.Process(
        target=_observed_process_put,
        args=(
            str(tmp_path),
            "NEW_B",
            writer_ready,
            start_writer,
            writer_started,
            writer_attempted,
            writer_acquired,
            writer_completed,
            writer_entered,
            writer_exchange,
            results,
            5.0,
        ),
    )
    writer.start()
    assert writer_ready.wait(5.0)
    assert not writer_attempted.is_set()
    rollback.start()
    assert exchanged.wait(5.0)
    start_writer.set()
    assert writer_started.wait(5.0)
    assert writer_attempted.wait(5.0)
    assert not writer_acquired.is_set()
    assert not writer_entered.wait(0.25)
    release.set()
    outcomes = {results.get(timeout=10.0), results.get(timeout=10.0)}
    rollback.join(10.0)
    writer.join(10.0)

    assert rollback.exitcode == writer.exitcode == 0
    rollback_result = next(result for result in outcomes if result[0] == "rollback")
    writer_result = next(result for result in outcomes if result[0] == "writer")
    assert rollback_result[1] == "error"
    assert rollback_result[4:] == (2, "BLOCKED")
    assert writer_result[0:3] == ("writer", "error", "SecureStoreUnavailableError")
    assert "manual recovery" in writer_result[3]
    assert writer_result[4] == "BLOCKED"
    assert not writer_entered.is_set()
    assert writer_acquired.is_set()
    assert writer_completed.is_set()
    assert not writer_exchange.is_set()
    assert (tmp_path / "secrets" / ".store-manual-recovery").is_file()
    assert list((tmp_path / "secrets").glob(".pending-*"))
    blocked = LinuxEncryptedFileSecretStore(tmp_path)
    assert blocked._read_store_state().state is module._StoreHealth.POISONED
    assert blocked.doctor().status == "BLOCKED"
    with pytest.raises(SecureStoreUnavailableError, match="manual recovery"):
        blocked.get("credential.active")
    blocked.close()


@pytest.mark.skipif(os.name != "posix", reason="multiprocess fail-stop requires POSIX")
def test_partial_poison_and_marker_failure_release_lock_but_restart_stays_blocked(
    tmp_path: Path,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    initial = LinuxEncryptedFileSecretStore(tmp_path)
    initial.put("credential.active", "OLD")
    initial.close()
    context = multiprocessing.get_context("spawn")
    fatal = context.Event()
    release = context.Event()
    writer_ready = context.Event()
    start_writer = context.Event()
    writer_started = context.Event()
    writer_attempted = context.Event()
    writer_acquired = context.Event()
    writer_completed = context.Event()
    writer_entered = context.Event()
    writer_exchange = context.Event()
    results = context.Queue()
    poisoned = context.Process(
        target=_poison_persistence_failure_process,
        args=(str(tmp_path), fatal, release, results),
    )
    writer = context.Process(
        target=_observed_process_put,
        args=(
            str(tmp_path),
            "NEW_B",
            writer_ready,
            start_writer,
            writer_started,
            writer_attempted,
            writer_acquired,
            writer_completed,
            writer_entered,
            writer_exchange,
            results,
            0.15,
        ),
    )
    writer.start()
    assert writer_ready.wait(5.0)
    assert not writer_attempted.is_set()
    poisoned.start()
    assert fatal.wait(5.0)
    fatal_result = results.get(timeout=5.0)
    start_writer.set()
    assert writer_started.wait(5.0)
    assert writer_attempted.wait(5.0)
    writer_result = results.get(timeout=5.0)
    assert fatal_result[0:3] == ("fatal", "error", "SecureStoreUnavailableError")
    assert fatal_result[3] == "controlled final validation failure"
    assert writer_result[0:3] == ("writer", "error", "SecureStoreUnavailableError")
    assert "state is corrupt" in writer_result[3]
    assert writer_acquired.is_set()
    assert writer_completed.is_set()
    assert not writer_entered.is_set()
    assert not writer_exchange.is_set()
    release.set()
    poisoned.join(10.0)
    writer.join(10.0)
    assert poisoned.exitcode == writer.exitcode == 0
    assert not (tmp_path / "secrets" / ".store-manual-recovery").exists()
    blocked = LinuxEncryptedFileSecretStore(tmp_path)
    slots = blocked._read_store_state_slots()
    assert any(slot is not None and slot.state is module._StoreHealth.MUTATING for slot in slots)
    assert blocked.doctor().status == "BLOCKED"
    assert blocked.doctor().detail.startswith("BLOCKED_STATE_CORRUPT")
    with pytest.raises(SecureStoreUnavailableError, match="state is corrupt"):
        blocked.put("credential.active", "must-not-run")
    blocked.close()


@pytest.mark.skipif(os.name != "posix", reason="secret publication requires POSIX")
def test_secret_update_without_rename_exchange_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    store.put("credential.active", "old")
    monkeypatch.setattr(
        module,
        "rename_exchange",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            SecureFilesystemUnavailableError("RENAME_EXCHANGE unavailable")
        ),
    )

    with pytest.raises(SecureFilesystemUnavailableError, match="RENAME_EXCHANGE"):
        store.put("credential.active", "new")

    assert store.get("credential.active") == "old"
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="secret publication requires POSIX")
def test_secret_exchange_rollback_failure_requires_manual_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.linux import secret_store as module

    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    store.put("credential.active", "old")
    second = LinuxEncryptedFileSecretStore(tmp_path)
    real_exchange = module.rename_exchange
    calls = 0

    def fail_inverse_exchange(
        source_dir_fd: int,
        source: str,
        destination_dir_fd: int,
        destination: str,
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            real_exchange(source_dir_fd, source, destination_dir_fd, destination)
            return
        raise OSError("controlled inverse exchange failure")

    def reject_final(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise SecureStoreUnavailableError("controlled final validation failure")

    monkeypatch.setattr(module, "rename_exchange", fail_inverse_exchange)
    monkeypatch.setattr(store, "_validate_published_secret", reject_final)

    with pytest.raises(SecureStoreUnavailableError) as raised:
        store.put("credential.active", "new")

    assert any("manual recovery" in note for note in raised.value.__notes__)
    assert calls == 2
    assert (tmp_path / "secrets" / ".store-manual-recovery").is_file()
    assert store.doctor().status == "BLOCKED"
    with pytest.raises(SecureStoreUnavailableError, match="manual recovery"):
        second.put("credential.active", "must-not-run")
    with pytest.raises(SecureStoreUnavailableError, match="manual recovery"):
        second.get("credential.active")
    second.close()
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="secret cryptography requires POSIX fixture")
def test_secret_ciphertext_plaintext_and_tag_self_checks_are_fail_closed(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    nonce = os.urandom(12)
    encrypted = nonce + store._aesgcm(store._master_key).encrypt(
        nonce,
        b"different",
        b"credential.active",
    )

    with pytest.raises(SecureStoreUnavailableError, match="plaintext self-check"):
        store._validate_ciphertext(
            encrypted,
            key="credential.active",
            expected_plaintext=b"requested",
        )
    corrupted = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
    with pytest.raises(SecureStoreUnavailableError, match="validation failed"):
        store._validate_ciphertext(
            corrupted,
            key="credential.active",
            expected_plaintext=b"different",
        )
    store.close()
