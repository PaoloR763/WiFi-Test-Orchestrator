from __future__ import annotations

from typing import Any, cast

import pytest
from conftest import FakeClock

from wto_desktop_agent import __version__
from wto_desktop_agent.application.capabilities import CapabilityRegistry, ManifestService
from wto_desktop_agent.application.runtime import AgentRuntime
from wto_desktop_agent.domain.errors import TransportError
from wto_desktop_agent.infrastructure.backoff import BackoffPolicy
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore

_AGENT_ID = "40000000-0000-4000-8000-000000000001"


class _OrderedPlatform:
    platform_id = "linux"

    def __init__(self, events: list[str], *, platform_version: str = "test-linux-1") -> None:
        self.events = events
        self.platform_version = platform_version
        self.overrides: dict[str, dict[str, object]] = {}

    def capability_overrides(self) -> dict[str, dict[str, object]]:
        raise AssertionError("the async manifest path must be used")

    async def capability_overrides_async(self) -> dict[str, dict[str, object]]:
        self.events.append("live_capability_probe")
        return self.overrides


class _ManifestTransport:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.fail_next = False

    async def publish_manifest(
        self, _credential: str, _payload: dict[str, object]
    ) -> dict[str, object]:
        self.events.append("publish_manifest")
        if self.fail_next:
            self.fail_next = False
            raise TransportError("synthetic manifest acknowledgement loss")
        return {"manifest_digest": "a" * 64}


class _Identity:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def active_credential_async(self) -> str:
        self.events.append("identity")
        return "credential"

    async def mark_revoked_async(self) -> None:
        self.events.append("revoked")


class _Heartbeat:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def send(self, _credential: str) -> dict[str, object]:
        self.events.append("heartbeat")
        return {}


class _OrderedScheduler:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def run_persisted_once(self) -> None:
        self.events.append("persisted_binding_result")

    async def run_once(self) -> None:
        self.events.append("fetch_exact_binding_retry")
        self.events.append("publish_bound_result")

    async def shutdown(self) -> None:
        return None


def _prepare_runtime_store(store: SQLiteStore) -> None:
    store.ensure_identity(
        installation_id="30000000-0000-4000-8000-000000000001",
        display_name="runtime-order-test",
        platform="linux",
        platform_version="test-linux-1",
        agent_version=__version__,
        enrollment_idempotency_key="50000000-0000-4000-8000-000000000001",
        enrollment_reported_at="2026-07-18T12:00:00Z",
    )
    store.update_identity(
        {
            "agent_id": _AGENT_ID,
            "protocol_version": "1.0.0",
            "rotation_state": "none",
        }
    )
    store.start_runtime("60000000-0000-4000-8000-000000000001")


def _runtime(
    store: SQLiteStore,
    manifests: ManifestService,
    events: list[str],
) -> AgentRuntime:
    return AgentRuntime(
        store,
        cast(Any, _Identity(events)),
        manifests,
        cast(Any, _Heartbeat(events)),
        FakeClock(),
        heartbeat_interval_seconds=30.0,
        backoff=BackoffPolicy(1.0, 60.0, 2.0, 0.2),
        random_source=cast(Any, object()),
        scheduler=cast(Any, _OrderedScheduler(events)),
    )


def _manifest_service(
    store: SQLiteStore,
    platform: _OrderedPlatform,
    transport: _ManifestTransport,
) -> ManifestService:
    return ManifestService(
        store,
        CapabilityRegistry(cast(Any, platform)),
        cast(Any, transport),
        cast(Any, platform),
        FakeClock(),
    )


@pytest.mark.asyncio
async def test_runtime_requires_bootstrap_and_never_initializes_sqlite() -> None:
    events: list[str] = []

    class InitializedStore:
        def initialize(self) -> None:
            raise AssertionError("runtime must not initialize SQLite")

        def recover_interrupted(self) -> int:
            events.append("recover")
            return 0

        def start_runtime(self, _boot_id: str) -> None:
            events.append("start")

        def identity(self) -> None:
            return None

        def stop_runtime(self) -> None:
            events.append("stop")

    runtime = AgentRuntime(
        cast(Any, InitializedStore()),
        cast(Any, object()),
        cast(Any, object()),
        cast(Any, object()),
        cast(Any, object()),
        heartbeat_interval_seconds=30.0,
        backoff=BackoffPolicy(1.0, 60.0, 2.0, 0.2),
        random_source=cast(Any, object()),
    )

    await runtime.start()
    await runtime.shutdown()

    assert events == ["recover", "start", "stop"]


@pytest.mark.asyncio
async def test_confirmed_manifest_delivers_fetched_exact_binding_before_live_refresh(
    store: SQLiteStore,
) -> None:
    events: list[str] = []
    _prepare_runtime_store(store)
    platform = _OrderedPlatform(events)
    transport = _ManifestTransport(events)
    manifests = _manifest_service(store, platform, transport)
    await manifests.ensure_published("credential")
    events.clear()
    platform.overrides = {
        "wifi.connection.read": {"implementation_status": {"status": "implemented", "reason": None}}
    }

    await _runtime(store, manifests, events).cycle()

    assert events == [
        "identity",
        "heartbeat",
        "fetch_exact_binding_retry",
        "publish_bound_result",
        "live_capability_probe",
        "publish_manifest",
    ]
    assert events.index("publish_bound_result") < events.index("live_capability_probe")
    rows = store.rows("capability_manifests")
    assert [row["state"] for row in rows] == ["confirmed", "confirmed"]


@pytest.mark.asyncio
async def test_initial_manifest_is_live_and_confirmed_before_fetch(
    store: SQLiteStore,
) -> None:
    events: list[str] = []
    _prepare_runtime_store(store)
    platform = _OrderedPlatform(events)
    transport = _ManifestTransport(events)

    await _runtime(store, _manifest_service(store, platform, transport), events).cycle()

    assert events == [
        "identity",
        "live_capability_probe",
        "publish_manifest",
        "heartbeat",
        "fetch_exact_binding_retry",
        "publish_bound_result",
    ]
    assert store.confirmed_manifest() is not None


@pytest.mark.asyncio
async def test_static_manifest_change_refreshes_before_fetch(
    store: SQLiteStore,
) -> None:
    events: list[str] = []
    _prepare_runtime_store(store)
    platform = _OrderedPlatform(events)
    transport = _ManifestTransport(events)
    manifests = _manifest_service(store, platform, transport)
    await manifests.ensure_published("credential")
    events.clear()
    platform.platform_version = "test-linux-2"

    await _runtime(store, manifests, events).cycle()

    assert events == [
        "identity",
        "live_capability_probe",
        "publish_manifest",
        "heartbeat",
        "fetch_exact_binding_retry",
        "publish_bound_result",
    ]


@pytest.mark.asyncio
async def test_compatible_pending_manifest_retries_before_fetch_then_refreshes(
    store: SQLiteStore,
) -> None:
    events: list[str] = []
    _prepare_runtime_store(store)
    platform = _OrderedPlatform(events)
    transport = _ManifestTransport(events)
    manifests = _manifest_service(store, platform, transport)
    transport.fail_next = True
    with pytest.raises(TransportError):
        await manifests.ensure_published("credential")
    assert store.pending_manifest() is not None
    events.clear()

    await _runtime(store, manifests, events).cycle()

    assert events == [
        "identity",
        "publish_manifest",
        "heartbeat",
        "fetch_exact_binding_retry",
        "publish_bound_result",
        "live_capability_probe",
    ]


@pytest.mark.asyncio
async def test_incompatible_pending_manifest_refreshes_live_before_fetch(
    store: SQLiteStore,
) -> None:
    events: list[str] = []
    _prepare_runtime_store(store)
    platform = _OrderedPlatform(events)
    transport = _ManifestTransport(events)
    manifests = _manifest_service(store, platform, transport)
    transport.fail_next = True
    with pytest.raises(TransportError):
        await manifests.ensure_published("credential")
    platform.platform_version = "test-linux-2"
    events.clear()

    await _runtime(store, manifests, events).cycle()

    assert events == [
        "identity",
        "publish_manifest",
        "live_capability_probe",
        "publish_manifest",
        "heartbeat",
        "fetch_exact_binding_retry",
        "publish_bound_result",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("corruption", ["payload_hash", "manifest_id"])
async def test_corrupt_confirmed_manifest_fails_closed_before_fetch(
    store: SQLiteStore,
    corruption: str,
) -> None:
    events: list[str] = []
    _prepare_runtime_store(store)
    platform = _OrderedPlatform(events)
    transport = _ManifestTransport(events)
    manifests = _manifest_service(store, platform, transport)
    await manifests.ensure_published("credential")
    with store.connection() as connection:
        if corruption == "payload_hash":
            connection.execute(
                "UPDATE capability_manifests SET payload_hash=? WHERE state='confirmed'",
                ("b" * 64,),
            )
        else:
            connection.execute(
                "UPDATE capability_manifests "
                "SET manifest_id='70000000-0000-4000-8000-000000000001' "
                "WHERE state='confirmed'"
            )
        connection.commit()
    events.clear()

    with pytest.raises(RuntimeError, match="durable capability manifest identity is invalid"):
        await _runtime(store, manifests, events).cycle()

    assert events == ["identity"]
