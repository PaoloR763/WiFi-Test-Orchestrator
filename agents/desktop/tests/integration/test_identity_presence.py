from __future__ import annotations

from pathlib import Path

import pytest
from conftest import FakeClock

from wto_desktop_agent.application.capabilities import (
    CapabilityRegistry,
    ManifestService,
)
from wto_desktop_agent.application.heartbeat import HeartbeatService
from wto_desktop_agent.application.identity import IdentityManager
from wto_desktop_agent.domain.errors import SecureStoreUnavailableError, TransportError
from wto_desktop_agent.infrastructure.simulated_transport import SimulatedAgentTransport
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.platforms.simulated.adapter import SimulatedPlatformAdapter

TOKEN = "wto_enr_1.10000000-0000-4000-8000-000000000001." + "T" * 43


async def enrolled(
    tmp_path: Path, transport: SimulatedAgentTransport | None = None
) -> tuple[SQLiteStore, SimulatedPlatformAdapter, SimulatedAgentTransport, IdentityManager]:
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    store.initialize()
    platform = SimulatedPlatformAdapter()
    actual_transport = transport or SimulatedAgentTransport()
    manager = IdentityManager(
        store,
        platform,
        actual_transport,
        FakeClock(),
        allow_insecure_development_store=True,
    )
    await manager.enroll(token=TOKEN, display_name="desktop test")
    return store, platform, actual_transport, manager


@pytest.mark.asyncio
async def test_enrollment_keeps_secrets_out_of_sqlite(tmp_path: Path) -> None:
    store, platform, transport, manager = await enrolled(tmp_path)
    credential = manager.active_credential()
    sqlite_bytes = b"".join(
        path.read_bytes()
        for path in store.path.parent.glob(store.path.name + "*")
        if path.is_file()
    )
    assert TOKEN.encode() not in sqlite_bytes
    assert credential.encode() not in sqlite_bytes
    identity = store.identity()
    assert identity is not None
    assert identity["active_credential_fingerprint"] in sqlite_bytes.decode("latin1")
    assert platform.secret_store.get(str(identity["active_credential_ref"])) == credential
    assert transport.calls[0][0] == "enroll"


class EnrollmentAcceptedThenDisconnected(SimulatedAgentTransport):
    failed = False

    async def enroll(self, payload, idempotency_key):  # type: ignore[no-untyped-def]
        response = await super().enroll(payload, idempotency_key)
        if not self.failed:
            self.failed = True
            raise TransportError("synthetic enrollment ack loss")
        return response


@pytest.mark.asyncio
async def test_enrollment_retry_reuses_exact_payload_and_key(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    store.initialize()
    platform = SimulatedPlatformAdapter()
    transport = EnrollmentAcceptedThenDisconnected()
    manager = IdentityManager(
        store,
        platform,
        transport,
        FakeClock(),
        allow_insecure_development_store=True,
    )
    with pytest.raises(TransportError):
        await manager.enroll(token=TOKEN, display_name="desktop test")
    await manager.enroll(token=TOKEN, display_name="desktop test")
    calls = [payload for name, payload in transport.calls if name == "enroll"]
    assert len(calls) == 2 and calls[0] == calls[1]


@pytest.mark.asyncio
async def test_enrollment_fails_closed_without_secure_or_explicit_dev_store(
    tmp_path: Path,
) -> None:
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    store.initialize()
    manager = IdentityManager(
        store, SimulatedPlatformAdapter(), SimulatedAgentTransport(), FakeClock()
    )
    with pytest.raises(SecureStoreUnavailableError):
        await manager.enroll(token=TOKEN, display_name="blocked")


@pytest.mark.asyncio
async def test_confirmed_revocation_removes_all_local_secret_references(
    tmp_path: Path,
) -> None:
    store, platform, _, manager = await enrolled(tmp_path)
    identity = store.identity()
    assert identity is not None
    reference = str(identity["active_credential_ref"])
    assert platform.secret_store.get(reference) is not None
    manager.mark_revoked()
    assert platform.secret_store.get(reference) is None
    assert store.identity()["rotation_state"] == "revoked"  # type: ignore[index]


class CreateAcceptedThenDisconnected(SimulatedAgentTransport):
    failed = False

    async def create_rotation(self, credential, payload, idempotency_key):  # type: ignore[no-untyped-def]
        response = await super().create_rotation(credential, payload, idempotency_key)
        if not self.failed:
            self.failed = True
            raise TransportError("synthetic disconnect")
        return response


class ActivationAcceptedThenDisconnected(SimulatedAgentTransport):
    failed = False

    async def activate_rotation(self, credential, rotation_id, payload, idempotency_key):  # type: ignore[no-untyped-def]
        response = await super().activate_rotation(
            credential, rotation_id, payload, idempotency_key
        )
        if not self.failed:
            self.failed = True
            raise TransportError("synthetic disconnect")
        return response


class ActivationDisconnectedBeforeServer(SimulatedAgentTransport):
    failed = False

    async def activate_rotation(  # type: ignore[no-untyped-def]
        self, credential, rotation_id, payload, idempotency_key
    ):
        if not self.failed:
            self.failed = True
            raise TransportError("synthetic disconnect before activation")
        return await super().activate_rotation(credential, rotation_id, payload, idempotency_key)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "transport_type",
    [
        CreateAcceptedThenDisconnected,
        ActivationDisconnectedBeforeServer,
        ActivationAcceptedThenDisconnected,
    ],
)
async def test_rotation_recovers_after_response_boundaries(
    tmp_path: Path, transport_type: type[SimulatedAgentTransport]
) -> None:
    transport = transport_type()
    store, platform, _, manager = await enrolled(tmp_path, transport)
    old = manager.active_credential()
    with pytest.raises(TransportError):
        await manager.rotate()
    state_after_failure = store.identity()
    assert state_after_failure is not None
    assert state_after_failure["rotation_state"] in {
        "requested",
        "activation_uncertain",
    }
    await manager.rotate()
    new = manager.active_credential()
    assert new != old
    final = store.identity()
    assert final is not None and final["rotation_state"] == "none"
    assert final["pending_credential_ref"] is None
    assert old not in platform.secret_store._values.values()
    database = store.path.read_bytes()
    assert old.encode() not in database and new.encode() not in database


@pytest.mark.asyncio
async def test_rotation_finalizes_old_secret_after_local_cutover_crash(
    tmp_path: Path,
) -> None:
    store, platform, _, manager = await enrolled(tmp_path)
    old = manager.active_credential()
    await manager.rotate()
    current = store.identity()
    assert current is not None
    active_ref = str(current["active_credential_ref"])
    old_ref = "credential.orphan.old"
    platform.secret_store.put(old_ref, old)
    store.update_identity(
        {
            "previous_credential_id": "old-id",
            "previous_credential_ref": old_ref,
            "rotation_state": "activated",
        }
    )
    await manager.rotate()
    assert platform.secret_store.get(old_ref) is None
    assert platform.secret_store.get(active_ref) == manager.active_credential()


class ManifestAckLost(SimulatedAgentTransport):
    failed = False

    async def publish_manifest(self, credential, payload):  # type: ignore[no-untyped-def]
        response = await super().publish_manifest(credential, payload)
        if not self.failed:
            self.failed = True
            raise TransportError("synthetic manifest ack loss")
        return response


class HeartbeatAckLost(SimulatedAgentTransport):
    heartbeat_failed = False

    async def heartbeat(self, credential, payload):  # type: ignore[no-untyped-def]
        response = await super().heartbeat(credential, payload)
        if not self.heartbeat_failed:
            self.heartbeat_failed = True
            raise TransportError("synthetic heartbeat ack loss")
        return response


@pytest.mark.asyncio
async def test_manifest_retry_uses_identical_id_sequence_and_payload(
    tmp_path: Path,
) -> None:
    transport = ManifestAckLost()
    store, platform, _, manager = await enrolled(tmp_path, transport)
    store.start_runtime("30000000-0000-4000-8000-000000000001")
    service = ManifestService(store, CapabilityRegistry(platform), transport, platform, FakeClock())
    with pytest.raises(TransportError):
        await service.ensure_published(manager.active_credential())
    pending = store.pending_manifest()
    assert pending is not None
    await service.ensure_published(manager.active_credential())
    calls = [body for name, body in transport.calls if name == "publish_manifest"]
    assert len(calls) == 2 and calls[0] == calls[1]
    assert calls[0]["manifest_sequence"] == 0
    assert store.pending_manifest() is None


@pytest.mark.asyncio
async def test_heartbeat_retry_uses_identical_sequence_and_payload(
    tmp_path: Path,
) -> None:
    transport = HeartbeatAckLost()
    store, platform, _, manager = await enrolled(tmp_path, transport)
    store.start_runtime("30000000-0000-4000-8000-000000000001")
    credential = manager.active_credential()
    await ManifestService(
        store, CapabilityRegistry(platform), transport, platform, FakeClock()
    ).ensure_published(credential)
    service = HeartbeatService(store, transport, FakeClock())
    with pytest.raises(TransportError):
        await service.send(credential)
    pending = store.pending_heartbeat()
    assert pending is not None
    await service.send(credential)
    calls = [body for name, body in transport.calls if name == "heartbeat"]
    assert len(calls) == 2 and calls[0] == calls[1]
    assert calls[0]["sequence"] == 0
    assert store.pending_heartbeat() is None
    assert store.runtime_state()["heartbeat_acked_sequence"] == 0  # type: ignore[index]
