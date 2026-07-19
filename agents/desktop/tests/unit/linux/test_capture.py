from __future__ import annotations

import asyncio
import errno
import gc
import hashlib
import json
import os
import stat
from pathlib import Path
from uuid import UUID

import pytest

import wto_desktop_agent.platforms.linux.capture as capture_module
from wto_desktop_agent.application.artifacts import StagedArtifact
from wto_desktop_agent.config import AgentSettings
from wto_desktop_agent.platforms.linux.capability_manifest import (
    linux_capability_overrides,
)
from wto_desktop_agent.platforms.linux.capture import (
    CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE,
    MONITOR_CAPTURE_CAPABILITY,
    CaptureCoordinator,
    CaptureOperationError,
    CaptureRequest,
    CaptureWorkspace,
    FileCaptureJournal,
    InterfaceState,
    PrivilegedAuthorizationDecision,
    SimulatedCaptureBackend,
    UnavailableControlPlaneAuthorization,
)
from wto_desktop_agent.platforms.linux.secure_fs import (
    FileIdentity,
    SecureQuarantineError,
)
from wto_desktop_agent.platforms.linux.tooling import ToolStatus
from wto_desktop_agent.ports.plugins import CancellationToken

TASK_ID = UUID("10000000-0000-4000-8000-000000000001")
EXECUTION_ID = UUID("20000000-0000-4000-8000-000000000001")
IDEMPOTENCY_KEY = UUID("30000000-0000-4000-8000-000000000001")
AGENT_ID = "40000000-0000-4000-8000-000000000001"
CONNECTION_UUID = "50000000-0000-4000-8000-000000000001"

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux capture filesystem semantics")


class StaticGrantAuthorization:
    def __init__(
        self,
        agent_id: str = AGENT_ID,
        capabilities: frozenset[str] = frozenset({MONITOR_CAPTURE_CAPABILITY}),
    ) -> None:
        self.agent_id = agent_id
        self.capabilities = capabilities

    def authorize(
        self, *, agent_id: str | None, capability_id: str
    ) -> PrivilegedAuthorizationDecision:
        allowed = agent_id == self.agent_id and capability_id in self.capabilities
        return PrivilegedAuthorizationDecision(
            allowed,
            None if allowed else CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE,
        )


class RecordingStager:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root
        self.values: list[tuple[dict[str, object], Path, UUID]] = []
        self.persisted: dict[str, tuple[StagedArtifact, UUID]] = {}

    async def find_existing(
        self,
        identity: dict[str, object],
        task_id: UUID,
        *,
        cancellation: CancellationToken,
    ) -> StagedArtifact | None:
        del cancellation
        artifact_id = identity.get("artifact_id")
        if not isinstance(artifact_id, str):
            return None
        persisted = self.persisted.get(artifact_id)
        if persisted is None:
            return None
        staged, persisted_task_id = persisted
        if persisted_task_id != task_id:
            raise RuntimeError("artifact idempotency conflict: task_id")
        for field_name in (
            "schema_version",
            "artifact_id",
            "execution_id",
            "artifact_type",
            "media_type",
            "idempotency_key",
        ):
            if staged.manifest.get(field_name) != identity.get(field_name):
                raise RuntimeError(f"artifact idempotency conflict: {field_name}")
        return staged

    async def stage(
        self,
        manifest: dict[str, object],
        path: Path,
        task_id: UUID,
        *,
        maximum_size_bytes: int,
        cancellation: CancellationToken,
    ) -> StagedArtifact:
        del cancellation
        if path.stat().st_size > maximum_size_bytes:
            raise RuntimeError("artifact size limit was violated")
        completed = {
            **manifest,
            "size_bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        self.values.append((completed, path, task_id))
        staged = StagedArtifact(path=path, manifest=completed)
        self.persisted[str(completed["artifact_id"])] = (staged, task_id)
        return staged

    async def stage_from_descriptor(
        self,
        manifest: dict[str, object],
        descriptor: int,
        expected_identity: FileIdentity,
        task_id: UUID,
        *,
        maximum_size_bytes: int,
        cancellation: CancellationToken,
    ) -> StagedArtifact:
        del cancellation
        metadata = os.fstat(descriptor)
        if not expected_identity.matches(metadata):
            raise RuntimeError("artifact source identity changed")
        if metadata.st_size > maximum_size_bytes:
            raise RuntimeError("artifact size limit was violated")
        duplicate = os.dup(descriptor)
        try:
            os.lseek(duplicate, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(duplicate, 65_536)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(duplicate)
        content = b"".join(chunks)
        if self.root is None:
            raise RuntimeError("recording stager root is not bound")
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / f"{manifest['artifact_id']}.{manifest['artifact_type']}"
        path.write_bytes(content)
        completed = {
            **manifest,
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        self.values.append((completed, path, task_id))
        staged = StagedArtifact(path=path, manifest=completed)
        self.persisted[str(completed["artifact_id"])] = (staged, task_id)
        return staged


class RecordingJournal:
    def __init__(self) -> None:
        self.records: list[tuple[CaptureRequest, InterfaceState]] = []
        self.cleared: list[UUID] = []

    async def pending(self, execution_id: UUID) -> bool:
        return (
            any(request.execution_id == execution_id for request, _state in self.records)
            and execution_id not in self.cleared
        )

    async def record(self, request: CaptureRequest, state: InterfaceState) -> None:
        self.records.append((request, state))

    async def clear(self, execution_id: UUID) -> None:
        self.cleared.append(execution_id)


def _state() -> InterfaceState:
    return InterfaceState(
        interface="wlan1",
        interface_type="managed",
        administratively_up=True,
        network_manager_managed=True,
        channel=1,
        frequency_mhz=2412,
        width_mhz=20,
        active_connection_uuids=(CONNECTION_UUID,),
        active_connections_status="complete",
        active_connections_provenance=("simulated",),
        network_manager_connection_uuid=CONNECTION_UUID,
        network_manager_connection_name="Capture Radio",
        namespace="net:[4026531840]",
        wiphy="phy1",
        driver="ath9k_htc",
    )


def _request(**overrides: object) -> CaptureRequest:
    values: dict[str, object] = {
        "task_id": TASK_ID,
        "execution_id": EXECUTION_ID,
        "idempotency_key": IDEMPOTENCY_KEY,
        "interface": "wlan1",
        "channel": 36,
        "frequency_mhz": 5180,
        "width_mhz": 20,
        "duration_seconds": 5,
        "max_size_bytes": 4096,
        "capture_format": "pcapng",
    }
    values.update(overrides)
    return CaptureRequest.model_validate(values)


def _coordinator(
    tmp_path: Path,
    backend: SimulatedCaptureBackend,
    stager: RecordingStager,
    **overrides: object,
) -> CaptureCoordinator:
    values: dict[str, object] = {
        "role": "capture_node",
        "enabled": True,
        "agent_id_provider": lambda: AGENT_ID,
        "authorization": StaticGrantAuthorization(),
        "provider_ready": True,
        "privileged_ready": True,
        "technical_ready": True,
        "tree_containment_ready": True,
        "allowed_interfaces": frozenset({"wlan1"}),
        "protected_interfaces": frozenset({"eth0"}),
        "allowed_channels": frozenset({36}),
        "allowed_frequencies_mhz": frozenset({5180}),
        "allowed_widths_mhz": frozenset({20}),
        "max_duration_seconds": 30,
        "max_size_bytes": 8192,
    }
    values.update(overrides)
    if stager.root is None:
        stager.root = tmp_path / "recorded-artifacts"
    return CaptureCoordinator(backend, CaptureWorkspace(tmp_path), stager, **values)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_capture_simulation_hash_staging_metadata_and_complete_rollback(
    tmp_path: Path,
) -> None:
    backend = SimulatedCaptureBackend(_state())
    stager = RecordingStager()
    result = await _coordinator(tmp_path, backend, stager).execute(_request(), CancellationToken())

    assert result.status == "completed"
    assert result.rollback.complete
    assert backend.state.interface_type == "managed"
    assert backend.state.administratively_up
    assert backend.state.network_manager_managed
    assert result.metadata["wiphy"] == "phy1"
    assert result.metadata["driver"] == "ath9k_htc"
    assert len(stager.values) == 1
    manifest, path, task_id = stager.values[0]
    assert task_id == TASK_ID
    assert manifest["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert manifest["artifact_type"] == "pcapng"
    assert backend.state == _state()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("width_mhz", "setup_center_frequency_mhz", "rollback_center_frequency_mhz"),
    [(80, 5210, 5530), (160, 5250, 5570)],
)
async def test_wide_channel_centers_are_journaled_and_restored_end_to_end(
    tmp_path: Path,
    width_mhz: int,
    setup_center_frequency_mhz: int,
    rollback_center_frequency_mhz: int,
) -> None:
    journal = FileCaptureJournal(tmp_path / "state")
    journal_path = journal.root / f"{EXECUTION_ID}.json"
    original = _state().model_copy(
        update={
            "channel": 100,
            "frequency_mhz": 5500,
            "width_mhz": width_mhz,
            "center_frequency_1_mhz": rollback_center_frequency_mhz,
            "center_frequency_2_mhz": None,
            "band": "5GHz",
            "geometry_version": "linux-channel-geometry-v1",
        }
    )

    class _WideChannelBackend(SimulatedCaptureBackend):
        def __init__(self, state: InterfaceState) -> None:
            super().__init__(state)
            self.frequency_calls: list[tuple[int, int, int, int, int | None]] = []
            self.journal_state: object | None = None

        async def set_frequency(
            self,
            interface: str,
            frequency_mhz: int,
            width_mhz: int,
            *,
            channel: int,
            center_frequency_1_mhz: int,
            center_frequency_2_mhz: int | None,
        ) -> None:
            self.frequency_calls.append(
                (
                    frequency_mhz,
                    width_mhz,
                    channel,
                    center_frequency_1_mhz,
                    center_frequency_2_mhz,
                )
            )
            await super().set_frequency(
                interface,
                frequency_mhz,
                width_mhz,
                channel=channel,
                center_frequency_1_mhz=center_frequency_1_mhz,
                center_frequency_2_mhz=center_frequency_2_mhz,
            )

        async def capture(
            self,
            request: CaptureRequest,
            output_descriptor: int,
            cancellation: CancellationToken,
        ) -> None:
            payload = json.loads(journal_path.read_text(encoding="utf-8"))
            self.journal_state = payload["interface_state"]
            await super().capture(request, output_descriptor, cancellation)

    backend = _WideChannelBackend(original)
    coordinator = _coordinator(
        tmp_path / "workspace",
        backend,
        RecordingStager(),
        allowed_widths_mhz=frozenset({width_mhz}),
    )
    coordinator.journal = journal
    try:
        result = await coordinator.execute(
            _request(width_mhz=width_mhz),
            CancellationToken(),
        )
    finally:
        journal.close()

    assert result.rollback.complete
    assert result.rollback.verification_status == "complete"
    assert result.metadata["center_frequency_1_mhz"] == setup_center_frequency_mhz
    assert result.metadata["center_frequency_2_mhz"] is None
    assert backend.frequency_calls == [
        (5180, width_mhz, 36, setup_center_frequency_mhz, None),
        (5500, width_mhz, 100, rollback_center_frequency_mhz, None),
    ]
    assert backend.journal_state == {
        **original.model_dump(mode="json"),
    }
    assert backend.state == original
    assert not journal_path.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("interface_type", ["monitor", "AP", "mesh"])
async def test_backend_supported_interface_types_are_fully_restored(
    tmp_path: Path, interface_type: str
) -> None:
    original = _state().model_copy(
        update={
            "interface_type": interface_type,
            "network_manager_managed": False,
            "active_connection_uuids": (),
            "network_manager_connection_uuid": None,
            "network_manager_connection_name": None,
        }
    )
    backend = SimulatedCaptureBackend(original)

    result = await _coordinator(tmp_path, backend, RecordingStager()).execute(
        _request(), CancellationToken()
    )

    assert result.rollback.complete
    assert backend.state == original


@pytest.mark.asyncio
async def test_disconnected_managed_snapshot_without_radio_is_rejected_before_effects(
    tmp_path: Path,
) -> None:
    disconnected = _state().model_copy(
        update={
            "channel": None,
            "frequency_mhz": None,
            "width_mhz": None,
            "center_frequency_1_mhz": None,
            "center_frequency_2_mhz": None,
            "band": None,
            "geometry_version": None,
            "active_connection_uuids": (),
            "network_manager_connection_uuid": None,
            "network_manager_connection_name": None,
        }
    )
    backend = SimulatedCaptureBackend(disconnected)
    journal = RecordingJournal()
    coordinator = _coordinator(tmp_path, backend, RecordingStager())
    coordinator.journal = journal

    with pytest.raises(RuntimeError, match="snapshot_not_restorable: radio_snapshot_required"):
        await coordinator.execute(_request(), CancellationToken())

    assert backend.calls == ["snapshot"]
    assert journal.records == []


@pytest.mark.asyncio
async def test_idempotent_retry_reuses_original_manifest_before_any_interface_command(
    tmp_path: Path,
) -> None:
    backend = SimulatedCaptureBackend(_state())
    stager = RecordingStager()
    journal = RecordingJournal()
    coordinator = _coordinator(tmp_path, backend, stager)
    coordinator.journal = journal

    first = await coordinator.execute(_request(), CancellationToken())
    original_created_at = first.artifact_manifest["created_at"]  # type: ignore[index]
    first_calls = tuple(backend.calls)
    assert "capture" in first_calls

    backend.calls.clear()
    second = await coordinator.execute(_request(), CancellationToken())

    assert second.artifact_manifest == first.artifact_manifest
    assert second.artifact_manifest["created_at"] == original_created_at  # type: ignore[index]
    assert second.artifact_path == first.artifact_path
    assert backend.calls == []
    assert len(journal.records) == 1
    assert len(stager.values) == 1


@pytest.mark.asyncio
async def test_incompatible_idempotent_retry_fails_before_snapshot_or_mutation(
    tmp_path: Path,
) -> None:
    backend = SimulatedCaptureBackend(_state())
    stager = RecordingStager()
    journal = RecordingJournal()
    coordinator = _coordinator(tmp_path, backend, stager)
    coordinator.journal = journal
    await coordinator.execute(_request(), CancellationToken())
    backend.calls.clear()

    with pytest.raises(RuntimeError, match="execution_id"):
        await coordinator.execute(
            _request(execution_id=UUID("20000000-0000-4000-8000-000000000099")),
            CancellationToken(),
        )

    assert backend.calls == []
    assert len(journal.records) == 1
    assert len(stager.values) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state",
    [
        _state().model_copy(update={"interface_type": "P2P-client"}),
        _state().model_copy(update={"interface_type": "P2P-GO"}),
        _state().model_copy(update={"interface_type": "P2P-device"}),
        _state().model_copy(update={"interface_type": "unknown"}),
        _state().model_copy(update={"network_manager_connection_uuid": None}),
        _state().model_copy(update={"width_mhz": None}),
        _state().model_copy(update={"frequency_mhz": None}),
        _state().model_copy(
            update={
                "channel": 36,
                "frequency_mhz": 5180,
                "width_mhz": 80,
                "center_frequency_1_mhz": None,
                "center_frequency_2_mhz": None,
                "band": "5GHz",
                "geometry_version": "linux-channel-geometry-v1",
            }
        ),
        _state().model_copy(
            update={
                "channel": 36,
                "frequency_mhz": 5180,
                "width_mhz": 160,
                "center_frequency_1_mhz": None,
                "center_frequency_2_mhz": None,
                "band": "5GHz",
                "geometry_version": "linux-channel-geometry-v1",
            }
        ),
        _state().model_copy(update={"width_mhz": 40}),
        _state().model_copy(update={"width_mhz": 320}),
        _state().model_copy(update={"channel": 1, "frequency_mhz": 58_320, "width_mhz": 2160}),
        _state().model_copy(update={"channel": 2, "frequency_mhz": 5935, "width_mhz": 80}),
        _state().model_copy(update={"channel": 2, "frequency_mhz": 5935, "width_mhz": 160}),
    ],
)
async def test_non_restorable_snapshot_is_rejected_without_mutation_or_journal(
    tmp_path: Path, state: InterfaceState
) -> None:
    backend = SimulatedCaptureBackend(state)
    journal = RecordingJournal()
    coordinator = _coordinator(tmp_path, backend, RecordingStager())
    coordinator.journal = journal

    with pytest.raises(RuntimeError, match="snapshot_not_restorable"):
        await coordinator.execute(_request(), CancellationToken())

    assert backend.calls == ["snapshot"]
    assert journal.records == []


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="capture workspace requires POSIX")
async def test_partial_active_connections_reject_snapshot_before_journal_or_mutation(
    tmp_path: Path,
) -> None:
    partial = _state().model_copy(
        update={
            "active_connection_uuids": (CONNECTION_UUID,),
            "active_connections_status": "partial",
            "active_connections_source_errors": ("active_connection_disappeared",),
        }
    )
    backend = SimulatedCaptureBackend(partial)
    journal = RecordingJournal()
    coordinator = _coordinator(tmp_path, backend, RecordingStager())
    coordinator.journal = journal

    with pytest.raises(RuntimeError, match="active_connections_partial"):
        await coordinator.execute(_request(), CancellationToken())

    assert backend.calls == ["snapshot"]
    assert journal.records == []
    assert not list(tmp_path.glob("capture-*.pcapng"))
    assert "capture" not in backend.calls


@pytest.mark.asyncio
async def test_capture_without_tree_containment_fails_before_snapshot_or_journal(
    tmp_path: Path,
) -> None:
    backend = SimulatedCaptureBackend(_state())
    journal = RecordingJournal()
    coordinator = _coordinator(
        tmp_path,
        backend,
        RecordingStager(),
        tree_containment_ready=False,
    )
    coordinator.journal = journal

    with pytest.raises(PermissionError):
        await coordinator.execute(_request(), CancellationToken())

    assert backend.calls == []
    assert journal.records == []
    assert not list(tmp_path.glob("capture-*.pcapng"))


@pytest.mark.asyncio
async def test_capture_rechecks_tree_containment_at_authorization_time(
    tmp_path: Path,
) -> None:
    readiness = [True]
    backend = SimulatedCaptureBackend(_state())
    coordinator = _coordinator(
        tmp_path,
        backend,
        RecordingStager(),
        tree_containment_ready=lambda: readiness[0],
    )
    assert coordinator.authorization_decision().allowed

    readiness[0] = False
    with pytest.raises(PermissionError):
        await coordinator.execute(_request(), CancellationToken())

    assert backend.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authorization,agent_id_provider",
    [
        (UnavailableControlPlaneAuthorization(), lambda: AGENT_ID),
        (StaticGrantAuthorization(agent_id="other-agent"), lambda: AGENT_ID),
        (
            StaticGrantAuthorization(capabilities=frozenset({"traffic.pcap.replay"})),
            lambda: AGENT_ID,
        ),
    ],
)
async def test_capture_requires_exact_server_issued_agent_and_capability_grant(
    tmp_path: Path,
    authorization: object,
    agent_id_provider: object,
) -> None:
    backend = SimulatedCaptureBackend(_state())
    coordinator = _coordinator(
        tmp_path,
        backend,
        RecordingStager(),
        authorization=authorization,
        agent_id_provider=agent_id_provider,
    )

    with pytest.raises(PermissionError, match=CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE):
        await coordinator.execute(_request(), CancellationToken())
    assert backend.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("restriction", [{"role": "endpoint"}, {"enabled": False}])
async def test_local_configuration_can_only_restrict_a_valid_grant(
    tmp_path: Path, restriction: dict[str, object]
) -> None:
    backend = SimulatedCaptureBackend(_state())
    coordinator = _coordinator(tmp_path, backend, RecordingStager(), **restriction)

    with pytest.raises(PermissionError):
        await coordinator.execute(_request(), CancellationToken())
    assert backend.calls == []


@pytest.mark.asyncio
async def test_manifest_and_execute_share_control_plane_authorization_decision(
    tmp_path: Path,
) -> None:
    authorization = UnavailableControlPlaneAuthorization()
    backend = SimulatedCaptureBackend(_state())
    coordinator = _coordinator(
        tmp_path,
        backend,
        RecordingStager(),
        authorization=authorization,
    )
    settings = AgentSettings.model_validate(
        {
            "environment": "test",
            "server_url": "http://testserver",
            "state_dir": tmp_path / "state",
            "node_role": "capture_node",
            "capture_enabled": True,
            "allowed_capture_interfaces": ["wlan1"],
            "allowed_capture_channels": [36],
            "allowed_capture_frequencies_mhz": [5180],
        }
    )
    ready = ToolStatus(
        name="dumpcap",
        path=Path("/usr/bin/dumpcap"),
        installed=True,
        self_check=True,
        access="allowed",
        secure=True,
        version="1.0.0",
    )
    absent = ToolStatus(
        name="absent",
        path=None,
        installed=False,
        self_check=False,
        access="missing",
        secure=False,
        version=None,
    )
    overrides = linux_capability_overrides(
        settings,
        service_state="active",
        dumpcap=ready,
        flent=absent,
        netperf=absent,
        tcpreplay=absent,
        monitor_interfaces=frozenset({"wlan1"}),
        effective_capabilities=frozenset({"cap_net_admin", "cap_net_raw"}),
        tree_containment_ready=True,
        agent_id=AGENT_ID,
        authorization=authorization,
    )
    decision = coordinator.authorization_decision()
    manifest_reason = overrides["capture.ieee80211.monitor"]["technical_support"][  # type: ignore[index]
        "reason"
    ][
        "detail"
    ]

    assert not decision.allowed
    assert manifest_reason == decision.reason == CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE
    with pytest.raises(PermissionError, match=CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE):
        await coordinator._authorize(_request())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "role,enabled,connectivity,monitor,protected",
    [
        ("endpoint", True, False, True, frozenset()),
        ("capture_node", False, False, True, frozenset()),
        ("capture_node", True, True, True, frozenset()),
        ("capture_node", True, False, False, frozenset()),
        ("capture_node", True, False, True, frozenset({"wlan1"})),
    ],
)
async def test_endpoint_policy_nic_connectivity_and_protected_interface_rejections(
    tmp_path: Path,
    role: str,
    enabled: bool,
    connectivity: bool,
    monitor: bool,
    protected: frozenset[str],
) -> None:
    backend = SimulatedCaptureBackend(_state(), connectivity=connectivity, monitor=monitor)
    coordinator = _coordinator(
        tmp_path,
        backend,
        RecordingStager(),
        role=role,
        enabled=enabled,
        protected_interfaces=protected,
    )

    with pytest.raises((PermissionError, RuntimeError)):
        await coordinator.execute(_request(), CancellationToken())
    assert "set_type" not in backend.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("override", [{"provider_ready": False}, {"privileged_ready": False}])
async def test_missing_dumpcap_or_monitor_permissions_reject_before_mutation(
    tmp_path: Path, override: dict[str, object]
) -> None:
    backend = SimulatedCaptureBackend(_state())
    coordinator = _coordinator(tmp_path, backend, RecordingStager(), **override)

    with pytest.raises((PermissionError, RuntimeError)):
        await coordinator.execute(_request(), CancellationToken())

    assert backend.calls == []


@pytest.mark.asyncio
async def test_channel_duration_size_and_width_policy_are_deny_by_default(
    tmp_path: Path,
) -> None:
    coordinator = _coordinator(tmp_path, SimulatedCaptureBackend(_state()), RecordingStager())
    for request in (
        _request(channel=1, frequency_mhz=2412),
        _request(duration_seconds=31),
        _request(max_size_bytes=9000),
        _request(width_mhz=80),
    ):
        with pytest.raises(PermissionError):
            await coordinator.execute(request, CancellationToken())


@pytest.mark.asyncio
async def test_timeout_or_cancellation_rolls_back_and_removes_partial_artifact(
    tmp_path: Path,
) -> None:
    backend = SimulatedCaptureBackend(_state(), fail_steps=frozenset({"capture"}))
    coordinator = _coordinator(tmp_path, backend, RecordingStager())

    with pytest.raises(CaptureOperationError) as raised:
        await coordinator.execute(_request(), CancellationToken())

    assert raised.value.rollback.complete
    assert not list(tmp_path.glob("*.pcapng"))
    assert backend.state.interface_type == "managed"

    token = CancellationToken()
    token.cancel()
    with pytest.raises(CaptureOperationError) as cancelled:
        await coordinator.execute(
            _request(execution_id=UUID("20000000-0000-4000-8000-000000000002")), token
        )
    assert cancelled.value.reason == "cancelled"
    assert cancelled.value.rollback.complete


class IncompleteRollbackBackend(SimulatedCaptureBackend):
    async def set_managed(self, interface: str, managed: bool) -> None:
        if managed:
            self.calls.append("restore_managed_failure")
            raise RuntimeError("controlled rollback failure")
        await super().set_managed(interface, managed)


class BlockingCaptureBackend(SimulatedCaptureBackend):
    def __init__(self, state: InterfaceState) -> None:
        super().__init__(state)
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def capture(
        self,
        request: CaptureRequest,
        output_descriptor: int,
        cancellation: CancellationToken,
    ) -> None:
        self.started.set()
        await self.release.wait()
        await super().capture(request, output_descriptor, cancellation)


@pytest.mark.asyncio
async def test_partial_rollback_is_visible_and_never_silently_reports_success(
    tmp_path: Path,
) -> None:
    backend = IncompleteRollbackBackend(_state())
    result = await _coordinator(tmp_path, backend, RecordingStager()).execute(
        _request(), CancellationToken()
    )

    assert result.status == "failed"
    assert result.reason == "rollback_incomplete"
    assert not result.rollback.complete
    assert any(not step.completed for step in result.rollback.steps)


@pytest.mark.asyncio
async def test_capture_concurrency_is_limited_to_one_transaction(
    tmp_path: Path,
) -> None:
    backend = BlockingCaptureBackend(_state())
    coordinator = _coordinator(tmp_path, backend, RecordingStager())
    first = asyncio.create_task(coordinator.execute(_request(), CancellationToken()))
    await backend.started.wait()

    with pytest.raises(RuntimeError, match="concurrency"):
        await coordinator.execute(
            _request(
                execution_id=UUID("20000000-0000-4000-8000-000000000004"),
                idempotency_key=UUID("30000000-0000-4000-8000-000000000004"),
            ),
            CancellationToken(),
        )

    backend.release.set()
    assert (await first).status == "completed"


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="capture journal durability requires POSIX")
async def test_interface_snapshot_journal_is_cleared_only_after_verified_rollback(
    tmp_path: Path,
) -> None:
    journal = FileCaptureJournal(tmp_path / "state")
    backend = SimulatedCaptureBackend(_state())
    coordinator = CaptureCoordinator(
        backend,
        CaptureWorkspace(tmp_path / "artifacts"),
        RecordingStager(tmp_path / "staged"),
        journal,
        role="capture_node",
        enabled=True,
        agent_id_provider=lambda: AGENT_ID,
        authorization=StaticGrantAuthorization(),
        provider_ready=True,
        privileged_ready=True,
        technical_ready=True,
        tree_containment_ready=True,
        allowed_interfaces=frozenset({"wlan1"}),
        protected_interfaces=frozenset(),
        allowed_channels=frozenset({36}),
        allowed_frequencies_mhz=frozenset({5180}),
        allowed_widths_mhz=frozenset({20}),
        max_duration_seconds=30,
        max_size_bytes=8192,
    )
    await coordinator.execute(_request(), CancellationToken())
    assert not list((tmp_path / "state" / "capture-journal").glob("*.json"))

    incomplete = IncompleteRollbackBackend(_state())
    coordinator.backend = incomplete
    second = _request(
        execution_id=UUID("20000000-0000-4000-8000-000000000003"),
        idempotency_key=UUID("30000000-0000-4000-8000-000000000003"),
    )
    result = await coordinator.execute(second, CancellationToken())
    journals = list((tmp_path / "state" / "capture-journal").glob("*.json"))
    assert result.reason == "rollback_incomplete"
    assert len(journals) == 1
    assert str(second.execution_id) in journals[0].read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_artifact_limit_and_insecure_permissions_fail_closed(
    tmp_path: Path,
) -> None:
    backend = SimulatedCaptureBackend(_state(), artifact_bytes=b"x" * 9000)
    with pytest.raises(CaptureOperationError):
        await _coordinator(tmp_path, backend, RecordingStager()).execute(
            _request(), CancellationToken()
        )
    assert not list(tmp_path.glob("*.pcapng"))


def test_invalid_channel_frequency_pair_and_arbitrary_fields_are_rejected() -> None:
    with pytest.raises(ValueError):
        _request(channel=36, frequency_mhz=2412)
    with pytest.raises(ValueError):
        CaptureRequest.model_validate({**_request().model_dump(), "arguments": ["--evil"]})


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="directory fsync semantics require POSIX")
async def test_capture_journal_fsyncs_file_then_parent_after_rename_and_on_clear(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    real_fsync = os.fsync
    real_rename = capture_module.rename_noreplace

    def tracked_fsync(descriptor: int) -> None:
        events.append("fsync_dir" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "fsync_file")
        real_fsync(descriptor)

    def tracked_rename(
        source_dir_fd: int,
        source_name: str,
        destination_dir_fd: int,
        destination_name: str,
    ) -> None:
        events.append("rename_noreplace")
        real_rename(source_dir_fd, source_name, destination_dir_fd, destination_name)

    monkeypatch.setattr(capture_module.os, "fsync", tracked_fsync)
    monkeypatch.setattr(capture_module, "rename_noreplace", tracked_rename)
    journal = FileCaptureJournal(tmp_path / "state")

    await journal.record(_request(), _state())
    assert events.index("fsync_file") < events.index("rename_noreplace") < events.index("fsync_dir")
    directory_syncs = events.count("fsync_dir")
    await journal.clear(EXECUTION_ID)
    assert events.count("fsync_dir") == directory_syncs + 1
    assert not (journal.root / f"{EXECUTION_ID}.json").exists()
    assert list(journal.root.glob(".capture-journal-retired-*"))


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="directory fsync semantics require POSIX")
async def test_directory_fsync_failure_prevents_all_interface_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_fsync = os.fsync

    def fail_directory_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("simulated directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(capture_module.os, "fsync", fail_directory_fsync)
    backend = SimulatedCaptureBackend(_state())
    coordinator = _coordinator(tmp_path / "artifacts", backend, RecordingStager())
    coordinator.journal = FileCaptureJournal(tmp_path / "state")

    with pytest.raises(OSError, match="directory fsync"):
        await coordinator.execute(_request(), CancellationToken())

    assert backend.calls == ["snapshot"]


@pytest.mark.skipif(os.name != "posix", reason="descriptor semantics require POSIX")
def test_journal_close_error_is_not_allowed_to_replace_primary_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = FileCaptureJournal(tmp_path / "state")

    def primary_failure(descriptor: int) -> None:
        del descriptor
        raise OSError("primary fsync failure")

    def close_failure(descriptor: int) -> None:
        del descriptor
        raise OSError("secondary close failure")

    monkeypatch.setattr(capture_module.os, "fsync", primary_failure)
    monkeypatch.setattr(capture_module.os, "close", close_failure)
    with pytest.raises(OSError, match="primary fsync failure") as raised:
        journal._record(_request(), _state())
    assert any("secondary close failure" in note for note in raised.value.__notes__)


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="journal recovery requires POSIX")
async def test_orphaned_unique_journal_temporary_does_not_block_retry(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state" / "capture-journal"
    root.mkdir(parents=True, mode=0o700)
    os.chmod(root, 0o700)
    orphan = root / f".{EXECUTION_ID}.pending.{'a' * 48}"
    orphan.write_bytes(b"incomplete")
    os.chmod(orphan, 0o600)
    journal = FileCaptureJournal(tmp_path / "state")

    await journal.record(_request(), _state())

    assert (root / f"{EXECUTION_ID}.json").is_file()
    assert orphan.is_file()
    assert journal.recovery_issues


@pytest.mark.skipif(os.name != "posix", reason="journal recovery requires POSIX")
def test_journal_constructor_closes_root_descriptor_when_recovery_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target: list[FileCaptureJournal] = []
    target_identity: tuple[int, int] | None = None
    target_descriptor = -1
    target_closes: list[tuple[int, int, int]] = []
    unrelated_closes: list[tuple[int, str]] = []
    recovery_error = OSError("controlled journal recovery failure")
    real_close = capture_module.close_descriptor

    foreign = CaptureWorkspace(tmp_path / "foreign-workspace")
    foreign_descriptor = foreign._root_descriptor
    foreign_metadata = os.fstat(foreign_descriptor)
    foreign_identity = (int(foreign_metadata.st_dev), int(foreign_metadata.st_ino))
    foreign._test_cycle = foreign  # type: ignore[attr-defined]
    del foreign

    def fail_recovery(self: FileCaptureJournal) -> None:
        nonlocal target_descriptor, target_identity
        target.append(self)
        target_descriptor = self._root_descriptor
        metadata = os.fstat(target_descriptor)
        target_identity = (int(metadata.st_dev), int(metadata.st_ino))
        gc.collect()
        raise recovery_error

    def recording_close(
        descriptor: int,
        *,
        primary_error: BaseException | None = None,
        context: str = "descriptor",
    ) -> None:
        try:
            metadata = os.fstat(descriptor)
            identity = (int(metadata.st_dev), int(metadata.st_ino))
        except OSError:
            identity = None
        if (
            target_identity is not None
            and descriptor == target_descriptor
            and identity == target_identity
            and primary_error is recovery_error
            and context == "capture journal directory"
        ):
            target_closes.append((descriptor, *identity))
        else:
            unrelated_closes.append((descriptor, context))
        real_close(
            descriptor,
            primary_error=primary_error,
            context=context,
        )

    monkeypatch.setattr(FileCaptureJournal, "_recover_temporaries", fail_recovery)
    monkeypatch.setattr(capture_module, "close_descriptor", recording_close)

    with pytest.raises(OSError, match="recovery failure") as raised:
        FileCaptureJournal(tmp_path / "state")

    assert raised.value is recovery_error
    assert len(target) == 1
    assert target[0]._root_descriptor == -1
    assert target_identity is not None
    assert target_closes == [(target_descriptor, *target_identity)]
    assert (foreign_descriptor, "capture workspace directory") in unrelated_closes
    with pytest.raises(OSError) as closed_error:
        os.fstat(target_descriptor)
    assert closed_error.value.errno == errno.EBADF

    replacement_descriptors: list[int] = []
    try:
        for _ in range(128):
            replacement_descriptors.append(os.open(tmp_path, os.O_RDONLY))
            if replacement_descriptors[-1] == target_descriptor:
                break
        assert target_descriptor in replacement_descriptors
        replacement_metadata = os.fstat(target_descriptor)
        target[0].close()
        target[0].__del__()
        assert os.fstat(target_descriptor) == replacement_metadata
        assert target_closes == [(target_descriptor, *target_identity)]
    finally:
        for descriptor in replacement_descriptors:
            os.close(descriptor)

    assert foreign_identity != target_identity


@pytest.mark.skipif(os.name != "posix", reason="descriptor semantics require POSIX")
@pytest.mark.parametrize(
    ("resource_type", "root_name", "close_context", "error_message"),
    [
        (
            FileCaptureJournal,
            "capture-journal",
            "capture journal directory",
            "capture journal directory ownership or mode is unsafe",
        ),
        (
            CaptureWorkspace,
            "workspace",
            "capture workspace",
            "capture workspace ownership or mode is unsafe",
        ),
    ],
)
def test_unsafe_root_metadata_invalidates_descriptor_before_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    resource_type: type[FileCaptureJournal] | type[CaptureWorkspace],
    root_name: str,
    close_context: str,
    error_message: str,
) -> None:
    instances: list[FileCaptureJournal | CaptureWorkspace] = []
    close_observations: list[tuple[int, int, int, int, BaseException | None, str]] = []
    real_close = capture_module.close_descriptor
    real_os_close = os.close
    inject_close_failure = False
    root = tmp_path / root_name
    if resource_type is FileCaptureJournal:
        root = tmp_path / "state" / root_name
    root.mkdir(parents=True, mode=0o755)
    os.chmod(root, 0o755)  # noqa: S103 - intentionally unsafe constructor fixture

    class TrackedResource(resource_type):  # type: ignore[valid-type,misc]
        def __new__(cls, *_args: object, **_kwargs: object) -> TrackedResource:
            instance = object.__new__(cls)
            instances.append(instance)
            return instance

    def preserve_unsafe_mode(_path: Path, _mode: int) -> None:
        return None

    def recording_close(
        descriptor: int,
        *,
        primary_error: BaseException | None = None,
        context: str = "descriptor",
    ) -> None:
        nonlocal inject_close_failure
        metadata = os.fstat(descriptor)
        close_observations.append(
            (
                descriptor,
                int(metadata.st_dev),
                int(metadata.st_ino),
                instances[-1]._root_descriptor,
                primary_error,
                context,
            )
        )
        inject_close_failure = context == close_context
        try:
            real_close(
                descriptor,
                primary_error=primary_error,
                context=context,
            )
        finally:
            inject_close_failure = False

    def close_then_fail(descriptor: int) -> None:
        real_os_close(descriptor)
        if inject_close_failure:
            raise OSError("controlled unsafe root close failure")

    constructor_root = tmp_path / "state" if resource_type is FileCaptureJournal else root
    with monkeypatch.context() as constructor_patch:
        constructor_patch.setattr(capture_module.os, "chmod", preserve_unsafe_mode)
        constructor_patch.setattr(capture_module.os, "close", close_then_fail)
        constructor_patch.setattr(capture_module, "close_descriptor", recording_close)
        with pytest.raises(PermissionError, match=error_message) as raised:
            TrackedResource(constructor_root)

    assert len(instances) == 1
    instance = instances[0]
    assert instance._root_descriptor == -1
    assert len(close_observations) == 1
    descriptor, device, inode, observed_sentinel, close_primary, observed_context = (
        close_observations[0]
    )
    assert (device, inode) == (int(root.stat().st_dev), int(root.stat().st_ino))
    assert observed_sentinel == -1
    assert close_primary is raised.value
    assert observed_context == close_context
    assert any("controlled unsafe root close failure" in note for note in raised.value.__notes__)
    with pytest.raises(OSError) as closed_error:
        os.fstat(descriptor)
    assert closed_error.value.errno == errno.EBADF

    replacement_descriptors: list[int] = []
    try:
        for _ in range(128):
            replacement_descriptors.append(os.open(root, os.O_RDONLY))
            if replacement_descriptors[-1] == descriptor:
                break
        assert descriptor in replacement_descriptors
        replacement_metadata = os.fstat(descriptor)
        instance.close()
        instance.__del__()
        assert os.fstat(descriptor) == replacement_metadata
        assert len(close_observations) == 1
    finally:
        for replacement in replacement_descriptors:
            os.close(replacement)


@pytest.mark.skipif(os.name != "posix", reason="journal recovery requires POSIX")
def test_journal_recovery_never_promotes_replacement_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "state" / "capture-journal"
    root.mkdir(parents=True, mode=0o700)
    os.chmod(root, 0o700)
    temporary = root / f".{EXECUTION_ID}.pending.{'b' * 48}"
    payload = {
        "schema_version": "2.0.0",
        "execution_id": str(EXECUTION_ID),
        "recorded_at": "2026-07-15T00:00:00Z",
        "request": _request().model_dump(mode="json"),
        "interface_state": _state().model_dump(mode="json"),
    }
    temporary.write_bytes(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    os.chmod(temporary, 0o600)
    replacement_content = b"foreign-journal-object"
    real_rename = capture_module.rename_noreplace
    raced = False

    def replace_at_publication(
        source_dir_fd: int,
        source_name: str,
        destination_dir_fd: int,
        destination_name: str,
    ) -> None:
        nonlocal raced
        if not raced and destination_name == f"{EXECUTION_ID}.json":
            raced = True
            foreign = root / ".foreign-recovery-journal"
            foreign.write_bytes(replacement_content)
            os.chmod(foreign, 0o600)
            os.replace(
                foreign.name,
                source_name,
                src_dir_fd=source_dir_fd,
                dst_dir_fd=source_dir_fd,
            )
        real_rename(
            source_dir_fd,
            source_name,
            destination_dir_fd,
            destination_name,
        )

    monkeypatch.setattr(capture_module, "rename_noreplace", replace_at_publication)

    journal = FileCaptureJournal(tmp_path / "state")

    assert raced
    assert not (root / f"{EXECUTION_ID}.json").exists()
    quarantined = list(root.glob(f".{EXECUTION_ID}.recovery.*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == replacement_content
    assert any("manual_recovery_required" in issue for issue in journal.recovery_issues)


@pytest.mark.skipif(os.name != "posix", reason="journal recovery requires POSIX")
def test_journal_recovery_detects_in_place_content_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "state" / "capture-journal"
    root.mkdir(parents=True, mode=0o700)
    os.chmod(root, 0o700)
    temporary = root / f".{EXECUTION_ID}.pending.{'c' * 48}"
    payload = {
        "schema_version": "2.0.0",
        "execution_id": str(EXECUTION_ID),
        "recorded_at": "2026-07-15T00:00:00Z",
        "request": _request().model_dump(mode="json"),
        "interface_state": _state().model_dump(mode="json"),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    temporary.write_bytes(encoded)
    os.chmod(temporary, 0o600)
    original_inode = temporary.stat().st_ino
    real_rename = capture_module.rename_noreplace
    raced = False

    def mutate_at_publication(
        source_dir_fd: int,
        source_name: str,
        destination_dir_fd: int,
        destination_name: str,
    ) -> None:
        nonlocal raced
        if not raced and destination_name == f"{EXECUTION_ID}.json":
            raced = True
            descriptor = os.open(
                source_name,
                os.O_WRONLY | int(getattr(os, "O_NOFOLLOW", 0)),
                dir_fd=source_dir_fd,
            )
            try:
                mutated = b"x" * len(encoded)
                view = memoryview(mutated)
                while view:
                    written = os.write(descriptor, view)
                    assert written > 0
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        real_rename(
            source_dir_fd,
            source_name,
            destination_dir_fd,
            destination_name,
        )

    monkeypatch.setattr(capture_module, "rename_noreplace", mutate_at_publication)

    journal = FileCaptureJournal(tmp_path / "state")

    assert raced
    assert not (root / f"{EXECUTION_ID}.json").exists()
    quarantined = list(root.glob(f".{EXECUTION_ID}.recovery.*"))
    assert len(quarantined) == 1
    assert quarantined[0].stat().st_ino == original_inode
    assert quarantined[0].read_bytes() == b"x" * len(encoded)
    assert any("manual_recovery_required" in issue for issue in journal.recovery_issues)


@pytest.mark.skipif(os.name != "posix", reason="journal cleanup requires POSIX")
@pytest.mark.parametrize("failure", ["write", "file_fsync", "rename"])
def test_journal_failure_logically_quarantines_only_its_own_unique_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    journal = FileCaptureJournal(tmp_path / "state")
    real_write = capture_module.os.write
    real_fsync = capture_module.os.fsync

    if failure == "write":
        monkeypatch.setattr(
            capture_module.os,
            "write",
            lambda _descriptor, _data: (_ for _ in ()).throw(
                OSError("controlled journal write failure")
            ),
        )
    elif failure == "file_fsync":

        def fail_file_fsync(descriptor: int) -> None:
            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("controlled journal fsync failure")
            real_fsync(descriptor)

        monkeypatch.setattr(capture_module.os, "fsync", fail_file_fsync)
    else:
        monkeypatch.setattr(
            capture_module,
            "rename_noreplace",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError("controlled journal rename failure")
            ),
        )

    with pytest.raises(OSError, match="controlled journal"):
        journal._record(_request(), _state())

    monkeypatch.setattr(capture_module.os, "write", real_write)
    assert not list(journal.root.glob(f".{EXECUTION_ID}.pending.*"))
    assert list(journal.root.glob(".capture-journal-manual-*"))


@pytest.mark.skipif(os.name != "posix", reason="journal cleanup requires POSIX")
def test_journal_replacement_is_preserved_for_manual_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = FileCaptureJournal(tmp_path / "state")
    real_replace = os.replace
    replacement_content = b"foreign-journal-object"

    def replace_temporary_then_fail(
        source_dir_fd: int,
        source_name: str,
        destination_dir_fd: int,
        destination_name: str,
    ) -> None:
        del destination_dir_fd, destination_name
        foreign = journal.root / ".foreign-journal"
        foreign.write_bytes(replacement_content)
        os.chmod(foreign, 0o600)
        real_replace(
            foreign.name,
            source_name,
            src_dir_fd=source_dir_fd,
            dst_dir_fd=source_dir_fd,
        )
        raise OSError("controlled journal publication failure")

    monkeypatch.setattr(capture_module, "rename_noreplace", replace_temporary_then_fail)

    with pytest.raises(OSError, match="publication failure") as raised:
        journal._record(_request(), _state())

    temporaries = list(journal.root.glob(f".{EXECUTION_ID}.pending.*"))
    assert len(temporaries) == 1
    assert temporaries[0].read_bytes() == replacement_content
    assert any("manual filesystem recovery" in note for note in raised.value.__notes__)


@pytest.mark.skipif(os.name != "posix", reason="capture reservation requires POSIX")
def test_capture_output_reservation_is_exclusive_and_replacement_safe(
    tmp_path: Path,
) -> None:
    workspace = CaptureWorkspace(tmp_path)
    reserved = workspace.reserve(EXECUTION_ID, "pcapng")
    with pytest.raises(FileExistsError):
        workspace.reserve(EXECUTION_ID, "pcapng")
    original = os.fstat(reserved.descriptor)
    replacement = tmp_path / ".replacement-output"
    replacement.write_bytes(b"foreign-output")
    os.chmod(replacement, 0o600)
    os.replace(replacement, reserved.path)
    os.write(reserved.descriptor, b"captured-bytes")
    os.lseek(reserved.descriptor, 0, os.SEEK_SET)

    assert os.read(reserved.descriptor, 4096) == b"captured-bytes"
    assert os.fstat(reserved.descriptor).st_ino == original.st_ino
    with pytest.raises(PermissionError):
        reserved.validate_completed(4096)
    with pytest.raises(SecureQuarantineError):
        reserved.quarantine()
    assert reserved.path.read_bytes() == b"foreign-output"
    reserved.close()
    workspace.close()
