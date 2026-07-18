from __future__ import annotations

import asyncio
import json
import multiprocessing
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest

from wto_desktop_agent.application.artifacts import SQLiteArtifactStager
from wto_desktop_agent.config import AgentSettings
from wto_desktop_agent.domain.models import LocalTaskEnvelope
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.platforms.linux import adapter as linux_adapter_module
from wto_desktop_agent.platforms.linux.adapter import LinuxPlatformAdapter
from wto_desktop_agent.platforms.linux.capture import (
    MONITOR_CAPTURE_CAPABILITY,
    CaptureCoordinator,
    CaptureOperationError,
    CaptureRequest,
    CaptureWorkspace,
    DeferredCaptureCoordinator,
    FileCaptureJournal,
    InterfaceState,
    NetworkManagerConnectionProfileMissing,
    PrivilegedAuthorizationDecision,
    SimulatedCaptureBackend,
)
from wto_desktop_agent.platforms.linux.capture_backend import (
    build_capture_execution_plan,
)
from wto_desktop_agent.platforms.linux.capture_commands import capture_command_specs
from wto_desktop_agent.platforms.linux.capture_fingerprint import (
    canonical_capture_fingerprint_v1,
)
from wto_desktop_agent.platforms.linux.capture_identity import CaptureInterfaceType
from wto_desktop_agent.platforms.linux.capture_recovery import (
    CaptureFingerprint,
    CaptureIdempotencyConflict,
    CaptureInProgressError,
    CaptureManualRecoveryRequired,
    CaptureMarker,
    CaptureMarkerState,
    CaptureRecoveryStore,
)
from wto_desktop_agent.ports.plugins import CancellationToken

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX durable capture recovery")

TASK_ID = UUID("10000000-0000-4000-8000-000000000081")
EXECUTION_ID = UUID("20000000-0000-4000-8000-000000000081")
IDEMPOTENCY_KEY = UUID("30000000-0000-4000-8000-000000000081")
AGENT_ID = "40000000-0000-4000-8000-000000000081"
SECONDARY_CONNECTION_UUID_A = "50000000-0000-4000-8000-000000000082"
SECONDARY_CONNECTION_UUID_B = "50000000-0000-4000-8000-000000000083"
PRIMARY_CONNECTION_UUID = "50000000-0000-4000-8000-000000000084"


class _Authorization:
    def authorize(
        self, *, agent_id: str | None, capability_id: str
    ) -> PrivilegedAuthorizationDecision:
        return PrivilegedAuthorizationDecision(
            agent_id == AGENT_ID and capability_id == MONITOR_CAPTURE_CAPABILITY
        )


class _RevokedAuthorization:
    def authorize(
        self, *, agent_id: str | None, capability_id: str
    ) -> PrivilegedAuthorizationDecision:
        del agent_id, capability_id
        return PrivilegedAuthorizationDecision(False, "revoked_for_test")


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


def _state() -> InterfaceState:
    return InterfaceState(
        interface="wlan1",
        interface_type="managed",
        administratively_up=True,
        network_manager_managed=True,
        channel=1,
        frequency_mhz=2412,
        width_mhz=20,
        active_connection_uuids=(),
        active_connections_status="complete",
        active_connections_provenance=("test",),
        namespace="net:[4026531840]",
        wiphy="phy1",
        driver="test-driver",
    )


def _ap_state() -> InterfaceState:
    return _state().model_copy(
        update={
            "interface_type": "AP",
            "network_manager_managed": False,
        }
    )


class _APArgvRecordingBackend(SimulatedCaptureBackend):
    def __init__(self, log_path: Path) -> None:
        super().__init__(_ap_state())
        self.log_path = log_path
        self.type_argv: list[list[str]] = []

    async def set_type(
        self,
        interface: str,
        interface_type: CaptureInterfaceType,
    ) -> None:
        spec = capture_command_specs(
            paths={"iw": Path("/usr/sbin/iw")},
            artifact_root=self.log_path.parent / "artifacts-sibling",
            environment={"PATH": "/usr/sbin:/usr/bin"},
        )["linux.iw.type-set"]
        arguments = spec.argument_model.model_validate(
            {"interface": interface, "interface_type": interface_type}
        )
        argv = spec.build_argv(arguments)
        self.type_argv.append(argv)
        with self.log_path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(argv, separators=(",", ":")) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        await super().set_type(interface, interface_type)


def _multi_connection_state() -> InterfaceState:
    return InterfaceState(
        interface="wlan1",
        interface_type="managed",
        administratively_up=True,
        network_manager_managed=True,
        channel=1,
        frequency_mhz=2412,
        width_mhz=20,
        active_connection_uuids=(
            PRIMARY_CONNECTION_UUID,
            SECONDARY_CONNECTION_UUID_B,
            SECONDARY_CONNECTION_UUID_A,
        ),
        active_connections_status="complete",
        active_connections_provenance=("test",),
        network_manager_connection_uuid=PRIMARY_CONNECTION_UUID,
        network_manager_connection_name="Primary capture connection",
        namespace="net:[4026531840]",
        wiphy="phy1",
        driver="test-driver",
    )


def _store(path: Path) -> SQLiteStore:
    store = SQLiteStore(path)
    store.initialize()
    now = datetime(2026, 7, 17, tzinfo=UTC)
    store.ingest_task(
        LocalTaskEnvelope(
            task_id=TASK_ID,
            execution_id=EXECUTION_ID,
            task_type="protocol.contract_check",
            task_type_version="1.0.0",
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(minutes=5),
            idempotency_key=IDEMPOTENCY_KEY,
            parameters={},
            required_capabilities=[MONITOR_CAPTURE_CAPABILITY],
            foreground_requirement="not_required",
            user_interaction_requirement="none",
        )
    )
    return store


def _planned_source_name(state: Path) -> str:
    marker = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    first_event = json.loads(marker.read_text(encoding="utf-8").splitlines()[0])
    return str(first_event["details"]["source_name"])


def _coordinator(
    tmp_path: Path,
    *,
    artifact_root: Path | None = None,
    backend: SimulatedCaptureBackend | None = None,
) -> tuple[CaptureCoordinator, Path, Path]:
    state = tmp_path / "state"
    artifacts = artifact_root or tmp_path / "artifacts-sibling"
    state.mkdir(mode=0o700, exist_ok=True)
    artifacts.mkdir(mode=0o700, exist_ok=True)
    os.chmod(state, 0o700)
    os.chmod(artifacts, 0o700)
    store = _store(state / "agent.sqlite3")
    stager = SQLiteArtifactStager(store, artifacts, trusted_root=artifacts)
    coordinator = CaptureCoordinator(
        backend or SimulatedCaptureBackend(_state()),
        CaptureWorkspace(artifacts),
        stager,
        FileCaptureJournal(state),
        role="capture_node",
        enabled=True,
        agent_id_provider=lambda: AGENT_ID,
        authorization=_Authorization(),
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
        max_size_bytes=4096,
        recovery_store=CaptureRecoveryStore(state, artifacts),
        provider_version="evidence-only-1.0",
    )
    return coordinator, state, artifacts


def _close_coordinator(coordinator: CaptureCoordinator) -> None:
    coordinator.workspace.close()
    cast(FileCaptureJournal, coordinator.journal).close()
    cast(CaptureRecoveryStore, coordinator.recovery_store).close()


def _provision_adapter_identity(state: Path) -> None:
    store = SQLiteStore(state / "agent.sqlite3")
    store.ensure_identity(
        installation_id="50000000-0000-4000-8000-000000000081",
        display_name="binding-reuse-test",
        platform="linux",
        platform_version="test",
        agent_version="0.1.0",
        enrollment_idempotency_key="60000000-0000-4000-8000-000000000081",
        enrollment_reported_at="2026-07-18T00:00:00Z",
    )
    store.update_identity({"agent_id": AGENT_ID})


def _filesystem_snapshot(*roots: Path) -> dict[str, tuple[bool, int, bytes]]:
    snapshot: dict[str, tuple[bool, int, bytes]] = {}
    for root in roots:
        for path in sorted(root.rglob("*")):
            relative = f"{root.name}/{path.relative_to(root).as_posix()}"
            metadata = path.lstat()
            is_directory = path.is_dir()
            payload = path.read_bytes() if path.is_file() else b""
            snapshot[relative] = (is_directory, metadata.st_mode & 0o7777, payload)
    return snapshot


def _restart_adapter(
    state: Path,
    artifacts: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> LinuxPlatformAdapter:
    def forbidden_live_dependency(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("durable binding reuse constructed a live capture dependency")

    for name in (
        "_commands",
        "CgroupV2Manager",
        "LinuxProcessRunner",
        "LinuxServiceManager",
        "LinuxInventoryCollector",
        "NetworkManagerDbusProvider",
        "LinuxCommandCaptureBackend",
        "CaptureWorkspace",
        "FileCaptureJournal",
        "CaptureRecoveryStore",
        "LinuxEncryptedFileSecretStore",
        "probe_dumpcap",
        "probe_tool",
        "monitor_capable_interfaces",
    ):
        monkeypatch.setattr(linux_adapter_module, name, forbidden_live_dependency)

    settings = AgentSettings(
        environment="test",
        server_url="http://testserver",
        state_dir=state,
        artifacts_dir=artifacts,
        node_role="capture_node",
        linux_secret_backend="encrypted_file",
        capture_enabled=True,
        allowed_capture_interfaces=frozenset({"wlan1"}),
        allowed_capture_channels=frozenset({36}),
        allowed_capture_frequencies_mhz=frozenset({5180}),
        allowed_capture_widths_mhz=frozenset({20}),
        capture_max_duration_seconds=30,
        capture_max_size_bytes=4096,
    )
    adapter = LinuxPlatformAdapter(settings, SQLiteStore(state / "agent.sqlite3"))
    adapter.capture_provider.authorization = _Authorization()
    return adapter


class _TransientRollbackVerificationBackend(SimulatedCaptureBackend):
    def __init__(self, status: str) -> None:
        super().__init__(_state())
        self.verification_status = status
        self.snapshot_count = 0

    async def snapshot(self, interface: str) -> InterfaceState:
        observed = await super().snapshot(interface)
        self.snapshot_count += 1
        if self.snapshot_count < 3 or self.verification_status == "complete":
            return observed
        if self.verification_status == "mismatch":
            return observed.model_copy(
                update={"administratively_up": not observed.administratively_up}
            )
        return observed.model_copy(update={"active_connections_status": self.verification_status})


class _MultiConnectionVerificationBackend(SimulatedCaptureBackend):
    def __init__(self, verification_status: str) -> None:
        super().__init__(_multi_connection_state())
        self.verification_status = verification_status

    async def snapshot(self, interface: str) -> InterfaceState:
        observed = await super().snapshot(interface)
        restored_connections = sum(call.startswith("restore_connection:") for call in self.calls)
        if restored_connections < 3 or self.verification_status == "complete":
            return observed
        if self.verification_status == "mismatch":
            return observed.model_copy(
                update={
                    "primary_connection_uuid": SECONDARY_CONNECTION_UUID_A,
                    "ordered_active_connection_uuids": (
                        SECONDARY_CONNECTION_UUID_B,
                        PRIMARY_CONNECTION_UUID,
                        SECONDARY_CONNECTION_UUID_A,
                    ),
                }
            )
        return observed.model_copy(update={"active_connections_status": self.verification_status})


class _MissingConnectionProfileBackend(SimulatedCaptureBackend):
    async def restore_connection(self, interface: str, connection_uuid: str) -> None:
        del interface
        self.calls.append(f"restore_connection:{connection_uuid}")
        raise NetworkManagerConnectionProfileMissing("connection_profile_missing")


def _connection_step_names() -> tuple[str, ...]:
    return (
        f"restore_connection:{SECONDARY_CONNECTION_UUID_A}",
        f"restore_connection:{SECONDARY_CONNECTION_UUID_B}",
        f"restore_primary_connection:{PRIMARY_CONNECTION_UUID}",
    )


def _connection_backend_calls() -> tuple[str, ...]:
    return (
        f"restore_connection:{SECONDARY_CONNECTION_UUID_A}",
        f"restore_connection:{SECONDARY_CONNECTION_UUID_B}",
        f"restore_connection:{PRIMARY_CONNECTION_UUID}",
    )


def _marker_rollback_reports(marker: Path) -> list[dict[str, object]]:
    events = [json.loads(line) for line in marker.read_text(encoding="utf-8").splitlines()]
    return [
        cast(dict[str, object], event["details"]["rollback"])
        for event in events
        if event["state"] == CaptureMarkerState.ROLLBACK_VERIFICATION_PENDING.value
    ]


def _rewrite_last_marker_connection_step(
    marker: Path,
    *,
    field: str,
    value: object,
) -> None:
    events = [json.loads(line) for line in marker.read_text(encoding="utf-8").splitlines()]
    details = cast(dict[str, object], events[-1]["details"])
    rollback = cast(dict[str, object], details["rollback"])
    steps = cast(list[dict[str, object]], rollback["steps"])
    steps[-1][field] = value
    marker.write_text(
        "".join(
            f"{json.dumps(event, sort_keys=True, separators=(',', ':'))}\n" for event in events
        ),
        encoding="utf-8",
    )
    os.chmod(marker, 0o600)


def _install_connection_checkpoint_crash(
    monkeypatch: pytest.MonkeyPatch,
    *,
    target_step: str,
    after_persist: bool,
) -> Any:
    original_note = CaptureMarker.note_rollback_verification
    pending = True

    def crash_at_checkpoint(
        marker: CaptureMarker,
        rollback: dict[str, object],
    ) -> None:
        nonlocal pending
        steps = rollback.get("steps")
        matched = (
            pending
            and isinstance(steps, list)
            and any(
                isinstance(step, dict)
                and step.get("name") == target_step
                and step.get("operation_state") == "confirmed"
                for step in steps
            )
        )
        if matched and not after_persist:
            pending = False
            raise SystemExit("simulated pre-checkpoint process boundary")
        original_note(marker, rollback)
        if matched:
            pending = False
            raise SystemExit("simulated post-checkpoint process boundary")

    monkeypatch.setattr(CaptureMarker, "note_rollback_verification", crash_at_checkpoint)
    return original_note


def _exit_after_durable_boundary(root: str, boundary: str, exit_code: int) -> None:
    coordinator, _state, _artifacts = _coordinator(Path(root))
    if boundary == CaptureMarkerState.RESERVATION_PLANNED.value:

        def exit_before_reservation(*_args: object, **_kwargs: object) -> None:
            os._exit(exit_code)

        coordinator.workspace.reserve = exit_before_reservation  # type: ignore[method-assign]
    else:
        target = CaptureMarkerState(boundary)
        original_advance = CaptureMarker.advance

        def exit_after_advance(
            marker: CaptureMarker,
            state: CaptureMarkerState,
            details: dict[str, object],
        ) -> None:
            original_advance(marker, state, details)
            if state is target:
                os._exit(exit_code)

        CaptureMarker.advance = exit_after_advance  # type: ignore[method-assign]
    asyncio.run(coordinator.execute(_request(), CancellationToken()))
    os._exit(99)


def _exit_after_rollback_checkpoint(root: str, step_count: int, exit_code: int) -> None:
    coordinator, _state_path, _artifacts = _coordinator(Path(root))
    original_note = CaptureMarker.note_rollback_verification

    def exit_after_confirmed_prefix(
        marker: CaptureMarker,
        rollback: dict[str, object],
    ) -> None:
        original_note(marker, rollback)
        steps = rollback.get("steps")
        if isinstance(steps, list) and len(steps) == step_count:
            os._exit(exit_code)

    CaptureMarker.note_rollback_verification = exit_after_confirmed_prefix  # type: ignore[method-assign]
    asyncio.run(coordinator.execute(_request(), CancellationToken()))
    os._exit(99)


def _exit_after_ap_restore_type_checkpoint(root: str, exit_code: int) -> None:
    root_path = Path(root)
    backend = _APArgvRecordingBackend(root_path / "ap-type-argv.jsonl")
    coordinator, _state_path, _artifacts = _coordinator(root_path, backend=backend)
    original_note = CaptureMarker.note_rollback_verification

    def exit_after_ap_type_is_durable(
        marker: CaptureMarker,
        rollback: dict[str, object],
    ) -> None:
        original_note(marker, rollback)
        steps = rollback.get("steps")
        if (
            isinstance(steps, list)
            and steps
            and isinstance(steps[-1], dict)
            and steps[-1].get("name") == "restore_type"
            and steps[-1].get("completed") is True
        ):
            os._exit(exit_code)

    CaptureMarker.note_rollback_verification = exit_after_ap_type_is_durable  # type: ignore[method-assign]
    asyncio.run(coordinator.execute(_request(), CancellationToken()))
    os._exit(99)


def _execute_capture_retry_process(root: str, results: Any) -> None:
    try:
        coordinator = _deferred_coordinator(Path(root))
        result = asyncio.run(coordinator.execute(_request(), CancellationToken()))
        results.put(("ok", result.metadata.get("reused")))
    except BaseException as error:
        results.put(("error", type(error).__name__, str(error)))


def _deferred_coordinator(root: Path) -> DeferredCaptureCoordinator:
    def forbidden_live_factory() -> CaptureCoordinator:
        raise AssertionError("binding retry constructed live capture dependencies")

    return DeferredCaptureCoordinator(
        state_dir=root / "state",
        artifact_root=root / "artifacts-sibling",
        capture_plan_builder=build_capture_execution_plan,
        live_factory=forbidden_live_factory,
        role="capture_node",
        enabled=True,
        agent_id_provider=lambda: AGENT_ID,
        authorization=_Authorization(),
        allowed_interfaces=frozenset({"wlan1"}),
        protected_interfaces=frozenset(),
        allowed_channels=frozenset({36}),
        allowed_frequencies_mhz=frozenset({5180}),
        allowed_widths_mhz=frozenset({20}),
        max_duration_seconds=30,
        max_size_bytes=4096,
    )


async def _execute_retry_in_fresh_process(root: Path) -> tuple[object, ...]:
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    process = context.Process(
        target=_execute_capture_retry_process,
        args=(str(root), results),
    )
    process.start()
    try:
        outcome = cast(
            tuple[object, ...],
            await asyncio.to_thread(results.get, True, 10.0),
        )
        await asyncio.to_thread(process.join, 20.0)
        assert not process.is_alive()
        assert process.exitcode == 0
        return outcome
    finally:
        if process.is_alive():
            process.terminate()
            await asyncio.to_thread(process.join, 5.0)
        process.close()
        results.close()
        results.join_thread()


@pytest.mark.parametrize(
    ("boundary", "exit_code"),
    tuple(
        (state.value, 70 + index)
        for index, state in enumerate(
            (
                CaptureMarkerState.RESERVATION_PLANNED,
                CaptureMarkerState.RESERVED,
                CaptureMarkerState.CAPTURE_COMPLETE,
                CaptureMarkerState.INTERFACE_RESTORED,
                CaptureMarkerState.STAGING_INTENT_DURABLE,
                CaptureMarkerState.LOCAL_ARTIFACT_COMMITTED,
                CaptureMarkerState.BINDING_PUBLISHED,
            )
        )
    ),
)
@pytest.mark.asyncio
async def test_second_process_recovers_every_durable_crash_boundary(
    tmp_path: Path,
    boundary: str,
    exit_code: int,
) -> None:
    context = multiprocessing.get_context("fork")
    process = context.Process(
        target=_exit_after_durable_boundary,
        args=(str(tmp_path), boundary, exit_code),
    )
    process.start()
    await asyncio.to_thread(process.join, 20.0)
    assert not process.is_alive()
    assert process.exitcode == exit_code

    marker = tmp_path / "state" / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    assert marker.is_file()
    assert f'"state":"{boundary}"'.encode() in marker.read_bytes()

    restarted, _state, artifacts = _coordinator(tmp_path)
    recovered = await restarted.execute(_request(), CancellationToken())
    assert recovered.status == "completed"
    assert recovered.artifact_path is not None
    assert recovered.artifact_path.is_relative_to(artifacts)


@pytest.mark.asyncio
async def test_restart_resumes_only_unconfirmed_rollback_suffix(tmp_path: Path) -> None:
    context = multiprocessing.get_context("fork")
    process = context.Process(
        target=_exit_after_rollback_checkpoint,
        args=(str(tmp_path), 2, 89),
    )
    process.start()
    await asyncio.to_thread(process.join, 20.0)
    assert not process.is_alive()
    assert process.exitcode == 89

    marker_path = tmp_path / "state" / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    events = [json.loads(line) for line in marker_path.read_text(encoding="utf-8").splitlines()]
    pending = [
        event
        for event in events
        if event["state"] == CaptureMarkerState.ROLLBACK_VERIFICATION_PENDING.value
    ]
    assert [step["name"] for step in pending[-1]["details"]["rollback"]["steps"]] == [
        "link_down",
        "restore_type",
    ]

    restarted, _state_path, _artifacts = _coordinator(tmp_path)
    backend = cast(SimulatedCaptureBackend, restarted.backend)
    backend.calls.clear()
    recovered = await restarted.execute(_request(), CancellationToken())

    assert recovered.status == "completed"
    assert backend.calls == ["set_frequency", "set_link", "set_managed", "snapshot"]


@pytest.mark.asyncio
async def test_ap_journal_rollback_and_crash_restart_use_only_exact_iw_token(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("fork")
    process = context.Process(
        target=_exit_after_ap_restore_type_checkpoint,
        args=(str(tmp_path), 90),
    )
    process.start()
    await asyncio.to_thread(process.join, 20.0)
    assert not process.is_alive()
    assert process.exitcode == 90

    journal = tmp_path / "state" / "capture-journal" / f"{EXECUTION_ID}.json"
    marker = tmp_path / "state" / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    argv_log = tmp_path / "ap-type-argv.jsonl"
    assert journal.is_file()
    assert marker.is_file()
    journal_payload = json.loads(journal.read_text(encoding="utf-8"))
    assert journal_payload["interface_state"]["interface_type"] == "AP"
    assert "__ap" not in journal.read_text(encoding="utf-8")
    rollback_reports = _marker_rollback_reports(marker)
    assert any(
        step.get("name") == "restore_type" and step.get("completed") is True
        for report in rollback_reports
        for step in cast(list[dict[str, object]], report["steps"])
    )

    argv_before_restart = [
        cast(list[str], json.loads(line))
        for line in argv_log.read_text(encoding="utf-8").splitlines()
    ]
    assert [argv[-1] for argv in argv_before_restart] == ["monitor", "__ap"]
    assert all("AP" not in argv and "ap" not in argv for argv in argv_before_restart)

    restarted_backend = _APArgvRecordingBackend(argv_log)
    restarted, _state_path, _artifacts = _coordinator(
        tmp_path,
        backend=restarted_backend,
    )
    try:
        recovered = await restarted.execute(_request(), CancellationToken())
    finally:
        _close_coordinator(restarted)

    assert recovered.status == "completed"
    assert restarted_backend.type_argv == []
    assert "set_type" not in restarted_backend.calls
    argv_after_restart = [
        cast(list[str], json.loads(line))
        for line in argv_log.read_text(encoding="utf-8").splitlines()
    ]
    assert argv_after_restart == argv_before_restart
    assert not journal.exists()
    assert not marker.exists()


@pytest.mark.asyncio
async def test_multiple_connections_are_checkpointed_individually_and_primary_is_last(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = SimulatedCaptureBackend(_multi_connection_state())
    coordinator, state, _artifacts = _coordinator(tmp_path, backend=backend)
    durable_reports: list[dict[str, object]] = []
    original_note = CaptureMarker.note_rollback_verification

    def record_checkpoint(
        marker: CaptureMarker,
        rollback: dict[str, object],
    ) -> None:
        durable_reports.append(json.loads(json.dumps(rollback)))
        original_note(marker, rollback)

    monkeypatch.setattr(CaptureMarker, "note_rollback_verification", record_checkpoint)

    result = await coordinator.execute(_request(), CancellationToken())

    assert result.status == "completed"
    assert tuple(call for call in backend.calls if call.startswith("restore_connection:")) == (
        _connection_backend_calls()
    )
    connection_steps = tuple(
        step for step in result.rollback.steps if step.connection_uuid is not None
    )
    assert tuple(step.name for step in connection_steps) == _connection_step_names()
    assert tuple(step.connection_uuid for step in connection_steps) == (
        SECONDARY_CONNECTION_UUID_A,
        SECONDARY_CONNECTION_UUID_B,
        PRIMARY_CONNECTION_UUID,
    )
    assert tuple(step.position for step in connection_steps) == (0, 1, 2)
    assert all(step.completed and step.operation_state == "confirmed" for step in connection_steps)
    assert len({step.operation_token for step in connection_steps}) == 3
    assert tuple(step.name for step in result.rollback.steps[-3:]) == (
        "verify_active_connections",
        "verify_primary_connection",
        "verify_interface_state",
    )

    for expected_step in connection_steps:
        observations = [
            step
            for report in durable_reports
            for step in cast(list[dict[str, object]], report["steps"])
            if step.get("name") == expected_step.name
        ]
        assert any(
            step.get("operation_state") == "planned"
            and step.get("evidence") == "intent_fsynced_before_command"
            for step in observations
        )
        assert any(
            step.get("operation_state") == "confirmed"
            and step.get("evidence") == "connection_restore_command_confirmed"
            for step in observations
        )
        assert {
            step.get("operation_token")
            for step in observations
            if step.get("operation_token") is not None
        } == {expected_step.operation_token}

    marker = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    journal = state / "capture-journal" / f"{EXECUTION_ID}.json"
    assert not marker.exists()
    assert not journal.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("target_index", [0, 1, 2])
async def test_restart_skips_each_durably_confirmed_connection_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_index: int,
) -> None:
    backend = SimulatedCaptureBackend(_multi_connection_state())
    coordinator, state, _artifacts = _coordinator(tmp_path, backend=backend)
    target_step = _connection_step_names()[target_index]
    original_note = _install_connection_checkpoint_crash(
        monkeypatch,
        target_step=target_step,
        after_persist=True,
    )

    with pytest.raises(SystemExit, match="post-checkpoint"):
        await coordinator.execute(_request(), CancellationToken())

    marker = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    journal = state / "capture-journal" / f"{EXECUTION_ID}.json"
    last_report = _marker_rollback_reports(marker)[-1]
    last_steps = cast(list[dict[str, object]], last_report["steps"])
    assert last_steps[-1]["name"] == target_step
    assert last_steps[-1]["operation_state"] == "confirmed"
    live_state = backend.state
    _close_coordinator(coordinator)
    monkeypatch.setattr(CaptureMarker, "note_rollback_verification", original_note)

    restarted_backend = SimulatedCaptureBackend(live_state)
    restarted, _state_path, _artifacts = _coordinator(
        tmp_path,
        backend=restarted_backend,
    )
    recovered = await restarted.execute(_request(), CancellationToken())

    assert recovered.status == "completed"
    assert (
        tuple(call for call in restarted_backend.calls if call.startswith("restore_connection:"))
        == _connection_backend_calls()[target_index + 1 :]
    )
    assert not marker.exists()
    assert not journal.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("target_index", [0, 1, 2])
async def test_restart_observes_command_effect_before_repeating_uncheckpointed_uuid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_index: int,
) -> None:
    backend = SimulatedCaptureBackend(_multi_connection_state())
    coordinator, state, _artifacts = _coordinator(tmp_path, backend=backend)
    target_step = _connection_step_names()[target_index]
    original_note = _install_connection_checkpoint_crash(
        monkeypatch,
        target_step=target_step,
        after_persist=False,
    )

    with pytest.raises(SystemExit, match="pre-checkpoint"):
        await coordinator.execute(_request(), CancellationToken())

    marker = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    last_report = _marker_rollback_reports(marker)[-1]
    last_steps = cast(list[dict[str, object]], last_report["steps"])
    assert last_steps[-1]["name"] == target_step
    assert last_steps[-1]["operation_state"] == "planned"
    live_state = backend.state
    _close_coordinator(coordinator)
    monkeypatch.setattr(CaptureMarker, "note_rollback_verification", original_note)

    restarted_backend = SimulatedCaptureBackend(live_state)
    restarted, _state_path, _artifacts = _coordinator(
        tmp_path,
        backend=restarted_backend,
    )
    recovered = await restarted.execute(_request(), CancellationToken())

    assert recovered.status == "completed"
    assert (
        tuple(call for call in restarted_backend.calls if call.startswith("restore_connection:"))
        == _connection_backend_calls()[target_index + 1 :]
    )
    recovered_target = next(step for step in recovered.rollback.steps if step.name == target_step)
    assert recovered_target.operation_state == "confirmed"
    assert recovered_target.evidence == "effect_observed_before_retry"


@pytest.mark.asyncio
@pytest.mark.parametrize("observation_status", ["partial", "unavailable"])
async def test_restart_keeps_planned_uuid_when_connection_observation_is_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    observation_status: str,
) -> None:
    backend = SimulatedCaptureBackend(_multi_connection_state())
    coordinator, state, _artifacts = _coordinator(tmp_path, backend=backend)
    original_note = _install_connection_checkpoint_crash(
        monkeypatch,
        target_step=_connection_step_names()[0],
        after_persist=False,
    )

    with pytest.raises(SystemExit, match="pre-checkpoint"):
        await coordinator.execute(_request(), CancellationToken())

    marker = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    journal = state / "capture-journal" / f"{EXECUTION_ID}.json"
    live_state = backend.state.model_copy(update={"active_connections_status": observation_status})
    _close_coordinator(coordinator)
    monkeypatch.setattr(CaptureMarker, "note_rollback_verification", original_note)

    restarted_backend = SimulatedCaptureBackend(live_state)
    restarted, _state_path, _artifacts = _coordinator(
        tmp_path,
        backend=restarted_backend,
    )
    with pytest.raises(CaptureOperationError) as pending:
        await restarted.execute(_request(), CancellationToken())

    assert pending.value.rollback.verification_status == "unavailable"
    assert not any(call.startswith("restore_connection:") for call in restarted_backend.calls)
    pending_step = next(
        step for step in pending.value.rollback.steps if step.name == _connection_step_names()[0]
    )
    assert pending_step.operation_state == "planned"
    assert pending_step.evidence == "connection_observation_incomplete"
    assert marker.is_file()
    assert journal.is_file()


@pytest.mark.asyncio
@pytest.mark.parametrize("verification_status", ["partial", "unavailable", "mismatch"])
async def test_multiple_connection_verification_retries_read_only_and_retires_only_at_end(
    tmp_path: Path,
    verification_status: str,
) -> None:
    backend = _MultiConnectionVerificationBackend(verification_status)
    coordinator, state, _artifacts = _coordinator(tmp_path, backend=backend)

    with pytest.raises(CaptureOperationError) as first:
        await coordinator.execute(_request(), CancellationToken())

    assert first.value.rollback.verification_status == verification_status
    assert tuple(call for call in backend.calls if call.startswith("restore_connection:")) == (
        _connection_backend_calls()
    )
    marker = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    journal = state / "capture-journal" / f"{EXECUTION_ID}.json"
    assert marker.is_file()
    assert journal.is_file()

    backend.verification_status = "complete"
    backend.calls.clear()
    recovered = await coordinator.execute(_request(), CancellationToken())

    assert recovered.status == "completed"
    assert backend.calls == ["snapshot"]
    assert not marker.exists()
    assert not journal.exists()


@pytest.mark.asyncio
async def test_deleted_connection_profile_stays_failed_without_uuid_substitution_or_retry(
    tmp_path: Path,
) -> None:
    failed_call = f"restore_connection:{SECONDARY_CONNECTION_UUID_A}"
    backend = SimulatedCaptureBackend(
        _multi_connection_state(),
        fail_steps=frozenset({failed_call}),
    )
    coordinator, state, _artifacts = _coordinator(tmp_path, backend=backend)

    with pytest.raises(CaptureOperationError) as first:
        await coordinator.execute(_request(), CancellationToken())

    connection_steps = tuple(
        step for step in first.value.rollback.steps if step.connection_uuid is not None
    )
    assert len(connection_steps) == 1
    assert connection_steps[0].name == _connection_step_names()[0]
    assert connection_steps[0].connection_uuid == SECONDARY_CONNECTION_UUID_A
    assert connection_steps[0].operation_state == "failed"
    assert connection_steps[0].evidence == "connection_restore_command_failed"
    assert tuple(call for call in backend.calls if call.startswith("restore_connection:")) == (
        failed_call,
    )
    marker = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    journal = state / "capture-journal" / f"{EXECUTION_ID}.json"
    assert marker.is_file()
    assert journal.is_file()

    backend.calls.clear()
    with pytest.raises(CaptureOperationError) as retry:
        await coordinator.execute(_request(), CancellationToken())

    assert retry.value.rollback.verification_status == "unavailable"
    assert backend.calls == []
    assert marker.is_file()
    assert journal.is_file()


@pytest.mark.asyncio
async def test_missing_connection_profile_is_durable_and_never_retried_or_substituted(
    tmp_path: Path,
) -> None:
    backend = _MissingConnectionProfileBackend(_multi_connection_state())
    coordinator, state, _artifacts = _coordinator(tmp_path, backend=backend)

    with pytest.raises(CaptureOperationError) as first:
        await coordinator.execute(_request(), CancellationToken())

    failed_step = next(
        step for step in first.value.rollback.steps if step.connection_uuid is not None
    )
    assert failed_step.name == _connection_step_names()[0]
    assert failed_step.connection_uuid == SECONDARY_CONNECTION_UUID_A
    assert failed_step.position == 0
    assert failed_step.operation_token is not None
    assert failed_step.operation_state == "failed"
    assert failed_step.reason == "connection_profile_missing"
    assert failed_step.evidence == "connection_profile_missing"
    assert tuple(call for call in backend.calls if call.startswith("restore_connection:")) == (
        f"restore_connection:{SECONDARY_CONNECTION_UUID_A}",
    )

    marker = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    journal = state / "capture-journal" / f"{EXECUTION_ID}.json"
    persisted = cast(
        list[dict[str, object]],
        _marker_rollback_reports(marker)[-1]["steps"],
    )[-1]
    assert persisted["connection_uuid"] == SECONDARY_CONNECTION_UUID_A
    assert persisted["position"] == 0
    assert persisted["operation_token"] == failed_step.operation_token
    assert persisted["operation_state"] == "failed"
    assert persisted["reason"] == "connection_profile_missing"
    assert persisted["evidence"] == "connection_profile_missing"
    assert marker.is_file()
    assert journal.is_file()

    backend.calls.clear()
    with pytest.raises(CaptureOperationError) as retry:
        await coordinator.execute(_request(), CancellationToken())

    assert retry.value.rollback.verification_status == "unavailable"
    assert backend.calls == []
    assert marker.is_file()
    assert journal.is_file()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("operation_token", "f" * 32),
        ("connection_uuid", SECONDARY_CONNECTION_UUID_B),
        ("position", 1),
        ("evidence", "intent_fsynced_before_command"),
    ],
)
async def test_restart_rejects_corrupt_connection_checkpoint_authority_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    replacement: object,
) -> None:
    backend = SimulatedCaptureBackend(_multi_connection_state())
    coordinator, state, _artifacts = _coordinator(tmp_path, backend=backend)
    original_note = _install_connection_checkpoint_crash(
        monkeypatch,
        target_step=_connection_step_names()[0],
        after_persist=True,
    )

    with pytest.raises(SystemExit, match="post-checkpoint"):
        await coordinator.execute(_request(), CancellationToken())

    live_state = backend.state
    marker = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    journal = state / "capture-journal" / f"{EXECUTION_ID}.json"
    _close_coordinator(coordinator)
    monkeypatch.setattr(CaptureMarker, "note_rollback_verification", original_note)
    _rewrite_last_marker_connection_step(
        marker,
        field=field,
        value=replacement,
    )

    restarted_backend = SimulatedCaptureBackend(live_state)
    restarted, _state_path, _artifacts = _coordinator(
        tmp_path,
        backend=restarted_backend,
    )
    with pytest.raises(CaptureManualRecoveryRequired, match="checkpoint authority is invalid"):
        await restarted.execute(_request(), CancellationToken())

    assert restarted_backend.calls == []
    assert marker.is_file()
    assert journal.is_file()


@pytest.mark.asyncio
async def test_historical_multi_connection_journal_without_primary_requires_manual_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = SimulatedCaptureBackend(_multi_connection_state())
    coordinator, state, _artifacts = _coordinator(tmp_path, backend=backend)
    original_note = _install_connection_checkpoint_crash(
        monkeypatch,
        target_step=_connection_step_names()[0],
        after_persist=True,
    )

    with pytest.raises(SystemExit, match="post-checkpoint"):
        await coordinator.execute(_request(), CancellationToken())

    live_state = backend.state
    marker = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    journal = state / "capture-journal" / f"{EXECUTION_ID}.json"
    _close_coordinator(coordinator)
    monkeypatch.setattr(CaptureMarker, "note_rollback_verification", original_note)
    payload = json.loads(journal.read_text(encoding="utf-8"))
    interface_state = cast(dict[str, object], payload["interface_state"])
    interface_state["network_manager_connection_uuid"] = None
    interface_state["primary_connection_uuid"] = None
    interface_state["network_manager_connection_name"] = None
    journal.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    os.chmod(journal, 0o600)

    restarted_backend = SimulatedCaptureBackend(live_state)
    restarted, _state_path, _artifacts = _coordinator(
        tmp_path,
        backend=restarted_backend,
    )
    with pytest.raises(CaptureManualRecoveryRequired, match="primary connection is unavailable"):
        await restarted.execute(_request(), CancellationToken())

    assert restarted_backend.calls == []
    assert marker.is_file()
    assert journal.is_file()


@pytest.mark.asyncio
async def test_capture_staging_and_restart_support_a_separate_filesystem(
    tmp_path: Path,
) -> None:
    shared_memory = Path("/dev/shm")  # noqa: S108 - isolated second-filesystem fixture
    if not shared_memory.is_dir():
        pytest.skip("a second temporary filesystem is unavailable")
    with tempfile.TemporaryDirectory(prefix="wto-artifacts-", dir=shared_memory) as raw:
        artifacts = Path(raw)
        os.chmod(artifacts, 0o700)
        if artifacts.stat().st_dev == tmp_path.stat().st_dev:
            pytest.skip("the available temporary roots share one filesystem")

        coordinator, state, _ = _coordinator(tmp_path, artifact_root=artifacts)
        first = await coordinator.execute(_request(), CancellationToken())
        assert first.status == "completed"
        assert first.artifact_path is not None
        assert first.artifact_path.is_relative_to(artifacts)
        assert (state / "agent.sqlite3").is_file()
        assert not (artifacts / "agent.sqlite3").exists()

        cast(FileCaptureJournal, coordinator.journal).close()
        cast(CaptureRecoveryStore, coordinator.recovery_store).close()
        restarted, _, _ = _coordinator(tmp_path, artifact_root=artifacts)
        reused = await restarted.execute(_request(), CancellationToken())
        assert reused.artifact_path == first.artifact_path
        assert reused.metadata == {**first.metadata, "reused": True}


@pytest.mark.asyncio
async def test_durable_capture_binding_preserves_original_result_and_rejects_conflict(
    tmp_path: Path,
) -> None:
    coordinator, state, artifacts = _coordinator(tmp_path)
    request = _request()
    first = await coordinator.execute(request, CancellationToken())

    assert first.status == "completed"
    assert first.artifact_path is not None
    assert first.artifact_path.is_relative_to(artifacts)
    assert first.metadata["provider_version"] == "evidence-only-1.0"
    assert "reused" not in first.metadata
    assert list((state / "capture-bindings").glob("*.json"))
    assert not list((state / "capture-markers").glob("*.jsonl"))
    assert list((state / "capture-markers").glob(".capture-marker-retired-*"))
    assert list(artifacts.glob(".capture-output-quarantine-*"))

    original_metadata = dict(first.metadata)
    original_manifest = dict(first.artifact_manifest or {})

    async def forbidden_live_probe(*_args: object, **_kwargs: object) -> bool:
        raise AssertionError("exact binding reuse queried live interface state")

    def forbidden_preflight(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("exact binding reuse ran preflight")

    def forbidden_reservation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("exact binding reuse reserved a workspace")

    coordinator.backend.is_connectivity_interface = forbidden_live_probe  # type: ignore[method-assign]
    coordinator.backend.monitor_supported = forbidden_live_probe  # type: ignore[method-assign]
    coordinator.backend.snapshot = forbidden_live_probe  # type: ignore[method-assign,assignment]
    coordinator.backend.preflight = forbidden_preflight  # type: ignore[method-assign]
    coordinator.workspace.reserve = forbidden_reservation  # type: ignore[method-assign]
    coordinator.provider_ready = False
    coordinator.privileged_ready = False
    coordinator.technical_ready = False
    coordinator._tree_containment_readiness = lambda: False
    second = await coordinator.execute(request, CancellationToken())
    assert second.artifact_path == first.artifact_path
    assert second.artifact_manifest == original_manifest
    assert second.metadata == {**original_metadata, "reused": True}
    assert second.rollback == first.rollback

    with pytest.raises(CaptureIdempotencyConflict, match="fingerprint"):
        await coordinator.execute(
            _request(duration_seconds=6),
            CancellationToken(),
        )


@pytest.mark.asyncio
async def test_restarted_adapter_reuses_binding_without_any_live_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    producer, state, artifacts = _coordinator(tmp_path)
    producer.backend.capture_plan = build_capture_execution_plan  # type: ignore[method-assign]
    try:
        first = await producer.execute(_request(), CancellationToken())
    finally:
        _close_coordinator(producer)
    assert first.artifact_path is not None
    _provision_adapter_identity(state)

    journal_root = state / "capture-journal"
    os.chmod(journal_root, 0o755)  # noqa: S103 - intentionally unsafe journal fixture
    original_metadata = dict(first.metadata)
    original_manifest = dict(first.artifact_manifest or {})
    before = _filesystem_snapshot(state, artifacts)

    adapter = _restart_adapter(state, artifacts, monkeypatch)
    reused = await adapter.capture_provider.execute(_request(), CancellationToken())

    assert reused.status == first.status
    assert reused.reason == first.reason
    assert reused.artifact_path == first.artifact_path
    assert reused.artifact_manifest == original_manifest
    assert reused.metadata == {**original_metadata, "reused": True}
    assert reused.rollback == first.rollback
    assert adapter._live_initialized is False
    assert adapter.capture_provider._live is None
    assert _filesystem_snapshot(state, artifacts) == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected_error", "message"),
    [
        ("binding_corrupt", CaptureManualRecoveryRequired, "binding JSON is corrupt"),
        ("artifact_pruned", CaptureManualRecoveryRequired, "artifact is missing"),
        ("artifact_hash", CaptureManualRecoveryRequired, "artifact content changed"),
        ("artifact_identity", CaptureManualRecoveryRequired, "artifact inode changed"),
        ("rollback_evidence", CaptureManualRecoveryRequired, "rollback evidence"),
        ("rollback_incomplete", CaptureManualRecoveryRequired, "rollback evidence"),
        ("completed_with_reason", CaptureManualRecoveryRequired, "rollback evidence"),
        ("incompatible", CaptureIdempotencyConflict, "fingerprint"),
    ],
)
async def test_restarted_adapter_binding_failures_never_fall_through_to_live_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    expected_error: type[Exception],
    message: str,
) -> None:
    producer, state, artifacts = _coordinator(tmp_path)
    producer.backend.capture_plan = build_capture_execution_plan  # type: ignore[method-assign]
    try:
        first = await producer.execute(_request(), CancellationToken())
    finally:
        _close_coordinator(producer)
    assert first.artifact_path is not None
    _provision_adapter_identity(state)

    request = _request()
    if failure == "binding_corrupt":
        binding = next((state / "capture-bindings").glob("*.json"))
        binding.write_text("{", encoding="utf-8")
        os.chmod(binding, 0o600)
    elif failure == "artifact_pruned":
        first.artifact_path.unlink()
    elif failure == "artifact_hash":
        content = first.artifact_path.read_bytes()
        os.chmod(first.artifact_path, 0o600)
        first.artifact_path.write_bytes(b"x" * len(content))
        os.chmod(first.artifact_path, 0o400)
    elif failure == "artifact_identity":
        content = first.artifact_path.read_bytes()
        replaced = first.artifact_path.with_name("artifact-replaced-for-test.pcapng")
        first.artifact_path.rename(replaced)
        first.artifact_path.write_bytes(content)
        os.chmod(first.artifact_path, 0o400)
    elif failure in {"rollback_evidence", "rollback_incomplete", "completed_with_reason"}:
        binding = next((state / "capture-bindings").glob("*.json"))
        payload = json.loads(binding.read_text(encoding="utf-8"))
        if failure == "rollback_evidence":
            payload["rollback"]["steps"] = []
        elif failure == "rollback_incomplete":
            assert payload["status"] == "completed"
            payload["rollback"]["complete"] = False
        else:
            assert payload["status"] == "completed"
            payload["reason"] = "rollback_incomplete"
        binding.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        os.chmod(binding, 0o600)
    else:
        request = _request(duration_seconds=6)

    before = _filesystem_snapshot(state, artifacts)
    adapter = _restart_adapter(state, artifacts, monkeypatch)

    with pytest.raises(expected_error, match=message):
        await adapter.capture_provider.execute(request, CancellationToken())

    assert adapter._live_initialized is False
    assert adapter.capture_provider._live is None
    assert _filesystem_snapshot(state, artifacts) == before


@pytest.mark.asyncio
async def test_revoked_caller_cannot_read_an_existing_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator, state, _artifacts = _coordinator(tmp_path)
    await coordinator.execute(_request(), CancellationToken())
    binding = next((state / "capture-bindings").glob("*.json"))
    binding_before = binding.read_bytes()
    store = cast(CaptureRecoveryStore, coordinator.recovery_store)

    def forbidden_binding_read(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("revoked caller reached binding lookup")

    monkeypatch.setattr(store, "read_binding", forbidden_binding_read)
    coordinator.authorization = _RevokedAuthorization()
    cast(SimulatedCaptureBackend, coordinator.backend).calls.clear()

    with pytest.raises(PermissionError, match="revoked_for_test"):
        await coordinator.execute(_request(), CancellationToken())

    assert binding.read_bytes() == binding_before
    assert cast(SimulatedCaptureBackend, coordinator.backend).calls == []


@pytest.mark.asyncio
async def test_pruned_binding_artifact_requires_manual_recovery_without_recapture(
    tmp_path: Path,
) -> None:
    coordinator, state, _artifacts = _coordinator(tmp_path)
    first = await coordinator.execute(_request(), CancellationToken())
    assert first.artifact_path is not None
    binding = next((state / "capture-bindings").glob("*.json"))
    binding_before = binding.read_bytes()
    first.artifact_path.unlink()
    backend = cast(SimulatedCaptureBackend, coordinator.backend)
    backend.calls.clear()

    async def forbidden_live_probe(*_args: object, **_kwargs: object) -> bool:
        raise AssertionError("missing bound artifact triggered a live probe")

    def forbidden_reservation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("missing bound artifact triggered recapture")

    backend.is_connectivity_interface = forbidden_live_probe  # type: ignore[method-assign]
    backend.monitor_supported = forbidden_live_probe  # type: ignore[method-assign]
    backend.snapshot = forbidden_live_probe  # type: ignore[method-assign,assignment]
    coordinator.workspace.reserve = forbidden_reservation  # type: ignore[method-assign]

    with pytest.raises(CaptureManualRecoveryRequired, match="artifact"):
        await coordinator.execute(_request(), CancellationToken())

    assert backend.calls == []
    assert binding.read_bytes() == binding_before
    assert not list((state / "capture-markers").glob("*.jsonl"))
    assert not list((state / "capture-journal").glob("*.json"))


@pytest.mark.asyncio
async def test_operation_lock_serializes_binding_retry_across_processes(
    tmp_path: Path,
) -> None:
    coordinator, _state, _artifacts = _coordinator(tmp_path)
    coordinator.backend.capture_plan = build_capture_execution_plan  # type: ignore[method-assign]
    await coordinator.execute(_request(), CancellationToken())
    store = cast(CaptureRecoveryStore, coordinator.recovery_store)
    held_lock = store.acquire_operation_lock(IDEMPOTENCY_KEY)

    try:
        blocked = await _execute_retry_in_fresh_process(tmp_path)
    finally:
        held_lock.close()

    assert blocked[:2] == ("error", "CaptureInProgressError")
    assert "already active" in str(blocked[2])
    assert await _execute_retry_in_fresh_process(tmp_path) == ("ok", True)


@pytest.mark.asyncio
async def test_retry_does_not_build_live_dependencies_before_concurrent_publication(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    artifacts = tmp_path / "artifacts-sibling"
    state.mkdir(mode=0o700)
    artifacts.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    os.chmod(artifacts, 0o700)
    store = CaptureRecoveryStore(state, artifacts)
    held_lock = store.acquire_operation_lock(IDEMPOTENCY_KEY)

    try:
        blocked = await _execute_retry_in_fresh_process(tmp_path)
    finally:
        held_lock.close()
        store.close()

    assert blocked[:2] == ("error", "CaptureInProgressError")
    assert "already active" in str(blocked[2])
    assert not list((state / "capture-bindings").glob("*.json"))


@pytest.mark.asyncio
@pytest.mark.parametrize("wide_width_mhz", [80, 160])
async def test_legacy_v1_binding_reuse_is_limited_to_20_mhz(
    tmp_path: Path,
    wide_width_mhz: int,
) -> None:
    coordinator, state, _artifacts = _coordinator(tmp_path)
    request = _request()
    first = await coordinator.execute(request, CancellationToken())
    binding_path = next((state / "capture-bindings").glob("*.json"))
    payload = json.loads(binding_path.read_text(encoding="utf-8"))
    legacy = canonical_capture_fingerprint_v1(request, coordinator.backend.capture_plan(request))
    payload["fingerprint_version"] = legacy.version
    payload["fingerprint_sha256"] = legacy.sha256
    payload["metadata"]["fingerprint_version"] = legacy.version
    payload["metadata"]["fingerprint_sha256"] = legacy.sha256
    binding_path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    os.chmod(binding_path, 0o600)

    reused = await coordinator.execute(request, CancellationToken())

    assert reused.artifact_path == first.artifact_path
    assert reused.metadata["reused"] is True
    assert reused.metadata["fingerprint_version"] == "capture-functional-v1"

    wide_request = _request(width_mhz=wide_width_mhz)
    coordinator.allowed_widths_mhz = frozenset({20, wide_width_mhz})
    payload["fingerprint_version"] = "capture-functional-v1"
    payload["fingerprint_sha256"] = "f" * 64
    payload["metadata"]["fingerprint_version"] = "capture-functional-v1"
    payload["metadata"]["fingerprint_sha256"] = "f" * 64
    binding_path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    os.chmod(binding_path, 0o600)
    with pytest.raises(CaptureIdempotencyConflict, match="fingerprint"):
        await coordinator.execute(wide_request, CancellationToken())


@pytest.mark.asyncio
async def test_retry_detects_same_size_artifact_modification(tmp_path: Path) -> None:
    coordinator, _state_dir, _artifacts = _coordinator(tmp_path)
    first = await coordinator.execute(_request(), CancellationToken())
    assert first.artifact_path is not None
    content = first.artifact_path.read_bytes()
    os.chmod(first.artifact_path, 0o600)
    first.artifact_path.write_bytes(b"x" * len(content))
    os.chmod(first.artifact_path, 0o400)

    with pytest.raises(RuntimeError, match="content changed"):
        await coordinator.execute(_request(), CancellationToken())


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ("truncate", "hardlink", "replacement"))
async def test_retry_rejects_artifact_identity_changes(
    tmp_path: Path,
    mutation: str,
) -> None:
    coordinator, _state_dir, artifacts = _coordinator(tmp_path)
    first = await coordinator.execute(_request(), CancellationToken())
    assert first.artifact_path is not None
    path = first.artifact_path
    content = path.read_bytes()
    if mutation == "truncate":
        os.chmod(path, 0o600)
        path.write_bytes(content[:-1])
        os.chmod(path, 0o400)
    elif mutation == "hardlink":
        os.link(path, artifacts / "artifact-extra-link.pcapng")
    else:
        replaced = artifacts / "outbox" / "artifact-replaced-original.pcapng"
        path.rename(replaced)
        path.write_bytes(content)
        os.chmod(path, 0o400)

    with pytest.raises(RuntimeError, match="identity|inode"):
        await coordinator.execute(_request(), CancellationToken())


@pytest.mark.asyncio
async def test_binding_rejects_changed_artifact_root(tmp_path: Path) -> None:
    coordinator, state, _artifacts = _coordinator(tmp_path)
    first = await coordinator.execute(_request(), CancellationToken())
    replacement_root = tmp_path / "replacement-artifacts"
    replacement_root.mkdir(mode=0o700)
    os.chmod(replacement_root, 0o700)
    replacement_store = CaptureRecoveryStore(state, replacement_root)
    with pytest.raises(CaptureManualRecoveryRequired, match="artifact root changed"):
        replacement_store.read_binding(
            task_id=TASK_ID,
            execution_id=EXECUTION_ID,
            idempotency_key=IDEMPOTENCY_KEY,
            fingerprint=CaptureFingerprint(
                str(first.metadata["fingerprint_version"]),
                str(first.metadata["fingerprint_sha256"]),
            ),
        )


@pytest.mark.asyncio
async def test_reservation_planned_is_durable_before_source_o_excl(tmp_path: Path) -> None:
    coordinator, state, artifacts = _coordinator(tmp_path)
    observed: list[str] = []
    original_reserve = coordinator.workspace.reserve

    def guarded_reserve(  # type: ignore[no-untyped-def]
        execution_id: UUID,
        capture_format: str,
        *,
        source_name: str | None = None,
    ):
        marker = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
        assert marker.is_file()
        assert b'"state":"RESERVATION_PLANNED"' in marker.read_bytes()
        assert source_name == _planned_source_name(state)
        assert source_name is not None
        source = artifacts / source_name
        assert not source.exists()
        observed.append("planned_before_reserve")
        return original_reserve(
            execution_id,
            capture_format,
            source_name=source_name,
        )

    coordinator.workspace.reserve = guarded_reserve  # type: ignore[method-assign]
    await coordinator.execute(_request(), CancellationToken())
    assert observed == ["planned_before_reserve"]


@pytest.mark.asyncio
async def test_restart_resumes_from_interface_restored_marker(tmp_path: Path) -> None:
    coordinator, state, _artifacts = _coordinator(tmp_path)
    original_stage = coordinator.stager.stage_from_descriptor

    async def crash_before_staging(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        raise SystemExit("simulated process boundary")

    coordinator.stager.stage_from_descriptor = crash_before_staging  # type: ignore[method-assign]
    with pytest.raises(SystemExit, match="process boundary"):
        await coordinator.execute(_request(), CancellationToken())

    marker = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    assert marker.is_file()
    assert b'"state":"INTERFACE_RESTORED"' in marker.read_bytes()
    assert not list((state / "capture-journal").glob("*.json"))

    coordinator.stager.stage_from_descriptor = original_stage  # type: ignore[method-assign]
    recovered = await coordinator.execute(_request(), CancellationToken())
    assert recovered.status == "completed"
    assert not marker.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["partial", "unavailable", "mismatch"])
async def test_rollback_verification_pending_retries_read_only_without_mutators(
    tmp_path: Path,
    status: str,
) -> None:
    coordinator, state, _artifacts = _coordinator(tmp_path)
    backend = _TransientRollbackVerificationBackend(status)
    coordinator.backend = backend

    with pytest.raises(CaptureOperationError) as first:
        await coordinator.execute(_request(), CancellationToken())

    assert first.value.rollback.verification_status == status
    marker = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    journal = state / "capture-journal" / f"{EXECUTION_ID}.json"
    assert marker.is_file()
    assert journal.is_file()
    assert b'"state":"ROLLBACK_VERIFICATION_PENDING"' in marker.read_bytes()

    cast(FileCaptureJournal, coordinator.journal).close()
    cast(CaptureRecoveryStore, coordinator.recovery_store).close()
    restarted, _state_path, _artifacts = _coordinator(tmp_path)
    restarted_backend = cast(SimulatedCaptureBackend, restarted.backend)
    recovered = await restarted.execute(_request(), CancellationToken())

    assert recovered.status == "completed"
    assert restarted_backend.calls == ["snapshot"]
    assert not marker.exists()
    assert not journal.exists()


@pytest.mark.asyncio
async def test_failed_capture_pending_verification_never_repeats_confirmed_mutators(
    tmp_path: Path,
) -> None:
    coordinator, state, _artifacts = _coordinator(tmp_path)
    backend = _TransientRollbackVerificationBackend("unavailable")
    backend.fail_steps = frozenset({"capture"})
    coordinator.backend = backend

    with pytest.raises(CaptureOperationError) as first:
        await coordinator.execute(_request(), CancellationToken())

    assert first.value.rollback.verification_status == "unavailable"
    marker = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    journal = state / "capture-journal" / f"{EXECUTION_ID}.json"
    assert marker.is_file()
    assert journal.is_file()

    backend.verification_status = "complete"
    backend.calls.clear()
    with pytest.raises(CaptureOperationError, match="recovered_incomplete_capture"):
        await coordinator.execute(_request(), CancellationToken())

    assert backend.calls == ["snapshot"]
    assert not marker.exists()
    assert not journal.exists()


@pytest.mark.asyncio
async def test_restart_recovers_planned_marker_with_no_source(tmp_path: Path) -> None:
    coordinator, state, artifacts = _coordinator(tmp_path)
    original_reserve = coordinator.workspace.reserve

    def unavailable_reservation(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        raise OSError("simulated reservation boundary")

    coordinator.workspace.reserve = unavailable_reservation  # type: ignore[method-assign]
    with pytest.raises(OSError, match="reservation boundary"):
        await coordinator.execute(_request(), CancellationToken())
    marker = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    assert marker.is_file()
    assert b'"state":"RESERVATION_PLANNED"' in marker.read_bytes()
    assert not list(artifacts.glob(f"capture-{EXECUTION_ID}-*.pcapng"))

    coordinator.workspace.reserve = original_reserve  # type: ignore[method-assign]
    assert (await coordinator.execute(_request(), CancellationToken())).status == "completed"


@pytest.mark.asyncio
async def test_planned_marker_does_not_claim_unexpected_named_file(tmp_path: Path) -> None:
    coordinator, state, artifacts = _coordinator(tmp_path)
    original_reserve = coordinator.workspace.reserve

    def unavailable_reservation(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        raise OSError("simulated reservation boundary")

    coordinator.workspace.reserve = unavailable_reservation  # type: ignore[method-assign]
    with pytest.raises(OSError):
        await coordinator.execute(_request(), CancellationToken())
    assert (state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl").is_file()
    unexpected = artifacts / _planned_source_name(state)
    unexpected.write_bytes(b"foreign bytes")
    os.chmod(unexpected, 0o600)

    coordinator.workspace.reserve = original_reserve  # type: ignore[method-assign]
    with pytest.raises(CaptureManualRecoveryRequired, match="unexpected non-empty source"):
        await coordinator.execute(_request(), CancellationToken())


@pytest.mark.asyncio
async def test_planned_marker_ignores_unbound_conventional_capture_name(tmp_path: Path) -> None:
    coordinator, _state, artifacts = _coordinator(tmp_path)
    foreign = artifacts / f"capture-{EXECUTION_ID}.pcapng"
    foreign.write_bytes(b"foreign conventional name")
    os.chmod(foreign, 0o600)

    completed = await coordinator.execute(_request(), CancellationToken())

    assert completed.status == "completed"
    assert foreign.read_bytes() == b"foreign conventional name"
    assert completed.artifact_path is not None
    assert completed.artifact_path != foreign


@pytest.mark.asyncio
async def test_restart_adopts_only_marker_authorized_empty_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator, state, artifacts = _coordinator(tmp_path)
    original_advance = CaptureMarker.advance
    crash_once = True

    def crash_before_reserved_event(
        marker: CaptureMarker,
        marker_state: CaptureMarkerState,
        details: dict[str, object],
    ) -> None:
        nonlocal crash_once
        if marker_state is CaptureMarkerState.RESERVED and crash_once:
            crash_once = False
            raise SystemExit("simulated reserved marker boundary")
        original_advance(marker, marker_state, details)

    monkeypatch.setattr(CaptureMarker, "advance", crash_before_reserved_event)
    with pytest.raises(SystemExit, match="reserved marker boundary"):
        await coordinator.execute(_request(), CancellationToken())

    marker_path = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    source = artifacts / _planned_source_name(state)
    assert b'"state":"RESERVATION_PLANNED"' in marker_path.read_bytes()
    assert source.is_file() and source.stat().st_size == 0

    recovered = await coordinator.execute(_request(), CancellationToken())
    assert recovered.status == "completed"


def test_marker_lock_serializes_processes_and_fingerprint_conflicts(tmp_path: Path) -> None:
    state = tmp_path / "state"
    artifacts = tmp_path / "artifacts"
    state.mkdir(mode=0o700)
    artifacts.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    os.chmod(artifacts, 0o700)
    first_store = CaptureRecoveryStore(state, artifacts)
    second_store = CaptureRecoveryStore(state, artifacts)
    fingerprint = CaptureFingerprint("capture-functional-v1", "a" * 64)
    marker, created = first_store.begin_marker(
        task_id=TASK_ID,
        execution_id=EXECUTION_ID,
        idempotency_key=IDEMPOTENCY_KEY,
        fingerprint=fingerprint,
        request={"functional": True},
        capture_format="pcapng",
    )
    assert created
    with pytest.raises(CaptureInProgressError):
        second_store.begin_marker(
            task_id=TASK_ID,
            execution_id=EXECUTION_ID,
            idempotency_key=IDEMPOTENCY_KEY,
            fingerprint=fingerprint,
            request={"functional": True},
            capture_format="pcapng",
        )
    marker.close()

    reopened, created = second_store.begin_marker(
        task_id=TASK_ID,
        execution_id=EXECUTION_ID,
        idempotency_key=IDEMPOTENCY_KEY,
        fingerprint=fingerprint,
        request={"functional": True},
        capture_format="pcapng",
    )
    assert not created
    reopened.close()
    with pytest.raises(CaptureIdempotencyConflict, match="fingerprint"):
        second_store.begin_marker(
            task_id=TASK_ID,
            execution_id=EXECUTION_ID,
            idempotency_key=IDEMPOTENCY_KEY,
            fingerprint=CaptureFingerprint("capture-functional-v1", "b" * 64),
            request={"functional": False},
            capture_format="pcapng",
        )


def test_corrupt_marker_is_manual_recovery_not_implicit_reuse(tmp_path: Path) -> None:
    state = tmp_path / "state"
    artifacts = tmp_path / "artifacts"
    state.mkdir(mode=0o700)
    artifacts.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    os.chmod(artifacts, 0o700)
    store = CaptureRecoveryStore(state, artifacts)
    marker = state / "capture-markers" / f"{IDEMPOTENCY_KEY}.jsonl"
    marker.write_bytes(b"{corrupt\n")
    os.chmod(marker, 0o600)
    with pytest.raises(CaptureManualRecoveryRequired, match="corrupt"):
        store.begin_marker(
            task_id=TASK_ID,
            execution_id=EXECUTION_ID,
            idempotency_key=IDEMPOTENCY_KEY,
            fingerprint=CaptureFingerprint("capture-functional-v1", "a" * 64),
            request={"functional": True},
            capture_format="pcapng",
        )


@pytest.mark.asyncio
async def test_legacy_artifact_without_fingerprinted_binding_fails_closed(
    tmp_path: Path,
) -> None:
    coordinator, _state, artifacts = _coordinator(tmp_path)
    request = _request()
    source = artifacts / "legacy-source.pcapng"
    source.write_bytes(b"legacy capture bytes")
    os.chmod(source, 0o600)
    manifest = {
        **coordinator._artifact_identity(request),
        "created_at": "2026-07-17T00:00:00Z",
    }
    await coordinator.stager.stage(
        manifest,
        source,
        request.task_id,
        maximum_size_bytes=request.max_size_bytes,
        cancellation=CancellationToken(),
    )

    with pytest.raises(CaptureManualRecoveryRequired, match="without a fingerprinted binding"):
        await coordinator.execute(request, CancellationToken())


def test_capture_intent_v2_requires_matching_private_authority(tmp_path: Path) -> None:
    coordinator, _state, _artifacts = _coordinator(tmp_path)
    stager = cast(SQLiteArtifactStager, coordinator.stager)
    request = _request()
    manifest = {
        **coordinator._artifact_identity(request),
        "created_at": "2026-07-17T00:00:00Z",
        "size_bytes": 16,
        "sha256": "a" * 64,
    }
    authority: dict[str, object] = {
        "task_id": str(TASK_ID),
        "execution_id": str(EXECUTION_ID),
        "idempotency_key": str(IDEMPOTENCY_KEY),
        "fingerprint_version": "capture-functional-v1",
        "fingerprint_sha256": "b" * 64,
        "operation_token": "c" * 32,
    }
    descriptors = stager._open_managed_tree()
    try:
        intent = stager._write_intent(
            descriptors[3],
            task_id=str(TASK_ID),
            temporary_name=".staging-capture-authority",
            final_name="artifact-capture-authority.pcapng",
            manifest=manifest,
            capture_authority=authority,
        )
        decoded = stager._read_intent(descriptors[3], intent.name)
        assert decoded.capture_authority == authority
        with pytest.raises(ValueError, match="execution_id is inconsistent"):
            stager._write_intent(
                descriptors[3],
                task_id=str(TASK_ID),
                temporary_name=".staging-conflict",
                final_name="artifact-conflict.pcapng",
                manifest=manifest,
                capture_authority={
                    **authority,
                    "execution_id": "20000000-0000-4000-8000-000000000099",
                },
            )
    finally:
        stager._close_descriptors(tuple(reversed(descriptors)))
