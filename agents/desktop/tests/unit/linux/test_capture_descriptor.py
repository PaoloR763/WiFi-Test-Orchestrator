from __future__ import annotations

import asyncio
import hashlib
import os
import select
import signal
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from wto_desktop_agent.application.artifacts import SQLiteArtifactStager, StagedArtifact
from wto_desktop_agent.domain.models import LocalTaskEnvelope
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.platforms.common import (
    CommandOutputMode,
    CommandSpec,
    LinuxCleanupScope,
    LinuxProcessContext,
    LinuxProcessRunner,
)
from wto_desktop_agent.platforms.linux.capture import (
    MONITOR_CAPTURE_CAPABILITY,
    CaptureCoordinator,
    CaptureOperationError,
    CaptureRequest,
    CaptureWorkspace,
    InterfaceState,
    PrivilegedAuthorizationDecision,
)
from wto_desktop_agent.platforms.linux.capture_backend import LinuxCommandCaptureBackend
from wto_desktop_agent.platforms.linux.capture_commands import DumpcapArguments
from wto_desktop_agent.platforms.linux.frequency import validate_complete_channel_definition
from wto_desktop_agent.platforms.linux.secure_fs import FileIdentity
from wto_desktop_agent.ports.platform import CommandRequest, ProcessResult
from wto_desktop_agent.ports.plugins import CancellationToken

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Linux pidfd, spawn guard, and descriptor semantics require Linux",
)

TASK_ID = UUID("10000000-0000-4000-8000-000000000001")
EXECUTION_ID = UUID("20000000-0000-4000-8000-000000000001")
IDEMPOTENCY_KEY = UUID("30000000-0000-4000-8000-000000000001")
AGENT_ID = "40000000-0000-4000-8000-000000000001"
CONNECTION_UUID = "50000000-0000-4000-8000-000000000001"
PAYLOAD = b"\x0a\x0d\x0d\x0aWTO-FAKE-DUMPCAP\x00\xff"
DIAGNOSTIC = b"wto-fake-dumpcap-diagnostic"


class _Authorization:
    def authorize(
        self,
        *,
        agent_id: str | None,
        capability_id: str,
    ) -> PrivilegedAuthorizationDecision:
        allowed = agent_id == AGENT_ID and capability_id == MONITOR_CAPTURE_CAPABILITY
        return PrivilegedAuthorizationDecision(allowed, None if allowed else "denied")


class _FakeCgroupHandle:
    def __init__(self, events: list[str]) -> None:
        self.path = Path("/sys/fs/cgroup/fake/wto-exec-capture")
        self.events = events
        self.pid: int | None = None
        self.pidfd: int | None = None
        self.closed = False

    def attach_pid(self, pid: int) -> None:
        self.events.append("attach")
        self.pid = pid
        self.pidfd = os.pidfd_open(pid)

    def verify_pid(self, pid: int) -> None:
        assert pid == self.pid
        assert self.pidfd is not None
        signal.pidfd_send_signal(self.pidfd, 0)
        self.events.append("verify")

    def kill_remaining(self) -> None:
        assert self.pidfd is not None
        self.events.append("cgroup.kill")
        try:
            signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def is_populated(self) -> bool:
        if self.pidfd is None:
            return False
        readable, _, _ = select.select([self.pidfd], [], [], 0)
        return not readable

    async def wait_empty(self, deadline_monotonic: float) -> None:
        self.events.append("wait_empty")
        while self.is_populated():
            if asyncio.get_running_loop().time() >= deadline_monotonic:
                raise RuntimeError("fake cgroup remained populated")
            await asyncio.sleep(0.01)

    def remove_empty(self) -> None:
        if self.is_populated():
            raise RuntimeError("fake cgroup remained populated")
        self.events.append("remove")

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.events.append("close")
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None


class _FakeCgroupManager:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.handles: list[_FakeCgroupHandle] = []

    @property
    def readiness(self) -> object:
        return SimpleNamespace(available=True, reason=None)

    def create_execution(self) -> _FakeCgroupHandle:
        self.events.append("create")
        handle = _FakeCgroupHandle(self.events)
        self.handles.append(handle)
        return handle


class _ObservedLinuxRunner(LinuxProcessRunner):
    def __init__(self, spec: CommandSpec, manager: _FakeCgroupManager) -> None:
        super().__init__({spec.command_id: spec}, cgroup_manager=manager)  # type: ignore[arg-type]
        self.events = manager.events
        self.results: list[ProcessResult] = []
        self.released = asyncio.Event()
        self.stdout_identity_before_spawn: tuple[int, int] | None = None

    async def _after_guard_release_sent(self, context: LinuxProcessContext) -> None:
        assert context.pidfd >= 0
        assert context.cgroup is not None
        self.events.append("release")
        self.released.set()
        await super()._after_guard_release_sent(context)

    async def run_with_stdout_descriptor(
        self,
        request: CommandRequest,
        cancellation: CancellationToken,
        *,
        stdout_descriptor: int,
    ) -> ProcessResult:
        metadata = os.fstat(stdout_descriptor)
        self.stdout_identity_before_spawn = (int(metadata.st_dev), int(metadata.st_ino))
        result = await super().run_with_stdout_descriptor(
            request,
            cancellation,
            stdout_descriptor=stdout_descriptor,
        )
        self.results.append(result)
        return result


class _CoordinatorBackend(LinuxCommandCaptureBackend):
    def __init__(self, runner: _ObservedLinuxRunner) -> None:
        super().__init__(runner, frozenset({"linux.dumpcap.capture"}))
        self.state = InterfaceState(
            interface="wlan1",
            interface_type="managed",
            administratively_up=True,
            network_manager_managed=True,
            channel=1,
            frequency_mhz=2412,
            width_mhz=20,
            active_connection_uuids=(CONNECTION_UUID,),
            active_connections_status="complete",
            active_connections_provenance=("fake",),
            network_manager_connection_uuid=CONNECTION_UUID,
            network_manager_connection_name="Capture Radio",
            namespace="net:[4026531840]",
            wiphy="phy1",
            driver="fake-driver",
        )

    async def is_connectivity_interface(self, interface: str) -> bool:
        assert interface == "wlan1"
        return False

    async def monitor_supported(self, interface: str) -> bool:
        assert interface == "wlan1"
        return True

    async def snapshot(self, interface: str) -> InterfaceState:
        assert interface == "wlan1"
        return self.state

    def preflight(self, request: CaptureRequest, state: InterfaceState) -> None:
        assert request.interface == state.interface == "wlan1"

    async def set_managed(self, interface: str, managed: bool) -> None:
        assert interface == "wlan1"
        self.state = self.state.model_copy(update={"network_manager_managed": managed})

    async def set_link(self, interface: str, up: bool) -> None:
        assert interface == "wlan1"
        self.state = self.state.model_copy(update={"administratively_up": up})

    async def set_type(self, interface: str, interface_type: str) -> None:
        assert interface == "wlan1"
        self.state = self.state.model_copy(update={"interface_type": interface_type})

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
        assert interface == "wlan1"
        definition = validate_complete_channel_definition(
            frequency_mhz=frequency_mhz,
            channel=channel,
            width_mhz=width_mhz,
            center_frequency_1_mhz=center_frequency_1_mhz,
            center_frequency_2_mhz=center_frequency_2_mhz,
        )
        self.state = self.state.model_copy(
            update={
                "channel": definition.primary_channel,
                "frequency_mhz": frequency_mhz,
                "width_mhz": width_mhz,
                "center_frequency_1_mhz": center_frequency_1_mhz,
                "center_frequency_2_mhz": center_frequency_2_mhz,
                "band": definition.band,
                "geometry_version": definition.geometry_version,
            }
        )

    async def restore_connection(self, interface: str, connection_uuid: str) -> None:
        assert interface == "wlan1"
        assert connection_uuid == CONNECTION_UUID
        self.state = InterfaceState.model_validate(
            {
                **self.state.model_dump(mode="python"),
                "active_connection_uuids": (connection_uuid,),
                "ordered_active_connection_uuids": (connection_uuid,),
                "active_connection_interfaces": (
                    {
                        "connection_uuid": connection_uuid,
                        "interface": interface,
                        "restore_position": 0,
                    },
                ),
                "network_manager_connection_uuid": connection_uuid,
                "primary_connection_uuid": connection_uuid,
            }
        )


class _ReplacingStager(SQLiteArtifactStager):
    def __init__(
        self,
        store: SQLiteStore,
        artifact_root: Path,
        *,
        trusted_root: Path,
        workspace_root: Path,
    ) -> None:
        self.workspace_root = workspace_root
        self.replaced_inode: int | None = None
        super().__init__(store, artifact_root, trusted_root=trusted_root)

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
        self.replaced_inode = int(os.fstat(descriptor).st_ino)
        source = self.workspace_root / expected_identity.relative_name
        moved = self.workspace_root / ".retained-reserved-inode"
        os.rename(source, moved)
        source.write_bytes(b"attacker-path-replacement")
        os.chmod(source, 0o600)
        return await super().stage_from_descriptor(
            manifest,
            descriptor,
            expected_identity,
            task_id,
            maximum_size_bytes=maximum_size_bytes,
            cancellation=cancellation,
        )


def _request(*, duration_seconds: int = 1, max_size_bytes: int = 4096) -> CaptureRequest:
    return CaptureRequest.model_validate(
        {
            "task_id": str(TASK_ID),
            "execution_id": str(EXECUTION_ID),
            "idempotency_key": str(IDEMPOTENCY_KEY),
            "interface": "wlan1",
            "channel": 36,
            "frequency_mhz": 5180,
            "width_mhz": 20,
            "duration_seconds": duration_seconds,
            "max_size_bytes": max_size_bytes,
            "capture_format": "pcapng",
        }
    )


def _store(root: Path) -> SQLiteStore:
    store = SQLiteStore(root / "agent.sqlite3")
    store.initialize()
    now = datetime.now(UTC)
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
            required_capabilities=[MONITOR_CAPTURE_CAPABILITY],
            foreground_requirement="not_required",
            user_interaction_requirement="none",
            parameters={},
        )
    )
    return store


def _dumpcap_argv(value: DumpcapArguments, script: Path) -> list[str]:
    return [
        str(script),
        "-q",
        "-i",
        value.interface,
        "-I",
        "-y",
        "IEEE802_11_RADIO",
        "-F",
        value.capture_format,
        "-s",
        str(value.snapshot_length),
        "-a",
        f"duration:{value.duration_seconds}",
        "-a",
        f"filesize:{value.size_kib}",
        "-w",
        "-",
    ]


def _runner(tmp_path: Path, mode: str) -> tuple[_ObservedLinuxRunner, list[str], Path]:
    script = (
        Path(__file__).resolve().parents[2] / "fixtures" / "linux" / "fake_dumpcap.py"
    ).resolve(strict=True)
    ready = tmp_path / f"fake-dumpcap-{mode}.ready"
    spec = CommandSpec(
        command_id="linux.dumpcap.capture",
        executable=Path(sys.executable).resolve(strict=True),
        argument_model=DumpcapArguments,
        build_argv=lambda value: _dumpcap_argv(value, script),
        cwd=tmp_path,
        environment={
            "PYTHONDONTWRITEBYTECODE": "1",
            "WTO_FAKE_DUMPCAP_MODE": mode,
            "WTO_FAKE_DUMPCAP_READY": str(ready),
        },
        max_output_bytes=4096,
        linux_cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
        output_mode=CommandOutputMode.CALLER_FILE_DESCRIPTOR,
    )
    events: list[str] = []
    manager = _FakeCgroupManager(events)
    return _ObservedLinuxRunner(spec, manager), events, ready


def _coordinator(
    tmp_path: Path,
    mode: str,
    *,
    replacing_stager: bool = False,
) -> tuple[CaptureCoordinator, _ObservedLinuxRunner, SQLiteStore, Path]:
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    os.chmod(state_root, 0o700)
    workspace_root = state_root / "capture-workspace"
    runner, _events, _ready = _runner(tmp_path, mode)
    store = _store(tmp_path)
    if replacing_stager:
        stager: SQLiteArtifactStager = _ReplacingStager(
            store,
            state_root / "artifacts",
            trusted_root=state_root,
            workspace_root=workspace_root,
        )
    else:
        stager = SQLiteArtifactStager(
            store,
            state_root / "artifacts",
            trusted_root=state_root,
        )
    coordinator = CaptureCoordinator(
        _CoordinatorBackend(runner),
        CaptureWorkspace(workspace_root),
        stager,
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
        max_size_bytes=32_768,
    )
    return coordinator, runner, store, workspace_root


async def _wait_for_path(path: Path) -> None:
    for _ in range(500):
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError("fake dumpcap did not report readiness")


def _open_descriptors_for_identity(device: int, inode: int) -> list[int]:
    matches: list[int] = []
    for name in os.listdir("/proc/self/fd"):
        try:
            descriptor = int(name)
            metadata = os.fstat(descriptor)
        except (OSError, ValueError):
            continue
        if (int(metadata.st_dev), int(metadata.st_ino)) == (device, inode):
            matches.append(descriptor)
    return matches


@pytest.mark.asyncio
async def test_fake_dumpcap_streams_through_product_runner_and_spawn_guard(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    coordinator, runner, _store_value, workspace_root = _coordinator(tmp_path, "normal")
    request.addfinalizer(coordinator.workspace.close)
    extra = os.open(tmp_path / "not-allowlisted", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    additional_descriptor = os.dup(extra)
    os.set_inheritable(additional_descriptor, True)
    try:
        result = await coordinator.execute(_request(), CancellationToken())
    finally:
        os.close(additional_descriptor)
        os.close(extra)

    assert result.status == "completed"
    assert result.artifact_path is not None
    assert result.artifact_path.read_bytes() == PAYLOAD
    assert result.artifact_manifest is not None
    assert result.artifact_manifest["size_bytes"] == len(PAYLOAD)
    assert result.artifact_manifest["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
    assert runner.results and runner.results[0].stdout == b""
    assert DIAGNOSTIC in runner.results[0].stderr
    assert len(runner.results[0].stderr) <= 4096
    inherited = runner.results[0].stderr.split(b"fds=", 1)[-1].split(b"\n", 1)[0]
    assert str(additional_descriptor).encode("ascii") not in inherited.split(b",")
    assert DIAGNOSTIC not in result.artifact_path.read_bytes()
    assert runner.events.index("attach") < runner.events.index("verify")
    assert runner.events.index("verify") < runner.events.index("release")
    assert runner.events.count("remove") == 1
    assert runner.events.count("close") == 1
    quarantined = list(workspace_root.glob(".capture-output-quarantine-*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == PAYLOAD
    quarantine_metadata = quarantined[0].stat()
    assert runner.stdout_identity_before_spawn == (
        int(quarantine_metadata.st_dev),
        int(quarantine_metadata.st_ino),
    )
    assert not _open_descriptors_for_identity(
        int(quarantine_metadata.st_dev),
        int(quarantine_metadata.st_ino),
    )
    assert not runner._contexts
    assert not runner._handshakes


@pytest.mark.asyncio
async def test_path_replacement_does_not_change_descriptor_staged_artifact(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    coordinator, _runner_value, store, workspace_root = _coordinator(
        tmp_path,
        "normal",
        replacing_stager=True,
    )
    request.addfinalizer(coordinator.workspace.close)

    with pytest.raises(CaptureOperationError):
        await coordinator.execute(_request(), CancellationToken())

    row = store.artifact_upload(str(IDEMPOTENCY_KEY))
    assert row is not None
    staged = (workspace_root.parent / "artifacts") / str(row["relative_path"])
    assert staged.read_bytes() == PAYLOAD
    assert int(row["size_bytes"]) == len(PAYLOAD)
    assert str(row["sha256"]) == hashlib.sha256(PAYLOAD).hexdigest()
    assert (workspace_root / ".retained-reserved-inode").read_bytes() == PAYLOAD
    replacing = coordinator.stager
    assert isinstance(replacing, _ReplacingStager)
    retained_metadata = (workspace_root / ".retained-reserved-inode").stat()
    assert replacing.replaced_inode == int(retained_metadata.st_ino)
    assert not _open_descriptors_for_identity(
        int(retained_metadata.st_dev),
        int(retained_metadata.st_ino),
    )
    assert (workspace_root / f"capture-{EXECUTION_ID}.pcapng").read_bytes() == (
        b"attacker-path-replacement"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["nonzero", "oversize"])
async def test_fake_dumpcap_failure_and_size_limit_cleanup(
    tmp_path: Path,
    mode: str,
    request: pytest.FixtureRequest,
) -> None:
    coordinator, runner, store, workspace_root = _coordinator(tmp_path, mode)
    request.addfinalizer(coordinator.workspace.close)

    with pytest.raises(CaptureOperationError):
        await coordinator.execute(_request(), CancellationToken())

    assert store.artifact_upload(str(IDEMPOTENCY_KEY)) is None
    assert runner.results
    if mode == "nonzero":
        assert runner.results[0].return_code == 7
    quarantined = list(workspace_root.glob(".capture-output-quarantine-*"))
    assert len(quarantined) == 1
    assert DIAGNOSTIC not in quarantined[0].read_bytes()
    assert not runner._contexts
    assert not runner._handshakes


@pytest.mark.asyncio
async def test_cancelled_sigterm_ignoring_fake_escalates_to_cgroup_cleanup(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    coordinator, runner, store, workspace_root = _coordinator(tmp_path, "ignore-term")
    request.addfinalizer(coordinator.workspace.close)
    ready = tmp_path / "fake-dumpcap-ignore-term.ready"
    cancellation = CancellationToken()
    running = asyncio.create_task(coordinator.execute(_request(), cancellation))
    await _wait_for_path(ready)
    cancellation.cancel()

    with pytest.raises(CaptureOperationError):
        await asyncio.wait_for(running, timeout=8)

    assert "cgroup.kill" in runner.events
    assert runner.events.count("remove") == 1
    assert runner.events.count("close") == 1
    assert store.artifact_upload(str(IDEMPOTENCY_KEY)) is None
    assert list(workspace_root.glob(".capture-output-quarantine-*"))
    assert not runner._contexts
    assert not runner._handshakes


@pytest.mark.asyncio
async def test_blocked_fake_dumpcap_times_out_and_cleans_lifecycle(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    coordinator, runner, store, workspace_root = _coordinator(tmp_path, "block")
    request.addfinalizer(coordinator.workspace.close)
    ready = tmp_path / "fake-dumpcap-block.ready"
    running = asyncio.create_task(
        coordinator.execute(_request(duration_seconds=1), CancellationToken())
    )
    await _wait_for_path(ready)

    with pytest.raises(CaptureOperationError):
        await asyncio.wait_for(running, timeout=25)

    assert runner.events.count("remove") == 1
    assert runner.events.count("close") == 1
    assert store.artifact_upload(str(IDEMPOTENCY_KEY)) is None
    assert list(workspace_root.glob(".capture-output-quarantine-*"))
    assert not runner._contexts
    assert not runner._handshakes
