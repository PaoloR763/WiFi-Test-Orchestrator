from __future__ import annotations

from uuid import UUID

import pytest

from wto_desktop_agent.platforms.linux.capture import (
    CaptureCoordinator,
    CaptureRequest,
    InterfaceState,
    NetworkManagerConnectionProfileMissing,
    PrivilegedAuthorizationDecision,
    SimulatedCaptureBackend,
    networkmanager_restore_plan,
)
from wto_desktop_agent.platforms.linux.capture_backend import LinuxCommandCaptureBackend
from wto_desktop_agent.ports.platform import CommandRequest, ProcessResult
from wto_desktop_agent.ports.plugins import CancellationToken

AGENT_ID = "40000000-0000-4000-8000-000000000001"
CONNECTION_UUID = "50000000-0000-4000-8000-000000000001"
SECONDARY_UUID_A = "50000000-0000-4000-8000-000000000002"
SECONDARY_UUID_B = "50000000-0000-4000-8000-000000000003"


class _Runner:
    def __init__(self, nmcli_device: bytes) -> None:
        self.calls: list[str] = []
        self.requests: list[CommandRequest] = []
        self.errors: dict[str, BaseException] = {}
        self.results: dict[str, ProcessResult] = {}
        self.outputs = {
            "linux.ip.route-json": b"[]",
            "linux.ip.route6-json": b"[]",
            "linux.iw.dev": (b"phy#1\n\tInterface wlan1\n\t\tifindex 4\n\t\ttype managed\n"),
            "linux.iw.phy-info": (
                b"Wiphy phy1\n\tSupported interface modes:\n\t\t * managed\n\t\t * monitor\n"
            ),
            "linux.ip.link-one-json": (
                b'[{"ifindex":4,"ifname":"wlan1","flags":["UP"],'
                b'"operstate":"UP","addr_info":[]}]'
            ),
            "linux.iw.info": (
                b"Interface wlan1\n\ttype managed\n" b"\tchannel 36 (5180 MHz), width: 20 MHz\n"
            ),
            "linux.nmcli.device": nmcli_device,
            "linux.nmcli.active": f"{CONNECTION_UUID}:wlan1\n".encode(),
            "linux.ethtool.driver": b"driver: test-driver\n",
        }

    async def run(
        self,
        request: CommandRequest,
        cancellation: CancellationToken,
    ) -> ProcessResult:
        assert not cancellation.cancelled
        self.calls.append(request.command_id)
        self.requests.append(request)
        error = self.errors.get(request.command_id)
        if error is not None:
            raise error
        result = self.results.get(request.command_id)
        if result is not None:
            return result
        return ProcessResult(0, self.outputs[request.command_id], b"")


class _Authorization:
    def authorize(
        self,
        *,
        agent_id: str | None,
        capability_id: str,
    ) -> PrivilegedAuthorizationDecision:
        del capability_id
        return PrivilegedAuthorizationDecision(agent_id == AGENT_ID, None)


class _Stager:
    calls = 0

    async def find_existing(
        self,
        identity: dict[str, object],
        task_id: UUID,
        *,
        cancellation: CancellationToken,
    ) -> None:
        del identity, task_id, cancellation
        self.calls += 1
        return None


class _ForbiddenWorkspace:
    calls = 0

    def reserve(self, execution_id: UUID, capture_format: str) -> object:
        del execution_id, capture_format
        self.calls += 1
        raise AssertionError("an incomplete snapshot must fail before output reservation")


def _request() -> CaptureRequest:
    return CaptureRequest.model_validate(
        {
            "task_id": "10000000-0000-4000-8000-000000000001",
            "execution_id": "20000000-0000-4000-8000-000000000001",
            "idempotency_key": "30000000-0000-4000-8000-000000000001",
            "interface": "wlan1",
            "channel": 36,
            "frequency_mhz": 5180,
            "width_mhz": 20,
            "duration_seconds": 5,
            "max_size_bytes": 4096,
            "capture_format": "pcapng",
        }
    )


def _backend(nmcli_device: bytes) -> tuple[LinuxCommandCaptureBackend, _Runner]:
    runner = _Runner(nmcli_device)
    return (
        LinuxCommandCaptureBackend(runner, frozenset(runner.outputs)),  # type: ignore[arg-type]
        runner,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "nmcli_device",
    [
        b"GENERAL.STATE:100 (connected)\nGENERAL.CONNECTION:Capture Radio\n"
        + f"GENERAL.CON-UUID:{CONNECTION_UUID}\n".encode(),
        b"GENERAL.MANAGED:maybe\nGENERAL.STATE:100\nGENERAL.CONNECTION:Capture Radio\n"
        + f"GENERAL.CON-UUID:{CONNECTION_UUID}\n".encode(),
        b"GENERAL.MANAGED:yes\nGENERAL.STATE:100\n",
        b"GENERAL.MANAGED:yes\nmalformed\nGENERAL.CONNECTION:Capture Radio\n"
        + f"GENERAL.CON-UUID:{CONNECTION_UUID}\n".encode(),
    ],
)
async def test_product_backend_marks_one_missing_nmcli_view_partial(
    nmcli_device: bytes,
) -> None:
    backend, _runner = _backend(nmcli_device)

    snapshot = await backend.snapshot("wlan1")

    assert snapshot.network_manager_managed is None
    assert snapshot.active_connections_status == "partial"
    assert snapshot.ordered_active_connection_uuids == (CONNECTION_UUID,)
    assert "networkmanager_device_unavailable" in snapshot.active_connections_source_errors
    assert "active_connections_unavailable" not in snapshot.active_connections_source_errors


@pytest.mark.asyncio
async def test_product_backend_marks_both_missing_nmcli_views_unavailable() -> None:
    backend, runner = _backend(b"malformed\n")
    runner.outputs["linux.nmcli.active"] = b"malformed\n"

    snapshot = await backend.snapshot("wlan1")

    assert snapshot.network_manager_managed is None
    assert snapshot.active_connections_status == "unavailable"
    assert snapshot.ordered_active_connection_uuids == ()
    assert set(snapshot.active_connections_source_errors) == {
        "networkmanager_device_unavailable",
        "active_connections_unavailable",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("device_error", "active_error", "expected_status", "expected_errors"),
    [
        (
            TimeoutError("device timeout"),
            None,
            "partial",
            ("networkmanager_device_unavailable",),
        ),
        (
            None,
            TimeoutError("active timeout"),
            "partial",
            ("active_connections_unavailable",),
        ),
        (
            TimeoutError("device timeout"),
            OSError("active provider failed"),
            "unavailable",
            (
                "networkmanager_device_unavailable",
                "active_connections_unavailable",
            ),
        ),
    ],
)
async def test_product_backend_classifies_nmcli_timeout_without_losing_other_view(
    device_error: BaseException | None,
    active_error: BaseException | None,
    expected_status: str,
    expected_errors: tuple[str, ...],
) -> None:
    backend, runner = _backend(
        b"GENERAL.MANAGED:yes\nGENERAL.STATE:100 (connected)\n"
        b"GENERAL.CONNECTION:Capture Radio\n" + f"GENERAL.CON-UUID:{CONNECTION_UUID}\n".encode()
    )
    if device_error is not None:
        runner.errors["linux.nmcli.device"] = device_error
    if active_error is not None:
        runner.errors["linux.nmcli.active"] = active_error

    snapshot = await backend.snapshot("wlan1")

    assert snapshot.active_connections_status == expected_status
    assert snapshot.active_connections_source_errors == expected_errors
    assert snapshot.ordered_active_connection_uuids == (
        () if active_error is not None else (CONNECTION_UUID,)
    )


@pytest.mark.asyncio
async def test_capture_coordinator_rejects_product_partial_snapshot_without_mutation() -> None:
    backend, runner = _backend(
        b"GENERAL.MANAGED:yes\nGENERAL.CONNECTION:Capture Radio\n"
        + f"GENERAL.CON-UUID:{CONNECTION_UUID}\n".encode()
    )
    workspace = _ForbiddenWorkspace()
    stager = _Stager()
    coordinator = CaptureCoordinator(
        backend,
        workspace,  # type: ignore[arg-type]
        stager,  # type: ignore[arg-type]
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
        max_size_bytes=8192,
    )

    with pytest.raises(RuntimeError, match="snapshot_not_restorable"):
        await coordinator.execute(_request(), CancellationToken())

    mutating = {
        "linux.nmcli.managed-set",
        "linux.ip.link-set",
        "linux.iw.type-set",
        "linux.iw.frequency-set",
        "linux.nmcli.connection-up",
        "linux.dumpcap.capture",
    }
    assert mutating.isdisjoint(runner.calls)
    assert workspace.calls == 0
    assert stager.calls == 1


@pytest.mark.asyncio
async def test_product_snapshot_canonicalizes_mesh_and_keeps_name_as_metadata() -> None:
    backend, runner = _backend(
        b"GENERAL.MANAGED:yes\nGENERAL.STATE:100 (connected)\n"
        b"GENERAL.CONNECTION:Casa\\: 5 GHz\n" + f"GENERAL.CON-UUID:{CONNECTION_UUID}\n".encode()
    )
    runner.outputs["linux.iw.info"] = (
        b"Interface wlan1\n\ttype mesh point\n" b"\tchannel 36 (5180 MHz), width: 20 MHz\n"
    )

    snapshot = await backend.snapshot("wlan1")

    assert snapshot.interface_type == "mesh"
    assert snapshot.active_connection_uuids == (CONNECTION_UUID,)
    assert snapshot.network_manager_connection_uuid == CONNECTION_UUID
    assert snapshot.network_manager_connection_name == "Casa: 5 GHz"
    serialized = snapshot.model_dump(mode="json")
    assert serialized["interface_type"] == "mesh"
    assert "active_connections" not in serialized
    assert "network_manager_connection" not in serialized


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected_active"),
    [
        ("invalid_uuid", (CONNECTION_UUID,)),
        ("duplicate_uuid", ()),
        ("other_device", ()),
    ],
)
async def test_product_snapshot_fails_closed_for_unrestorable_uuid_views(
    failure: str,
    expected_active: tuple[str, ...],
) -> None:
    reported_uuid = (
        "ABCDEF00-0000-4000-8000-000000000001" if failure == "invalid_uuid" else CONNECTION_UUID
    )
    backend, runner = _backend(
        b"GENERAL.MANAGED:yes\nGENERAL.STATE:100 (connected)\n"
        b"GENERAL.CONNECTION:Capture Radio\n" + f"GENERAL.CON-UUID:{reported_uuid}\n".encode()
    )
    if failure == "duplicate_uuid":
        runner.outputs["linux.nmcli.active"] = (
            f"{CONNECTION_UUID}:wlan1\n{CONNECTION_UUID}:wlan1\n".encode()
        )
    elif failure == "other_device":
        runner.outputs["linux.nmcli.active"] = f"{CONNECTION_UUID}:eth0\n".encode()

    snapshot = await backend.snapshot("wlan1")

    assert snapshot.active_connections_status == "partial"
    assert snapshot.active_connection_uuids == expected_active


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("primary", "input_order", "expected_order"),
    [
        (
            CONNECTION_UUID,
            (CONNECTION_UUID, SECONDARY_UUID_B, SECONDARY_UUID_A),
            (SECONDARY_UUID_A, SECONDARY_UUID_B, CONNECTION_UUID),
        ),
        (
            SECONDARY_UUID_A,
            (SECONDARY_UUID_B, SECONDARY_UUID_A, CONNECTION_UUID),
            (CONNECTION_UUID, SECONDARY_UUID_B, SECONDARY_UUID_A),
        ),
        (
            SECONDARY_UUID_B,
            (SECONDARY_UUID_B, CONNECTION_UUID, SECONDARY_UUID_A),
            (CONNECTION_UUID, SECONDARY_UUID_A, SECONDARY_UUID_B),
        ),
        (
            SECONDARY_UUID_A,
            (CONNECTION_UUID, SECONDARY_UUID_A, SECONDARY_UUID_B),
            (CONNECTION_UUID, SECONDARY_UUID_B, SECONDARY_UUID_A),
        ),
    ],
)
async def test_product_snapshot_records_deterministic_restore_order_and_associations(
    primary: str,
    input_order: tuple[str, ...],
    expected_order: tuple[str, ...],
) -> None:
    backend, runner = _backend(
        b"GENERAL.MANAGED:yes\nGENERAL.STATE:100 (connected)\n"
        b"GENERAL.CONNECTION:Capture Radio\n" + f"GENERAL.CON-UUID:{primary}\n".encode()
    )
    runner.outputs["linux.nmcli.active"] = "".join(
        f"{connection_uuid}:wlan1\n" for connection_uuid in input_order
    ).encode()

    snapshot = await backend.snapshot("wlan1")

    assert snapshot.active_connections_status == "complete"
    assert snapshot.active_connection_uuids == expected_order
    assert snapshot.ordered_active_connection_uuids == expected_order
    assert snapshot.network_manager_connection_uuid == primary
    assert snapshot.primary_connection_uuid == primary
    assert snapshot.network_manager_restore_schema_version == "networkmanager-restore-v1"
    assert [
        (item.connection_uuid, item.interface, item.restore_position)
        for item in snapshot.active_connection_interfaces
    ] == [
        (connection_uuid, "wlan1", position)
        for position, connection_uuid in enumerate(expected_order)
    ]


def test_interface_state_rejects_duplicate_active_connection_uuid() -> None:
    with pytest.raises(ValueError, match="UUIDs are duplicated"):
        InterfaceState(
            interface="wlan1",
            interface_type="managed",
            administratively_up=True,
            network_manager_managed=True,
            channel=36,
            frequency_mhz=5180,
            width_mhz=20,
            active_connection_uuids=(CONNECTION_UUID, CONNECTION_UUID),
            active_connections_status="complete",
            network_manager_connection_uuid=CONNECTION_UUID,
            namespace="net:[1]",
            wiphy="phy1",
            driver="test",
        )


def test_restore_plan_rejects_active_set_without_demonstrable_primary() -> None:
    snapshot = InterfaceState(
        interface="wlan1",
        interface_type="managed",
        administratively_up=True,
        network_manager_managed=True,
        channel=36,
        frequency_mhz=5180,
        width_mhz=20,
        active_connection_uuids=(CONNECTION_UUID,),
        active_connections_status="complete",
        namespace="net:[1]",
        wiphy="phy1",
        driver="test",
    )

    with pytest.raises(ValueError, match="primary connection is unavailable"):
        networkmanager_restore_plan(snapshot)


def test_interface_state_rejects_connection_associated_with_another_interface() -> None:
    with pytest.raises(ValueError, match="associations are inconsistent"):
        InterfaceState(
            interface="wlan1",
            interface_type="managed",
            administratively_up=True,
            network_manager_managed=True,
            channel=36,
            frequency_mhz=5180,
            width_mhz=20,
            active_connection_uuids=(CONNECTION_UUID,),
            active_connection_interfaces=(
                {
                    "connection_uuid": CONNECTION_UUID,
                    "interface": "wlan2",
                    "restore_position": 0,
                },
            ),
            active_connections_status="complete",
            network_manager_connection_uuid=CONNECTION_UUID,
            namespace="net:[1]",
            wiphy="phy1",
            driver="test",
        )


@pytest.mark.asyncio
async def test_product_restore_uses_exact_uuid_identity_not_connection_label() -> None:
    backend, runner = _backend(
        b"GENERAL.MANAGED:yes\nGENERAL.STATE:100 (connected)\n"
        b"GENERAL.CONNECTION:Duplicate label\n" + f"GENERAL.CON-UUID:{CONNECTION_UUID}\n".encode()
    )
    runner.outputs["linux.nmcli.connection-up"] = b"activated\n"
    backend.commands = frozenset(runner.outputs)  # type: ignore[assignment]

    await backend.restore_connection("wlan1", SECONDARY_UUID_A)

    request = runner.requests[-1]
    assert request.command_id == "linux.nmcli.connection-up"
    assert request.arguments == {
        "interface": "wlan1",
        "connection_uuid": SECONDARY_UUID_A,
    }
    assert "Duplicate label" not in request.arguments.values()


@pytest.mark.asyncio
async def test_product_restore_classifies_exact_locale_c_missing_profile_diagnostic() -> None:
    backend, runner = _backend(
        b"GENERAL.MANAGED:yes\nGENERAL.STATE:100 (connected)\n"
        b"GENERAL.CONNECTION:Capture Radio\n" + f"GENERAL.CON-UUID:{CONNECTION_UUID}\n".encode()
    )
    runner.outputs["linux.nmcli.connection-up"] = b""
    backend.commands = frozenset(runner.outputs)  # type: ignore[assignment]
    runner.results["linux.nmcli.connection-up"] = ProcessResult(
        10,
        b"",
        f"Error: unknown connection '{SECONDARY_UUID_A}'.\n".encode("ascii"),
    )

    with pytest.raises(
        NetworkManagerConnectionProfileMissing,
        match="connection_profile_missing",
    ):
        await backend.restore_connection("wlan1", SECONDARY_UUID_A)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("return_code", "stderr"),
    [
        (
            10,
            f"Error: unknown connection '{SECONDARY_UUID_A}' .\n".encode("ascii"),
        ),
        (
            10,
            f"Error: unknown connection '{SECONDARY_UUID_B}'.\n".encode("ascii"),
        ),
        (
            10,
            b"Error: Connection activation failed: No suitable device found.\n",
        ),
        (
            1,
            f"Error: unknown connection '{SECONDARY_UUID_A}'.\n".encode("ascii"),
        ),
    ],
)
async def test_product_restore_keeps_similar_or_unrelated_nmcli_failures_generic(
    return_code: int,
    stderr: bytes,
) -> None:
    backend, runner = _backend(
        b"GENERAL.MANAGED:yes\nGENERAL.STATE:100 (connected)\n"
        b"GENERAL.CONNECTION:Capture Radio\n" + f"GENERAL.CON-UUID:{CONNECTION_UUID}\n".encode()
    )
    runner.outputs["linux.nmcli.connection-up"] = b""
    backend.commands = frozenset(runner.outputs)  # type: ignore[assignment]
    runner.results["linux.nmcli.connection-up"] = ProcessResult(return_code, b"", stderr)

    with pytest.raises(RuntimeError, match="allowlisted provider failed") as failure:
        await backend.restore_connection("wlan1", SECONDARY_UUID_A)

    assert type(failure.value) is RuntimeError


@pytest.mark.asyncio
async def test_preflight_rejection_occurs_before_workspace_journal_or_mutation() -> None:
    class _RejectedPreflightBackend(SimulatedCaptureBackend):
        def preflight(self, request: CaptureRequest, state: InterfaceState) -> None:
            self.calls.append("preflight")
            raise RuntimeError("controlled preflight rejection")

    backend = _RejectedPreflightBackend(
        InterfaceState(
            interface="wlan1",
            interface_type="managed",
            administratively_up=True,
            network_manager_managed=True,
            channel=36,
            frequency_mhz=5180,
            width_mhz=20,
            active_connection_uuids=(CONNECTION_UUID,),
            active_connections_status="complete",
            network_manager_connection_uuid=CONNECTION_UUID,
            network_manager_connection_name="Casa: 5 GHz",
            namespace="net:[1]",
            wiphy="phy1",
            driver="test",
        )
    )
    workspace = _ForbiddenWorkspace()
    coordinator = CaptureCoordinator(
        backend,
        workspace,  # type: ignore[arg-type]
        _Stager(),  # type: ignore[arg-type]
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
        max_size_bytes=8192,
    )

    with pytest.raises(RuntimeError, match="controlled preflight rejection"):
        await coordinator.execute(_request(), CancellationToken())

    assert backend.calls == ["snapshot", "preflight"]
    assert workspace.calls == 0
