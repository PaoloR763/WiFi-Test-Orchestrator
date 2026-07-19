from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

import wto_desktop_agent.platforms.linux.capture_commands as capture_commands_module
from wto_desktop_agent.platforms.common import CommandOutputMode, LinuxCleanupScope
from wto_desktop_agent.platforms.linux.capture import (
    MONITOR_CAPTURE_CAPABILITY,
    CaptureCoordinator,
    CaptureLiveDependencies,
    CaptureRequest,
    InterfaceState,
    PrivilegedAuthorizationDecision,
    _validate_legacy_journal_state,
)
from wto_desktop_agent.platforms.linux.capture_backend import LinuxCommandCaptureBackend
from wto_desktop_agent.platforms.linux.capture_commands import capture_command_specs
from wto_desktop_agent.platforms.linux.capture_identity import (
    IwInterfaceTypeCommandToken,
    canonical_interface_type_to_iw_command_token,
    parse_capture_interface_type,
    validate_networkmanager_connection_id,
)
from wto_desktop_agent.platforms.linux.frequency import (
    capture_channel_definition,
    frequency_to_channel,
)
from wto_desktop_agent.ports.plugins import CancellationToken


def _request(*, channel: int, frequency_mhz: int, width_mhz: int) -> CaptureRequest:
    return CaptureRequest.model_validate(
        {
            "task_id": UUID("10000000-0000-4000-8000-000000000001"),
            "execution_id": UUID("20000000-0000-4000-8000-000000000001"),
            "idempotency_key": UUID("30000000-0000-4000-8000-000000000001"),
            "interface": "wlan1",
            "channel": channel,
            "frequency_mhz": frequency_mhz,
            "width_mhz": width_mhz,
            "duration_seconds": 5,
            "max_size_bytes": 4096,
        }
    )


@pytest.mark.parametrize(
    "channel,frequency_mhz,width_mhz,width_token,center_frequency_1_mhz",
    [
        (1, 2412, 20, "HT20", 2412),
        (2, 5935, 20, "HT20", 5935),
        (1, 5955, 20, "HT20", 5955),
        (36, 5180, 80, "80", 5210),
        (36, 5180, 160, "160", 5250),
        (1, 5955, 80, "80", 5985),
        (1, 5955, 160, "160", 6025),
    ],
)
def test_iw_frequency_command_is_unambiguous_across_bands(
    channel: int,
    frequency_mhz: int,
    width_mhz: int,
    width_token: str,
    center_frequency_1_mhz: int,
) -> None:
    request = _request(
        channel=channel,
        frequency_mhz=frequency_mhz,
        width_mhz=width_mhz,
    )
    spec = capture_command_specs(
        paths={"iw": Path("/usr/sbin/iw")},
        artifact_root=Path("/var/lib/wto-agent/artifacts"),
        environment={"PATH": "/usr/sbin:/usr/bin"},
    )["linux.iw.frequency-set"]
    arguments = spec.argument_model.model_validate(
        {
            "interface": request.interface,
            "frequency_mhz": request.frequency_mhz,
            "channel": request.channel,
            "width_mhz": request.width_mhz,
            "center_frequency_1_mhz": center_frequency_1_mhz,
            "center_frequency_2_mhz": None,
        }
    )

    argv = spec.build_argv(arguments)

    expected = ["dev", "wlan1", "set", "freq", str(frequency_mhz), width_token]
    if width_mhz in {80, 160}:
        expected.append(str(center_frequency_1_mhz))
    assert argv == expected
    assert "channel" not in argv


def test_frequency_channel_mismatch_and_band_width_mismatch_are_rejected() -> None:
    with pytest.raises(ValueError, match="matching pair"):
        _request(channel=1, frequency_mhz=5180, width_mhz=20)


@pytest.mark.parametrize("width_mhz", [40, 320, 2160])
def test_incomplete_or_nonexistent_iw_widths_are_rejected_before_argv(
    width_mhz: int,
) -> None:
    spec = capture_command_specs(
        paths={"iw": Path("/usr/sbin/iw")},
        artifact_root=Path("/var/lib/wto-agent/artifacts"),
        environment={"PATH": "/usr/sbin:/usr/bin"},
    )["linux.iw.frequency-set"]

    with pytest.raises(ValueError):
        _request(channel=36, frequency_mhz=5180, width_mhz=width_mhz)
    with pytest.raises(ValueError):
        spec.argument_model.model_validate(
            {
                "interface": "wlan1",
                "frequency_mhz": 5180,
                "channel": 36,
                "width_mhz": width_mhz,
                "center_frequency_1_mhz": 5180,
            }
        )


@pytest.mark.parametrize("width_mhz", [80, 160])
def test_5935_special_channel_rejects_wide_capture_before_argv(width_mhz: int) -> None:
    spec = capture_command_specs(
        paths={"iw": Path("/usr/sbin/iw")},
        artifact_root=Path("/var/lib/wto-agent/artifacts"),
        environment={"PATH": "/usr/sbin:/usr/bin"},
    )["linux.iw.frequency-set"]

    with pytest.raises(ValueError, match="only at 20 MHz"):
        _request(channel=2, frequency_mhz=5935, width_mhz=width_mhz)
    with pytest.raises(ValueError, match="only at 20 MHz"):
        spec.argument_model.model_validate(
            {
                "interface": "wlan1",
                "frequency_mhz": 5935,
                "channel": 2,
                "width_mhz": width_mhz,
                "center_frequency_1_mhz": 5935,
            }
        )


@pytest.mark.parametrize("width_mhz", [80, 160])
def test_24_ghz_rejects_wide_capture_before_argv(width_mhz: int) -> None:
    spec = capture_command_specs(
        paths={"iw": Path("/usr/sbin/iw")},
        artifact_root=Path("/var/lib/wto-agent/artifacts"),
        environment={"PATH": "/usr/sbin:/usr/bin"},
    )["linux.iw.frequency-set"]

    with pytest.raises(ValueError, match="frequency band"):
        _request(channel=1, frequency_mhz=2412, width_mhz=width_mhz)
    with pytest.raises(ValueError, match="frequency band"):
        spec.argument_model.model_validate(
            {
                "interface": "wlan1",
                "frequency_mhz": 2412,
                "channel": 1,
                "width_mhz": width_mhz,
                "center_frequency_1_mhz": 2412,
            }
        )


def test_60_ghz_mapping_is_preserved_but_capture_command_is_blocked() -> None:
    information = frequency_to_channel(58_320)
    assert information is not None
    assert (information.channel, information.band) == (1, "60GHz")

    spec = capture_command_specs(
        paths={"iw": Path("/usr/sbin/iw")},
        artifact_root=Path("/var/lib/wto-agent/artifacts"),
        environment={"PATH": "/usr/sbin:/usr/bin"},
    )["linux.iw.frequency-set"]
    with pytest.raises(ValueError, match="frequency band"):
        spec.argument_model.model_validate(
            {
                "interface": "wlan1",
                "frequency_mhz": 58_320,
                "channel": 1,
                "width_mhz": 20,
                "center_frequency_1_mhz": 58_320,
            }
        )


@pytest.mark.parametrize(
    ("frequency_mhz", "channel", "band"),
    [
        (5935, 2, "6GHz"),
        (5955, 1, "6GHz"),
        (5895, 179, "5GHz"),
        (7115, 233, "6GHz"),
        (58_320, 1, "60GHz"),
    ],
)
def test_frequency_mapper_handles_supported_boundaries(
    frequency_mhz: int, channel: int, band: str
) -> None:
    information = frequency_to_channel(frequency_mhz)

    assert information is not None
    assert (information.channel, information.band) == (channel, band)


def test_wide_frequency_command_rejects_missing_or_wrong_center() -> None:
    spec = capture_command_specs(
        paths={"iw": Path("/usr/sbin/iw")},
        artifact_root=Path("/var/lib/wto-agent/artifacts"),
        environment={"PATH": "/usr/sbin:/usr/bin"},
    )["linux.iw.frequency-set"]
    base = {
        "interface": "wlan1",
        "frequency_mhz": 5180,
        "channel": 36,
        "width_mhz": 80,
    }
    with pytest.raises(ValueError, match="center_frequency_1"):
        spec.argument_model.model_validate(base)
    with pytest.raises(ValueError, match="inconsistent"):
        spec.argument_model.model_validate({**base, "center_frequency_1_mhz": 5290})
    definition = capture_channel_definition(frequency_mhz=5180, channel=36, width_mhz=80)
    assert definition.center_frequency_1_mhz == 5210


@pytest.mark.parametrize(
    ("band", "width_mhz", "center_channels", "offsets"),
    [
        ("5GHz", 80, (42, 58, 106, 122, 138, 155, 171), (-6, -2, 2, 6)),
        ("5GHz", 160, (50, 114, 163), (-14, -10, -6, -2, 2, 6, 10, 14)),
        ("6GHz", 80, tuple(range(7, 216, 16)), (-6, -2, 2, 6)),
        ("6GHz", 160, tuple(range(15, 208, 32)), (-14, -10, -6, -2, 2, 6, 10, 14)),
    ],
)
def test_wide_channel_geometry_uses_closed_annex_e_blocks(
    band: str,
    width_mhz: int,
    center_channels: tuple[int, ...],
    offsets: tuple[int, ...],
) -> None:
    for center_channel in center_channels:
        center_frequency = (5000 if band == "5GHz" else 5950) + 5 * center_channel
        for offset in offsets:
            primary_channel = center_channel + offset
            control_frequency = (5000 if band == "5GHz" else 5950) + 5 * primary_channel
            definition = capture_channel_definition(
                frequency_mhz=control_frequency,
                channel=primary_channel,
                width_mhz=width_mhz,
            )
            assert definition.band == band
            assert definition.center_frequency_1_mhz == center_frequency
            assert definition.center_frequency_2_mhz is None


def test_80_plus_80_and_unaligned_primaries_remain_rejected() -> None:
    spec = capture_command_specs(
        paths={"iw": Path("/usr/sbin/iw")},
        artifact_root=Path("/var/lib/wto-agent/artifacts"),
        environment={"PATH": "/usr/sbin:/usr/bin"},
    )["linux.iw.frequency-set"]
    with pytest.raises(ValueError, match=r"80\+80"):
        spec.argument_model.model_validate(
            {
                "interface": "wlan1",
                "frequency_mhz": 5180,
                "channel": 36,
                "width_mhz": 80,
                "center_frequency_1_mhz": 5210,
                "center_frequency_2_mhz": 5530,
            }
        )
    with pytest.raises(ValueError, match="aligned primary"):
        _request(channel=37, frequency_mhz=5185, width_mhz=80)


def _rollback_state(*, active_connection_uuids: tuple[str, ...] = ()) -> InterfaceState:
    primary = active_connection_uuids[0] if active_connection_uuids else None
    return InterfaceState(
        interface="wlan1",
        interface_type="managed",
        administratively_up=True,
        network_manager_managed=True,
        channel=36,
        frequency_mhz=5180,
        width_mhz=80,
        center_frequency_1_mhz=5210,
        active_connection_uuids=active_connection_uuids,
        active_connections_status="complete",
        network_manager_connection_uuid=primary,
        namespace="net:[4026531840]",
        wiphy="phy1",
        driver="ath9k_htc",
    )


@pytest.mark.parametrize(
    ("status", "expected"),
    [("complete", "complete"), ("partial", "partial"), ("unavailable", "unavailable")],
)
def test_rollback_assessment_distinguishes_measured_empty_from_missing_evidence(
    status: str,
    expected: str,
) -> None:
    original = _rollback_state()
    verification = original.model_copy(update={"active_connections_status": status})

    assessment = CaptureCoordinator._assess_rollback_verification(original, verification)

    assert assessment.status == expected


def test_rollback_assessment_rejects_unavailable_uuid_view_and_mismatch() -> None:
    original = _rollback_state(active_connection_uuids=("50000000-0000-4000-8000-000000000001",))
    unavailable = original.model_copy(
        update={"active_connection_uuids": (), "active_connections_status": "unavailable"}
    )
    mismatch = original.model_copy(update={"administratively_up": False})

    assert (
        CaptureCoordinator._assess_rollback_verification(original, unavailable).status
        == "unavailable"
    )
    assert CaptureCoordinator._assess_rollback_verification(original, mismatch).status == "mismatch"


@pytest.mark.parametrize("frequency_mhz", [5000, 5930, 5940, 5950, 7120])
def test_frequency_mapper_rejects_unaligned_or_impossible_values(frequency_mhz: int) -> None:
    assert frequency_to_channel(frequency_mhz) is None


def test_5935_rejects_crossed_channel_pair() -> None:
    with pytest.raises(ValueError, match="matching pair"):
        _request(channel=1, frequency_mhz=5935, width_mhz=20)


def test_dumpcap_writes_only_to_preopened_stdout_descriptor() -> None:
    spec = capture_command_specs(
        paths={"dumpcap": Path("/usr/bin/dumpcap")},
        artifact_root=Path("/var/lib/wto-agent/capture"),
        environment={"PATH": "/usr/bin"},
    )["linux.dumpcap.capture"]
    arguments = spec.argument_model.model_validate(
        {
            "interface": "wlan1",
            "duration_seconds": 5,
            "size_kib": 4,
            "capture_format": "pcapng",
            "snapshot_length": 262_144,
        }
    )

    argv = spec.build_argv(arguments)

    assert argv[-2:] == ["-w", "-"]
    assert "/var/lib/wto-agent/capture" not in " ".join(argv)
    assert spec.output_mode is CommandOutputMode.CALLER_FILE_DESCRIPTOR
    assert spec.linux_cleanup_scope is LinuxCleanupScope.PROCESS_TREE


@pytest.mark.parametrize("value", ["managed", "monitor", "AP", "mesh"])
def test_capture_interface_types_are_canonical_snapshot_values(value: str) -> None:
    assert parse_capture_interface_type(value) == value


@pytest.mark.parametrize(
    ("canonical_type", "command_token"),
    [
        ("managed", "managed"),
        ("monitor", "monitor"),
        ("mesh", "mesh"),
        ("AP", "__ap"),
    ],
)
def test_canonical_interface_type_maps_to_exact_iw_command_token(
    canonical_type: str,
    command_token: str,
) -> None:
    assert canonical_interface_type_to_iw_command_token(canonical_type) == command_token

    spec = capture_command_specs(
        paths={"iw": Path("/usr/sbin/iw")},
        artifact_root=Path("/var/lib/wto-agent/artifacts"),
        environment={"PATH": "/usr/sbin:/usr/bin"},
    )["linux.iw.type-set"]
    arguments = spec.argument_model.model_validate(
        {"interface": "wlan1", "interface_type": canonical_type}
    )

    assert spec.build_argv(arguments) == [
        "dev",
        "wlan1",
        "set",
        "type",
        command_token,
    ]


def test_ap_presentation_label_is_never_emitted_as_iw_command_token() -> None:
    spec = capture_command_specs(
        paths={"iw": Path("/usr/sbin/iw")},
        artifact_root=Path("/var/lib/wto-agent/artifacts"),
        environment={"PATH": "/usr/sbin:/usr/bin"},
    )["linux.iw.type-set"]
    arguments = spec.argument_model.model_validate({"interface": "wlan1", "interface_type": "AP"})

    argv = spec.build_argv(arguments)

    assert argv[-1] == "__ap"
    assert argv[-1] not in {"AP", "ap"}


@pytest.mark.parametrize("value", ["ap", "__ap", "AP-VLAN", "__ap_vlan", "P2P-client", "unknown"])
def test_command_tokens_and_unsupported_types_are_not_canonical_input(value: str) -> None:
    with pytest.raises(ValueError, match="no supported iw command token"):
        canonical_interface_type_to_iw_command_token(value)

    spec = capture_command_specs(
        paths={"iw": Path("/usr/sbin/iw")},
        artifact_root=Path("/var/lib/wto-agent/artifacts"),
        environment={"PATH": "/usr/sbin:/usr/bin"},
    )["linux.iw.type-set"]
    with pytest.raises(ValueError):
        spec.argument_model.model_validate({"interface": "wlan1", "interface_type": value})


def test_mesh_point_is_canonicalized_only_while_parsing_snapshot_state() -> None:
    state = InterfaceState.model_validate(
        {
            "interface": "wlan1",
            "interface_type": "mesh point",
            "administratively_up": True,
            "network_manager_managed": False,
            "channel": 36,
            "frequency_mhz": 5180,
            "width_mhz": 20,
            "active_connections_status": "complete",
        }
    )

    assert state.interface_type == "mesh"
    assert state.model_dump(mode="json")["interface_type"] == "mesh"


def test_legacy_journal_alias_is_canonical_but_name_identity_requires_manual_recovery() -> None:
    legacy = {
        "interface": "wlan1",
        "interface_type": "mesh point",
        "administratively_up": True,
        "network_manager_managed": False,
        "channel": 36,
        "frequency_mhz": 5180,
        "width_mhz": 20,
        "active_connections": (),
        "active_connections_status": "complete",
        "active_connections_provenance": (),
        "active_connections_source_errors": (),
        "network_manager_connection": None,
        "namespace": "net:[1]",
        "wiphy": "phy1",
        "driver": "test",
    }
    assert _validate_legacy_journal_state(legacy).interface_type == "mesh"

    legacy["active_connections"] = ("Capture Radio",)
    legacy["network_manager_connection"] = "Capture Radio"
    with pytest.raises(ValueError, match="manual recovery"):
        _validate_legacy_journal_state(legacy)


def test_historical_ap_journal_restores_with_current_exact_iw_token() -> None:
    historical = {
        "interface": "wlan1",
        "interface_type": "AP",
        "administratively_up": True,
        "network_manager_managed": False,
        "channel": 36,
        "frequency_mhz": 5180,
        "width_mhz": 20,
        "active_connections": (),
        "active_connections_status": "complete",
        "active_connections_provenance": (),
        "active_connections_source_errors": (),
        "network_manager_connection": None,
        "namespace": "net:[1]",
        "wiphy": "phy1",
        "driver": "test",
    }
    restored = _validate_legacy_journal_state(historical)
    assert restored.interface_type == "AP"

    spec = capture_command_specs(
        paths={"iw": Path("/usr/sbin/iw")},
        artifact_root=Path("/var/lib/wto-agent/artifacts"),
        environment={"PATH": "/usr/sbin:/usr/bin"},
    )["linux.iw.type-set"]
    arguments = spec.argument_model.model_validate(
        {"interface": restored.interface, "interface_type": restored.interface_type}
    )
    argv = spec.build_argv(arguments)

    assert argv == ["dev", "wlan1", "set", "type", "__ap"]
    assert "AP" not in argv


@pytest.mark.parametrize(
    "value",
    [
        "Mesh point",
        "mesh  point",
        " mesh point",
        "P2P-client",
        "ibss",
        "ap",
        "__ap",
        "AP-VLAN",
        "__ap_vlan",
        "wds",
        "ocb",
        "nan",
        "unknown",
    ],
)
def test_noncanonical_interface_type_spellings_are_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        parse_capture_interface_type(value)


@pytest.mark.parametrize(
    "connection_id",
    ["Casa: 5 GHz", "Wi-Fi (principal)", "Office LAN", "Red 主", "-lab-profile"],
)
def test_networkmanager_display_ids_are_metadata_only(connection_id: str) -> None:
    assert validate_networkmanager_connection_id(connection_id) == connection_id


@pytest.mark.parametrize("connection_id", ["bad\x00id", "bad\nname", "x" * 256, ""])
def test_networkmanager_display_ids_reject_controls_and_excessive_length(
    connection_id: str,
) -> None:
    with pytest.raises(ValueError):
        validate_networkmanager_connection_id(connection_id)


def test_networkmanager_rollback_uses_only_canonical_uuid() -> None:
    connection_uuid = "50000000-0000-4000-8000-000000000001"
    spec = capture_command_specs(
        paths={"nmcli": Path("/usr/bin/nmcli")},
        artifact_root=Path("/var/lib/wto-agent/artifacts"),
        environment={},
    )["linux.nmcli.connection-up"]
    arguments = spec.argument_model.model_validate(
        {"interface": "wlan1", "connection_uuid": connection_uuid}
    )

    assert spec.build_argv(arguments) == [
        "connection",
        "up",
        "uuid",
        connection_uuid,
        "ifname",
        "wlan1",
    ]
    for invalid in (
        "ABCDEF00-0000-4000-8000-000000000001",
        "not-a-uuid",
        connection_uuid + " ",
    ):
        with pytest.raises(ValueError):
            spec.argument_model.model_validate({"interface": "wlan1", "connection_uuid": invalid})


def test_product_preflight_builds_ap_rollback_without_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NoIoRunner:
        async def run(self, *args: object, **kwargs: object) -> object:
            raise AssertionError("preflight must not execute a provider")

    root = Path.cwd().resolve()
    paths = {name: root / name for name in ("ip", "iw", "nmcli", "dumpcap")}
    specs = capture_command_specs(
        paths=paths,
        artifact_root=root / "artifacts",
        environment={},
    )
    monkeypatch.setattr(
        "wto_desktop_agent.platforms.linux.capture_backend._revalidate_capture_executable",
        lambda command_id, spec: None,
    )
    backend = LinuxCommandCaptureBackend(_NoIoRunner(), specs)  # type: ignore[arg-type]
    connection_uuid = "50000000-0000-4000-8000-000000000001"
    state = InterfaceState(
        interface="wlan1",
        interface_type="AP",
        administratively_up=True,
        network_manager_managed=True,
        channel=1,
        frequency_mhz=2412,
        width_mhz=20,
        active_connection_uuids=(connection_uuid,),
        active_connections_status="complete",
        network_manager_connection_uuid=connection_uuid,
        network_manager_connection_name="Casa: 5 GHz",
    )

    backend.preflight(_request(channel=36, frequency_mhz=5180, width_mhz=20), state)


@pytest.mark.asyncio
async def test_unrepresentable_ap_mapper_fails_before_durable_or_live_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NoIoRunner:
        async def run(self, *args: object, **kwargs: object) -> object:
            raise AssertionError("AP preflight must not execute a provider")

    class _StaticAPBackend(LinuxCommandCaptureBackend):
        async def is_connectivity_interface(self, interface: str) -> bool:
            assert interface == "wlan1"
            return False

        async def monitor_supported(self, interface: str) -> bool:
            assert interface == "wlan1"
            return True

        async def snapshot(self, interface: str) -> InterfaceState:
            assert interface == "wlan1"
            return InterfaceState(
                interface="wlan1",
                interface_type="AP",
                administratively_up=True,
                network_manager_managed=False,
                channel=1,
                frequency_mhz=2412,
                width_mhz=20,
                active_connection_uuids=(),
                active_connections_status="complete",
                namespace="net:[1]",
                wiphy="phy1",
                driver="test",
            )

    class _Authorization:
        def authorize(
            self,
            *,
            agent_id: str | None,
            capability_id: str,
        ) -> PrivilegedAuthorizationDecision:
            return PrivilegedAuthorizationDecision(
                agent_id == "agent-for-ap-preflight" and capability_id == MONITOR_CAPTURE_CAPABILITY
            )

    root = tmp_path.resolve()
    paths = {name: root / name for name in ("ip", "iw", "nmcli", "dumpcap")}
    specs = capture_command_specs(
        paths=paths,
        artifact_root=root / "artifacts",
        environment={},
    )
    monkeypatch.setattr(
        "wto_desktop_agent.platforms.linux.capture_backend._revalidate_capture_executable",
        lambda command_id, spec: None,
    )
    supported_mapper = canonical_interface_type_to_iw_command_token

    def mapper_without_ap(value: object) -> IwInterfaceTypeCommandToken:
        if value == "AP":
            raise ValueError("target iw mapper version cannot represent AP")
        return supported_mapper(value)

    monkeypatch.setattr(
        capture_commands_module,
        "canonical_interface_type_to_iw_command_token",
        mapper_without_ap,
    )
    backend = _StaticAPBackend(_NoIoRunner(), specs)  # type: ignore[arg-type]
    live_factory_calls: list[str] = []

    def forbidden_live_factory() -> CaptureLiveDependencies:
        live_factory_calls.append("called")
        raise AssertionError("AP preflight constructed durable live dependencies")

    coordinator = CaptureCoordinator(
        backend,
        None,
        None,
        role="capture_node",
        enabled=True,
        agent_id_provider=lambda: "agent-for-ap-preflight",
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
        live_dependencies_factory=forbidden_live_factory,
    )

    with pytest.raises(ValueError, match="mapper version cannot represent AP"):
        await coordinator.execute(
            _request(channel=36, frequency_mhz=5180, width_mhz=20),
            CancellationToken(),
        )

    assert live_factory_calls == []
    assert not list(tmp_path.rglob("*"))
