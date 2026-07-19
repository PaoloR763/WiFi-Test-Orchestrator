from __future__ import annotations

import asyncio
import os
from collections.abc import Mapping
from typing import Literal, Protocol, cast

from wto_desktop_agent.platforms.common import CommandSpec
from wto_desktop_agent.platforms.linux.capture import (
    CaptureRequest,
    InterfaceState,
    NetworkManagerConnectionObservation,
    NetworkManagerConnectionProfileMissing,
    networkmanager_restore_plan,
)
from wto_desktop_agent.platforms.linux.capture_commands import (
    DumpcapArguments,
    build_dumpcap_argv,
)
from wto_desktop_agent.platforms.linux.capture_fingerprint import CaptureExecutionPlan
from wto_desktop_agent.platforms.linux.capture_identity import (
    CaptureInterfaceType,
    parse_capture_interface_type,
    validate_networkmanager_connection_id,
    validate_networkmanager_uuid,
)
from wto_desktop_agent.platforms.linux.frequency import (
    capture_channel_definition,
    validate_complete_channel_definition,
)
from wto_desktop_agent.platforms.linux.parsers import (
    parse_ethtool_driver,
    parse_ip_address_json,
    parse_ip_route_json,
    parse_iw_dev,
    parse_iw_info,
    parse_iw_phy_monitor_support,
    validate_interface_name,
)
from wto_desktop_agent.platforms.linux.tooling import (
    TrustedExecutableStatus,
    revalidate_trusted_executable,
)
from wto_desktop_agent.ports.platform import (
    CommandRequest,
    ProcessResult,
    ProcessRunner,
)
from wto_desktop_agent.ports.plugins import CancellationToken


class DescriptorProcessRunner(Protocol):
    async def run_with_stdout_descriptor(
        self,
        request: CommandRequest,
        cancellation: CancellationToken,
        *,
        stdout_descriptor: int,
    ) -> ProcessResult: ...


def _nmcli_reports_missing_connection_profile(
    *,
    return_code: int,
    stderr: bytes,
    connection_uuid: str,
) -> bool:
    """Recognize only NetworkManager's locale-C missing-profile diagnostic."""

    if return_code != 10:
        return False
    expected = f"Error: unknown connection '{connection_uuid}'.".encode("ascii")
    return stderr in {expected, expected + b"\n"}


def build_capture_execution_plan(request: CaptureRequest) -> CaptureExecutionPlan:
    """Build capture semantics without inspecting tools or live Linux state."""

    size_kib = max(1, request.max_size_bytes // 1024)
    parameters = DumpcapArguments.model_validate(
        {
            "interface": request.interface,
            "duration_seconds": request.duration_seconds,
            "size_kib": size_kib,
            "capture_format": request.capture_format,
            "snapshot_length": request.snapshot_length,
        }
    )
    argv = build_dumpcap_argv(parameters)
    return CaptureExecutionPlan(
        provider="linux-dumpcap",
        method="radiotap-frequency-lock",
        effective_dumpcap_arguments=tuple(argv),
        effective_size_limit_bytes=size_kib * 1024,
    )


def _split_escaped(value: str) -> tuple[str, str] | None:
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            return value[:index], value[index + 1 :].replace("\\:", ":").replace("\\\\", "\\")
    return None


def _parse_nmcli_device(value: str) -> dict[str, str]:
    expected = {
        "GENERAL.MANAGED",
        "GENERAL.STATE",
        "GENERAL.CONNECTION",
        "GENERAL.CON-UUID",
    }
    result: dict[str, str] = {}
    for line in value.splitlines():
        if not line:
            continue
        pair = _split_escaped(line)
        if pair is None or pair[0] not in expected or pair[0] in result:
            raise ValueError("NetworkManager device output is incomplete")
        result[pair[0]] = pair[1]
    if set(result) != expected or result["GENERAL.MANAGED"] not in {"yes", "no"}:
        raise ValueError("NetworkManager device properties are incomplete")
    return result


def _revalidate_capture_executable(command_id: str, spec: CommandSpec) -> None:
    if spec.executable_identity is None:
        raise RuntimeError(f"allowlisted provider has no trusted identity: {command_id}")
    status = TrustedExecutableStatus(
        name=command_id,
        path=spec.executable,
        reason=None,
        identity=spec.executable_identity,
        state="available",
    )
    try:
        revalidate_trusted_executable(status)
    except PermissionError as error:
        raise RuntimeError(
            f"allowlisted provider identity is no longer trusted: {command_id}"
        ) from error


class LinuxCommandCaptureBackend:
    def __init__(
        self,
        runner: ProcessRunner,
        commands: Mapping[str, CommandSpec] | frozenset[str],
    ) -> None:
        self.runner = runner
        if isinstance(commands, Mapping):
            self._command_specs = dict(commands)
            self.commands = frozenset(commands)
        else:
            self.commands = commands
            registered = getattr(runner, "_commands", None)
            self._command_specs = (
                {name: spec for name, spec in registered.items() if name in commands}
                if isinstance(registered, Mapping)
                and all(isinstance(spec, CommandSpec) for spec in registered.values())
                else {}
            )

    def _preflight_command(self, command_id: str, arguments: dict[str, object]) -> None:
        if command_id not in self.commands:
            raise RuntimeError(f"required allowlisted provider is unavailable: {command_id}")
        try:
            spec = self._command_specs[command_id]
        except KeyError as error:
            raise RuntimeError(
                f"allowlisted provider cannot be preflighted: {command_id}"
            ) from error
        parameters = spec.argument_model.model_validate(arguments)
        argv = spec.build_argv(parameters)
        if not spec.executable.is_absolute() or not spec.cwd.is_absolute():
            raise RuntimeError(f"allowlisted provider path is not absolute: {command_id}")
        _revalidate_capture_executable(command_id, spec)
        if not isinstance(argv, list) or any(
            type(argument) is not str or "\x00" in argument for argument in argv
        ):
            raise RuntimeError(f"allowlisted provider argv is invalid: {command_id}")

    def preflight(self, request: CaptureRequest, state: InterfaceState) -> None:
        """Build every future mutating/capture argv without executing providers."""

        interface = request.interface
        requested_channel = capture_channel_definition(
            frequency_mhz=request.frequency_mhz,
            channel=request.channel,
            width_mhz=request.width_mhz,
        )
        invocations: list[tuple[str, dict[str, object]]] = []
        if state.network_manager_managed:
            invocations.append(
                ("linux.nmcli.managed-set", {"interface": interface, "managed": False})
            )
        invocations.extend(
            (
                ("linux.ip.link-set", {"interface": interface, "state": "down"}),
                (
                    "linux.iw.type-set",
                    {"interface": interface, "interface_type": "monitor"},
                ),
                ("linux.ip.link-set", {"interface": interface, "state": "up"}),
                (
                    "linux.iw.frequency-set",
                    {
                        "interface": interface,
                        "frequency_mhz": request.frequency_mhz,
                        "channel": request.channel,
                        "width_mhz": request.width_mhz,
                        "center_frequency_1_mhz": (requested_channel.center_frequency_1_mhz),
                        "center_frequency_2_mhz": (requested_channel.center_frequency_2_mhz),
                    },
                ),
                (
                    "linux.dumpcap.capture",
                    {
                        "interface": interface,
                        "duration_seconds": request.duration_seconds,
                        "size_kib": max(1, request.max_size_bytes // 1024),
                        "capture_format": request.capture_format,
                        "snapshot_length": request.snapshot_length,
                    },
                ),
                ("linux.ip.link-set", {"interface": interface, "state": "down"}),
                (
                    "linux.iw.type-set",
                    {
                        "interface": interface,
                        "interface_type": state.interface_type,
                    },
                ),
            )
        )
        if (
            state.frequency_mhz is not None
            and state.channel is not None
            and state.width_mhz is not None
        ):
            original_channel = validate_complete_channel_definition(
                frequency_mhz=state.frequency_mhz,
                channel=state.channel,
                width_mhz=state.width_mhz,
                center_frequency_1_mhz=state.center_frequency_1_mhz,
                center_frequency_2_mhz=state.center_frequency_2_mhz,
            )
            invocations.append(
                (
                    "linux.iw.frequency-set",
                    {
                        "interface": interface,
                        "frequency_mhz": state.frequency_mhz,
                        "channel": state.channel,
                        "width_mhz": state.width_mhz,
                        "center_frequency_1_mhz": original_channel.center_frequency_1_mhz,
                        "center_frequency_2_mhz": original_channel.center_frequency_2_mhz,
                    },
                )
            )
        invocations.append(
            (
                "linux.ip.link-set",
                {
                    "interface": interface,
                    "state": "up" if state.administratively_up else "down",
                },
            )
        )
        if state.network_manager_managed is not None:
            invocations.append(
                (
                    "linux.nmcli.managed-set",
                    {
                        "interface": interface,
                        "managed": state.network_manager_managed,
                    },
                )
            )
        invocations.extend(
            (
                "linux.nmcli.connection-up",
                {
                    "interface": operation.interface,
                    "connection_uuid": operation.connection_uuid,
                },
            )
            for operation in networkmanager_restore_plan(state)
        )
        for command_id, arguments in invocations:
            self._preflight_command(command_id, arguments)

    def capture_plan(self, request: CaptureRequest) -> CaptureExecutionPlan:
        return build_capture_execution_plan(request)

    async def _run(
        self,
        command_id: str,
        arguments: dict[str, object],
        *,
        process_budget_seconds: float = 10.0,
        cancellation: CancellationToken | None = None,
    ) -> bytes:
        if command_id not in self.commands:
            raise RuntimeError(f"required allowlisted provider is unavailable: {command_id}")
        result = await self.runner.run(
            CommandRequest(
                command_id=command_id,
                arguments=arguments,
                timeout_seconds=process_budget_seconds,
            ),
            cancellation or CancellationToken(),
        )
        if result.return_code != 0:
            connection_uuid = arguments.get("connection_uuid")
            if (
                command_id == "linux.nmcli.connection-up"
                and isinstance(connection_uuid, str)
                and _nmcli_reports_missing_connection_profile(
                    return_code=result.return_code,
                    stderr=result.stderr,
                    connection_uuid=connection_uuid,
                )
            ):
                raise NetworkManagerConnectionProfileMissing("connection_profile_missing")
            raise RuntimeError(f"allowlisted provider failed: {command_id}")
        return result.stdout

    async def is_connectivity_interface(self, interface: str) -> bool:
        validate_interface_name(interface)
        raw4, raw6 = await asyncio.gather(
            self._run("linux.ip.route-json", {}),
            self._run("linux.ip.route6-json", {}),
        )
        return any(
            route["interface"] == interface and route["destination"] == "default"
            for route in [*parse_ip_route_json(raw4), *parse_ip_route_json(raw6)]
        )

    async def monitor_supported(self, interface: str) -> bool:
        validate_interface_name(interface)
        devices = parse_iw_dev(await self._run("linux.iw.dev", {}))
        device = next((item for item in devices if item["name"] == interface), None)
        if device is None or not isinstance(device.get("wiphy"), str):
            return False
        raw = await self._run("linux.iw.phy-info", {"phy": device["wiphy"]})
        return parse_iw_phy_monitor_support(raw)

    async def snapshot(self, interface: str) -> InterfaceState:
        validate_interface_name(interface)
        link_raw, iw_raw, devices_raw = await asyncio.gather(
            self._run("linux.ip.link-one-json", {"interface": interface}),
            self._run("linux.iw.info", {"interface": interface}),
            self._run("linux.iw.dev", {}),
        )
        links = parse_ip_address_json(link_raw)
        if len(links) != 1:
            raise RuntimeError("interface snapshot did not return exactly one link")
        link = links[0]
        iw = parse_iw_info(iw_raw)
        device = next(
            (item for item in parse_iw_dev(devices_raw) if item["name"] == interface),
            None,
        )
        managed: bool | None = None
        connection_uuids: tuple[str, ...] = ()
        connections_status: Literal["complete", "partial", "unavailable"] = "unavailable"
        connections_provenance: list[str] = []
        connections_errors: list[str] = []
        current_connection_uuid: str | None = None
        current_connection_name: str | None = None
        device_snapshot_complete = False
        active_snapshot_complete = False
        try:
            nm = (await self._run("linux.nmcli.device", {"interface": interface})).decode("utf-8")
            values = _parse_nmcli_device(nm)
            managed = values["GENERAL.MANAGED"] == "yes"
            reported_connection = values["GENERAL.CONNECTION"]
            reported_uuid = values["GENERAL.CON-UUID"]
            if reported_connection not in {"", "--"}:
                current_connection_name = validate_networkmanager_connection_id(reported_connection)
            if reported_uuid not in {"", "--"}:
                current_connection_uuid = validate_networkmanager_uuid(reported_uuid)
            if (current_connection_name is None) != (current_connection_uuid is None):
                raise ValueError("NetworkManager connection identity is incomplete")
            device_snapshot_complete = True
            connections_provenance.append("networkmanager.nmcli.device")
        except (RuntimeError, TimeoutError, OSError, UnicodeDecodeError, ValueError):
            managed = None
            current_connection_uuid = None
            current_connection_name = None
            connections_errors.append("networkmanager_device_unavailable")
        try:
            active = (await self._run("linux.nmcli.active", {})).decode("utf-8")
            uuids: list[str] = []
            for line in active.splitlines():
                if not line:
                    continue
                pair = _split_escaped(line)
                if pair is None:
                    raise ValueError("NetworkManager active connection output is incomplete")
                active_interface = validate_interface_name(pair[1])
                connection_uuid = validate_networkmanager_uuid(pair[0])
                if active_interface == interface:
                    uuids.append(connection_uuid)
            if len(set(uuids)) != len(uuids):
                raise ValueError("NetworkManager active connection UUIDs are duplicated")
            connection_uuids = tuple(sorted(uuids))
            active_snapshot_complete = True
            connections_provenance.append("networkmanager.nmcli.active")
        except (RuntimeError, TimeoutError, OSError, UnicodeDecodeError, ValueError):
            connection_uuids = ()
            connections_errors.append("active_connections_unavailable")
        if device_snapshot_complete and active_snapshot_complete:
            views_consistent = (not connection_uuids and current_connection_uuid is None) or (
                bool(connection_uuids)
                and current_connection_uuid is not None
                and current_connection_uuid in connection_uuids
            )
            if views_consistent:
                connections_status = "complete"
                secondaries = sorted(
                    connection_uuid
                    for connection_uuid in connection_uuids
                    if connection_uuid != current_connection_uuid
                )
                connection_uuids = tuple(
                    [*secondaries]
                    + ([current_connection_uuid] if current_connection_uuid is not None else [])
                )
            else:
                connections_status = "partial"
                connections_errors.append("networkmanager_connection_views_inconsistent")
        elif device_snapshot_complete or active_snapshot_complete:
            connections_status = "partial"
        driver: str | None = None
        try:
            driver_values = parse_ethtool_driver(
                await self._run("linux.ethtool.driver", {"interface": interface})
            )
            driver = driver_values.get("driver")
        except RuntimeError:
            pass
        namespace: str | None = None
        try:
            namespace = os.readlink("/proc/self/ns/net")[:128]
        except OSError:
            pass
        return InterfaceState(
            interface=interface,
            interface_type=parse_capture_interface_type(iw.get("type")),
            administratively_up=bool(link.get("administratively_up", False)),
            network_manager_managed=managed,
            channel=cast(int | None, iw.get("channel")),
            frequency_mhz=cast(int | None, iw.get("frequency_mhz")),
            width_mhz=cast(int | None, iw.get("channel_width_mhz")),
            center_frequency_1_mhz=cast(int | None, iw.get("center_frequency_1_mhz")),
            center_frequency_2_mhz=cast(int | None, iw.get("center_frequency_2_mhz")),
            active_connection_uuids=connection_uuids,
            ordered_active_connection_uuids=connection_uuids,
            active_connection_interfaces=tuple(
                NetworkManagerConnectionObservation(
                    connection_uuid=connection_uuid,
                    interface=interface,
                    restore_position=position,
                )
                for position, connection_uuid in enumerate(connection_uuids)
            ),
            active_connections_status=connections_status,
            active_connections_provenance=tuple(connections_provenance),
            active_connections_source_errors=tuple(connections_errors),
            network_manager_connection_uuid=current_connection_uuid,
            primary_connection_uuid=current_connection_uuid,
            network_manager_connection_name=current_connection_name,
            network_manager_restore_schema_version="networkmanager-restore-v1",
            namespace=namespace,
            wiphy=str(device["wiphy"]) if device and device.get("wiphy") else None,
            driver=driver,
        )

    async def set_managed(self, interface: str, managed: bool) -> None:
        await self._run("linux.nmcli.managed-set", {"interface": interface, "managed": managed})

    async def set_link(self, interface: str, up: bool) -> None:
        await self._run(
            "linux.ip.link-set",
            {"interface": interface, "state": "up" if up else "down"},
        )

    async def set_type(self, interface: str, interface_type: CaptureInterfaceType) -> None:
        if interface_type not in {"managed", "monitor", "AP", "mesh"}:
            raise RuntimeError("interface type is not a canonical command token")
        await self._run(
            "linux.iw.type-set",
            {"interface": interface, "interface_type": interface_type},
        )

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
        await self._run(
            "linux.iw.frequency-set",
            {
                "interface": interface,
                "frequency_mhz": frequency_mhz,
                "channel": channel,
                "width_mhz": width_mhz,
                "center_frequency_1_mhz": center_frequency_1_mhz,
                "center_frequency_2_mhz": center_frequency_2_mhz,
            },
        )

    async def restore_connection(self, interface: str, connection_uuid: str) -> None:
        await self._run(
            "linux.nmcli.connection-up",
            {
                "interface": validate_interface_name(interface),
                "connection_uuid": validate_networkmanager_uuid(connection_uuid),
            },
            process_budget_seconds=30.0,
        )

    async def capture(
        self,
        request: CaptureRequest,
        output_descriptor: int,
        cancellation: CancellationToken,
    ) -> None:
        command_id = "linux.dumpcap.capture"
        if command_id not in self.commands:
            raise RuntimeError(f"required allowlisted provider is unavailable: {command_id}")
        runner = cast(DescriptorProcessRunner, self.runner)
        result = await runner.run_with_stdout_descriptor(
            CommandRequest(
                command_id=command_id,
                arguments={
                    "interface": request.interface,
                    "duration_seconds": request.duration_seconds,
                    "size_kib": max(1, request.max_size_bytes // 1024),
                    "capture_format": request.capture_format,
                    "snapshot_length": request.snapshot_length,
                },
                timeout_seconds=float(request.duration_seconds + 10),
            ),
            cancellation,
            stdout_descriptor=output_descriptor,
        )
        if result.return_code != 0:
            raise RuntimeError(f"allowlisted provider failed: {command_id}")
