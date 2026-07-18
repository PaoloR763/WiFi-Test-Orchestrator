from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from wto_desktop_agent.platforms.common import (
    CommandOutputMode,
    CommandSpec,
    ExecutableIdentity,
    LinuxCleanupScope,
)
from wto_desktop_agent.platforms.linux.capture_identity import (
    CaptureInterfaceType,
    IwInterfaceTypeCommandToken,
    canonical_interface_type_to_iw_command_token,
    validate_networkmanager_uuid,
)
from wto_desktop_agent.platforms.linux.frequency import (
    iw_width_token,
    validate_complete_channel_definition,
)
from wto_desktop_agent.platforms.linux.parsers import validate_interface_name


class NoArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InterfaceArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")
    interface: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$")


class PhyArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")
    phy: str = Field(pattern=r"^phy[0-9]+$")


class LinkStateArguments(InterfaceArguments):
    state: Literal["up", "down"]


class ManagedArguments(InterfaceArguments):
    managed: bool


class InterfaceTypeArguments(InterfaceArguments):
    interface_type: CaptureInterfaceType


class IwTypeCommandArguments(InterfaceArguments):
    interface_type_token: IwInterfaceTypeCommandToken


class FrequencyArguments(InterfaceArguments):
    frequency_mhz: int = Field(ge=2400, le=71_000)
    channel: int = Field(ge=1, le=233)
    width_mhz: Literal[20, 80, 160]
    center_frequency_1_mhz: int = Field(ge=2400, le=71_000)
    center_frequency_2_mhz: int | None = Field(default=None, ge=2400, le=71_000)

    @model_validator(mode="after")
    def validate_capture_channel_definition(self) -> FrequencyArguments:
        validate_complete_channel_definition(
            frequency_mhz=self.frequency_mhz,
            channel=self.channel,
            width_mhz=self.width_mhz,
            center_frequency_1_mhz=self.center_frequency_1_mhz,
            center_frequency_2_mhz=self.center_frequency_2_mhz,
        )
        return self


class ConnectionArguments(InterfaceArguments):
    connection_uuid: str

    @field_validator("connection_uuid", mode="before")
    @classmethod
    def canonical_connection_uuid(cls, value: object) -> str:
        return validate_networkmanager_uuid(value)


class DumpcapArguments(InterfaceArguments):
    duration_seconds: int = Field(ge=1, le=3600)
    size_kib: int = Field(ge=1, le=1_048_576)
    capture_format: Literal["pcap", "pcapng"]
    snapshot_length: int = Field(default=262_144, ge=64, le=262_144)


def build_iw_frequency_argv(value: FrequencyArguments) -> list[str]:
    argv = [
        "dev",
        validate_interface_name(value.interface),
        "set",
        "freq",
        str(value.frequency_mhz),
        iw_width_token(value.width_mhz),
    ]
    if value.width_mhz in {80, 160}:
        argv.append(str(value.center_frequency_1_mhz))
    return argv


def build_iw_type_argv(value: InterfaceTypeArguments) -> list[str]:
    command = IwTypeCommandArguments(
        interface=value.interface,
        interface_type_token=canonical_interface_type_to_iw_command_token(value.interface_type),
    )
    return [
        "dev",
        validate_interface_name(command.interface),
        "set",
        "type",
        command.interface_type_token,
    ]


def build_dumpcap_argv(value: DumpcapArguments) -> list[str]:
    return [
        "-q",
        "-i",
        validate_interface_name(value.interface),
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


def capture_command_specs(
    *,
    paths: dict[str, Path | None],
    identities: dict[str, ExecutableIdentity | None] | None = None,
    artifact_root: Path,
    environment: dict[str, str],
) -> dict[str, CommandSpec]:
    root = Path("/").resolve()
    artifact_root = artifact_root.resolve()
    result: dict[str, CommandSpec] = {}
    identities = identities or {}
    ip = paths.get("ip")
    if ip is not None:
        result["linux.ip.link-one-json"] = CommandSpec(
            command_id="linux.ip.link-one-json",
            executable=ip,
            argument_model=InterfaceArguments,
            build_argv=lambda value: [
                "-details",
                "-statistics",
                "-json",
                "link",
                "show",
                "dev",
                validate_interface_name(value.interface),
            ],
            cwd=root,
            environment=environment,
            linux_cleanup_scope=LinuxCleanupScope.LEADER_ONLY,
            executable_identity=identities.get("ip"),
        )
        result["linux.ip.link-set"] = CommandSpec(
            command_id="linux.ip.link-set",
            executable=ip,
            argument_model=LinkStateArguments,
            build_argv=lambda value: [
                "link",
                "set",
                "dev",
                validate_interface_name(value.interface),
                value.state,
            ],
            cwd=root,
            environment=environment,
            linux_cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
            executable_identity=identities.get("ip"),
        )
    iw = paths.get("iw")
    if iw is not None:
        result["linux.iw.phy-info"] = CommandSpec(
            command_id="linux.iw.phy-info",
            executable=iw,
            argument_model=PhyArguments,
            build_argv=lambda value: ["phy", value.phy, "info"],
            cwd=root,
            environment=environment,
            max_output_bytes=4_194_304,
            linux_cleanup_scope=LinuxCleanupScope.LEADER_ONLY,
            executable_identity=identities.get("iw"),
        )
        result["linux.iw.type-set"] = CommandSpec(
            command_id="linux.iw.type-set",
            executable=iw,
            argument_model=InterfaceTypeArguments,
            build_argv=build_iw_type_argv,
            cwd=root,
            environment=environment,
            linux_cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
            executable_identity=identities.get("iw"),
        )
        result["linux.iw.frequency-set"] = CommandSpec(
            command_id="linux.iw.frequency-set",
            executable=iw,
            argument_model=FrequencyArguments,
            build_argv=build_iw_frequency_argv,
            cwd=root,
            environment=environment,
            linux_cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
            executable_identity=identities.get("iw"),
        )
    nmcli = paths.get("nmcli")
    if nmcli is not None:
        result["linux.nmcli.device"] = CommandSpec(
            command_id="linux.nmcli.device",
            executable=nmcli,
            argument_model=InterfaceArguments,
            build_argv=lambda value: [
                "--terse",
                "--escape",
                "yes",
                "--fields",
                "GENERAL.MANAGED,GENERAL.STATE,GENERAL.CONNECTION,GENERAL.CON-UUID",
                "device",
                "show",
                validate_interface_name(value.interface),
            ],
            cwd=root,
            environment=environment,
            linux_cleanup_scope=LinuxCleanupScope.LEADER_ONLY,
            executable_identity=identities.get("nmcli"),
        )
        result["linux.nmcli.active"] = CommandSpec(
            command_id="linux.nmcli.active",
            executable=nmcli,
            argument_model=NoArguments,
            build_argv=lambda _: [
                "--terse",
                "--escape",
                "yes",
                "--fields",
                "UUID,DEVICE",
                "connection",
                "show",
                "--active",
            ],
            cwd=root,
            environment=environment,
            linux_cleanup_scope=LinuxCleanupScope.LEADER_ONLY,
            executable_identity=identities.get("nmcli"),
        )
        result["linux.nmcli.managed-set"] = CommandSpec(
            command_id="linux.nmcli.managed-set",
            executable=nmcli,
            argument_model=ManagedArguments,
            build_argv=lambda value: [
                "device",
                "set",
                validate_interface_name(value.interface),
                "managed",
                "yes" if value.managed else "no",
            ],
            cwd=root,
            environment=environment,
            linux_cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
            executable_identity=identities.get("nmcli"),
        )
        result["linux.nmcli.connection-up"] = CommandSpec(
            command_id="linux.nmcli.connection-up",
            executable=nmcli,
            argument_model=ConnectionArguments,
            build_argv=lambda value: [
                "connection",
                "up",
                "uuid",
                value.connection_uuid,
                "ifname",
                validate_interface_name(value.interface),
            ],
            cwd=root,
            environment=environment,
            linux_cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
            executable_identity=identities.get("nmcli"),
        )
    dumpcap = paths.get("dumpcap")
    if dumpcap is not None:

        result["linux.dumpcap.capture"] = CommandSpec(
            command_id="linux.dumpcap.capture",
            executable=dumpcap,
            argument_model=DumpcapArguments,
            build_argv=build_dumpcap_argv,
            cwd=artifact_root,
            environment=environment,
            max_output_bytes=1_048_576,
            linux_cleanup_scope=LinuxCleanupScope.PROCESS_TREE,
            output_mode=CommandOutputMode.CALLER_FILE_DESCRIPTOR,
            executable_identity=identities.get("dumpcap"),
        )
    return result
