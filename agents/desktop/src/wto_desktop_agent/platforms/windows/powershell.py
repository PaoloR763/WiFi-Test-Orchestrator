from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

NETWORK_INVENTORY_SCRIPT_SHA256 = "e56df62259967f814ed07fa41e4055663127b9877869ec5e3c5949ea6c03767b"


class StrictPowerShellModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PowerShellAddress(StrictPowerShellModel):
    family: Literal["IPv4", "IPv6"]
    address: str
    prefix_length: int = Field(ge=0, le=128)


class PowerShellRoute(StrictPowerShellModel):
    family: Literal["IPv4", "IPv6"]
    destination_prefix: str
    next_hop: str
    route_metric: int = Field(ge=0)


class PowerShellAdapter(StrictPowerShellModel):
    interface_guid: str | None
    interface_index: int = Field(ge=0)
    name: str
    description: str | None
    status: str | None
    virtual: bool | None
    hardware_interface: bool | None
    manufacturer: str | None
    model: str | None = None
    driver_description: str | None
    driver_provider: str | None
    driver_version: str | None
    mac_address: str | None
    link_speed: str | None
    statistics_available: bool = True
    ip_configuration_available: bool = True
    addresses_available: bool = True
    routes_available: bool = True
    dns_available: bool = True
    received_bytes: int | None = Field(default=None, ge=0)
    sent_bytes: int | None = Field(default=None, ge=0)
    received_packets: int | None = Field(default=None, ge=0)
    sent_packets: int | None = Field(default=None, ge=0)
    received_errors: int | None = Field(default=None, ge=0)
    sent_errors: int | None = Field(default=None, ge=0)
    received_discards: int | None = Field(default=None, ge=0)
    sent_discards: int | None = Field(default=None, ge=0)
    addresses: list[PowerShellAddress]
    routes: list[PowerShellRoute]
    gateways: list[str] = Field(default_factory=list)
    dns_servers: list[str]

    @field_validator("interface_guid")
    @classmethod
    def canonical_guid(cls, value: str | None) -> str | None:
        return str(UUID(value.strip("{}"))) if value else None


class PowerShellInventory(StrictPowerShellModel):
    schema_version: Literal["1.0.0"]
    powershell_edition: str
    powershell_version: str
    adapters: list[PowerShellAdapter]


def parse_powershell_inventory(raw: bytes, *, max_bytes: int = 4_194_304) -> PowerShellInventory:
    if len(raw) > max_bytes:
        raise ValueError("PowerShell output exceeds limit")
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    text = raw.decode("utf-8", errors="strict")
    if not text or text.lstrip() != text or not text.startswith("{"):
        raise ValueError("PowerShell stdout contains non-JSON noise")
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError("PowerShell stdout is invalid JSON") from error
    return PowerShellInventory.model_validate(document)


def inventory_script_path() -> Path:
    return Path(
        str(
            files("wto_desktop_agent.platforms.windows")
            .joinpath("scripts")
            .joinpath("network_inventory.ps1")
        )
    )


def script_sha256(path: Path | None = None) -> str:
    return hashlib.sha256((path or inventory_script_path()).read_bytes()).hexdigest()


def verify_inventory_script(path: Path | None = None) -> Path:
    candidate = path or inventory_script_path()
    if script_sha256(candidate) != NETWORK_INVENTORY_SCRIPT_SHA256:
        raise RuntimeError("packaged PowerShell inventory script integrity mismatch")
    return candidate
