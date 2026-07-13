from __future__ import annotations

import re
from pathlib import Path

import pytest

from wto_desktop_agent.platforms.windows.netsh import parse_netsh_interfaces
from wto_desktop_agent.platforms.windows.powershell import (
    NETWORK_INVENTORY_SCRIPT_SHA256,
    PowerShellAdapter,
    PowerShellInventory,
    parse_powershell_inventory,
    script_sha256,
    verify_inventory_script,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "windows"
SCRIPT = (
    Path(__file__).parents[3]
    / "src"
    / "wto_desktop_agent"
    / "platforms"
    / "windows"
    / "scripts"
    / "network_inventory.ps1"
)


def test_powershell_51_and_7_have_stable_arrays() -> None:
    desktop = parse_powershell_inventory(
        (FIXTURES / "powershell" / "5.1" / "inventory.json").read_bytes()
    )
    core = parse_powershell_inventory(
        (FIXTURES / "powershell" / "7" / "inventory.json").read_bytes()
    )
    assert desktop.adapters[0].name == "Wi-Fi Ñ"
    assert desktop.adapters[0].received_errors is None
    assert desktop.adapters[0].sent_errors == 0
    assert core.adapters == []


@pytest.mark.parametrize("locale_name", ["en-US", "es-AR", "es-ES"])
def test_localized_netsh_fixtures(locale_name: str) -> None:
    raw = (FIXTURES / "netsh" / f"{locale_name}.txt").read_bytes()
    interfaces = parse_netsh_interfaces(raw)
    assert len(interfaces) == 1
    assert interfaces[0].guid is not None


def test_netsh_cp1252_and_unknown_labels() -> None:
    text = (FIXTURES / "netsh" / "es-AR.txt").read_text(encoding="utf-8")
    interface = parse_netsh_interfaces(text.encode("cp1252"))[0]
    assert interface.name == "Wi-Fi Ñ"
    assert interface.transmit_rate_mbps == 960.5


def test_noisy_or_invalid_powershell_is_rejected() -> None:
    with pytest.raises(ValueError, match="noise"):
        parse_powershell_inventory(b"warning\n{}")
    with pytest.raises(ValueError, match="invalid JSON"):
        parse_powershell_inventory(b"{truncated")


def test_packaged_powershell_script_hash_is_verified(tmp_path: Path) -> None:
    assert script_sha256() == NETWORK_INVENTORY_SCRIPT_SHA256
    assert verify_inventory_script().name == "network_inventory.ps1"
    changed = tmp_path / "network_inventory.ps1"
    changed.write_bytes(b"Write-Output '{}'")
    with pytest.raises(RuntimeError, match="integrity"):
        verify_inventory_script(changed)


def test_inventory_script_schema_keys_match_strict_models() -> None:
    inventory = parse_powershell_inventory(
        (FIXTURES / "powershell" / "5.1" / "inventory.json").read_bytes()
    ).model_dump(mode="json")

    assert set(inventory) == set(PowerShellInventory.model_fields)
    assert set(inventory["adapters"][0]) == set(PowerShellAdapter.model_fields)


def test_inventory_script_queries_each_global_source_once_before_assembly() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assembly_offset = source.index("$adapters =")
    commands = (
        "Get-CimInstance",
        "Get-NetAdapter",
        "Get-NetAdapterStatistics",
        "Get-NetIPConfiguration",
        "Get-NetIPAddress",
        "Get-NetRoute",
        "Get-DnsClientServerAddress",
    )

    for command in commands:
        occurrences = list(re.finditer(rf"\b{re.escape(command)}\b", source))
        assert len(occurrences) == 1, command
        assert occurrences[0].start() < assembly_offset, command
    assert "$signedDrivers | Where-Object" not in source
    assert re.search(
        r"-Property\s+DeviceID,\s*Manufacturer,\s*DeviceName,\s*"
        r"DriverProviderName,\s*DriverVersion",
        source,
    )
    assert "-OperationTimeoutSec 8" in source
