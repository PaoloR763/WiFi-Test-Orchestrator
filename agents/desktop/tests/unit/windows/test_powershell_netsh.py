from __future__ import annotations

from pathlib import Path

import pytest

from wto_desktop_agent.platforms.windows.netsh import parse_netsh_interfaces
from wto_desktop_agent.platforms.windows.powershell import (
    parse_powershell_inventory,
    verify_inventory_script,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "windows"


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
    assert verify_inventory_script().name == "network_inventory.ps1"
    changed = tmp_path / "network_inventory.ps1"
    changed.write_bytes(b"Write-Output '{}'")
    with pytest.raises(RuntimeError, match="integrity"):
        verify_inventory_script(changed)
