from __future__ import annotations

import json
from pathlib import Path

import pytest

from wto_desktop_agent.platforms.linux.errors import LinuxProviderError
from wto_desktop_agent.platforms.linux.parsers import (
    infer_phy_standard,
    parse_ethtool_driver,
    parse_ip_address_json,
    parse_ip_route_json,
    parse_iw_dev,
    parse_iw_info,
    parse_iw_link,
    parse_iw_phy_monitor_support,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "linux"


def test_ip_json_preserves_physical_virtual_addresses_counters_and_missing_fields() -> None:
    interfaces = parse_ip_address_json((FIXTURES / "ip" / "address.json").read_bytes())
    routes = parse_ip_route_json((FIXTURES / "ip" / "routes.json").read_bytes())

    assert [item["name"] for item in interfaces] == ["eth0", "wlan0", "veth0"]
    assert interfaces[0]["rx_drops"] == 1
    assert interfaces[1]["addresses"] == [
        {"family": "ipv4", "address": "198.51.100.4", "prefix_length": 24},
        {"family": "ipv6", "address": "2001:db8::4", "prefix_length": 64},
    ]
    assert interfaces[2]["virtual_kind"] == "veth"
    assert interfaces[2]["rx_bytes"] is None
    assert routes[0]["gateway"] == "192.0.2.1"


def test_ip_json_requires_authoritative_link_flags() -> None:
    document = json.loads((FIXTURES / "ip" / "address.json").read_text(encoding="utf-8"))
    del document[0]["flags"]

    with pytest.raises(LinuxProviderError, match="invalid_output"):
        parse_ip_address_json(json.dumps(document).encode("utf-8"))


def test_iw_and_ethtool_parsers_are_structured_and_locale_independent() -> None:
    devices = parse_iw_dev((FIXTURES / "iw" / "dev.txt").read_bytes())
    link = parse_iw_link((FIXTURES / "iw" / "link.txt").read_bytes())
    info = parse_iw_info((FIXTURES / "iw" / "info.txt").read_bytes())
    driver = parse_ethtool_driver((FIXTURES / "ethtool" / "driver.txt").read_bytes())

    assert devices == [
        {
            "name": "wlan0",
            "wiphy": "phy0",
            "index": 3,
            "mac_address": "02:00:00:00:00:02",
            "type": "managed",
            "tx_power_dbm": 20.0,
        }
    ]
    assert link["signal_dbm"] == -47.0
    assert link["rx_bitrate_mbps"] == 780.0
    assert infer_phy_standard(link["phy_markers"]) == "802.11ax"
    assert info == {
        "type": "managed",
        "channel": 36,
        "frequency_mhz": 5180,
        "channel_width_mhz": 80,
        "center_frequency_1_mhz": 5210,
        "center_frequency_2_mhz": None,
    }
    assert driver["driver"] == "iwlwifi"
    assert parse_iw_phy_monitor_support((FIXTURES / "iw" / "phy.txt").read_bytes())
    assert parse_iw_link(b"Not connected.\n") == {"connected": False}
    with pytest.raises(LinuxProviderError, match="invalid_output"):
        parse_iw_link(b"texto no reconocido\nNot connected.\n")
    with pytest.raises(LinuxProviderError, match="invalid_output") as empty:
        parse_iw_link(b" \n\t\n")
    assert empty.value.detail == "empty_output"
    with pytest.raises(LinuxProviderError, match="invalid_output"):
        parse_iw_link(b"Connected to aa:bb:cc:dd:ee:ff\nunknown: value\n")
    with pytest.raises(LinuxProviderError, match="invalid_output"):
        parse_iw_link(b"Connected to aa:bb:cc:dd:ee:ff\nfreq: 5180\nfreq: 5200\n")


@pytest.mark.parametrize(
    "parser,payload",
    [
        (parse_ip_address_json, b"{}"),
        (parse_ip_address_json, b"not-json"),
        (parse_ip_route_json, b'[{"dev":"../../bad"}]'),
        (parse_iw_link, b"garbage"),
        (parse_ethtool_driver, b"campo-desconocido: valor\n"),
    ],
)
def test_invalid_outputs_fail_closed(parser: object, payload: bytes) -> None:
    with pytest.raises((LinuxProviderError, ValueError)):
        parser(payload)  # type: ignore[operator]
