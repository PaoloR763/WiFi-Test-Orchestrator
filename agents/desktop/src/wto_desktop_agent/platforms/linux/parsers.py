from __future__ import annotations

import json
import re
from ipaddress import ip_address
from typing import Any

from wto_desktop_agent.platforms.linux.errors import LinuxProviderError

_INTERFACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$")
_MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


def validate_interface_name(value: str) -> str:
    if not _INTERFACE.fullmatch(value):
        raise ValueError("invalid Linux interface name")
    return value


def _json(raw: bytes, provider: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LinuxProviderError(
            provider, "invalid_output", "provider returned invalid JSON"
        ) from error


def _integer(value: object, provider: str, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise LinuxProviderError(provider, "invalid_output", f"{field} is not an integer")
    return value


def parse_ip_address_json(raw: bytes) -> list[dict[str, object]]:
    document = _json(raw, "ip-address")
    if not isinstance(document, list):
        raise LinuxProviderError("ip-address", "invalid_output", "top-level value is not an array")
    result: list[dict[str, object]] = []
    for entry in document:
        if not isinstance(entry, dict) or not isinstance(entry.get("ifname"), str):
            raise LinuxProviderError("ip-address", "invalid_output", "interface entry is invalid")
        name = validate_interface_name(entry["ifname"])
        flags = entry.get("flags")
        if not isinstance(flags, list) or not all(isinstance(item, str) for item in flags):
            raise LinuxProviderError("ip-address", "invalid_output", "flags are invalid")
        addresses: list[dict[str, object]] = []
        address_data = entry.get("addr_info", [])
        if not isinstance(address_data, list):
            raise LinuxProviderError("ip-address", "invalid_output", "addr_info is invalid")
        for address in address_data:
            if not isinstance(address, dict):
                raise LinuxProviderError("ip-address", "invalid_output", "address entry is invalid")
            family = address.get("family")
            local = address.get("local")
            prefix = address.get("prefixlen")
            if family not in {"inet", "inet6"} or not isinstance(local, str):
                continue
            prefix_value = _integer(prefix, "ip-address", "prefixlen")
            addresses.append(
                {
                    "family": "ipv4" if family == "inet" else "ipv6",
                    "address": local,
                    "prefix_length": prefix_value,
                }
            )
        stats = entry.get("stats64") or entry.get("stats") or {}
        if not isinstance(stats, dict):
            raise LinuxProviderError("ip-address", "invalid_output", "statistics are invalid")
        rx = stats.get("rx", {})
        tx = stats.get("tx", {})
        if not isinstance(rx, dict) or not isinstance(tx, dict):
            raise LinuxProviderError("ip-address", "invalid_output", "counter groups are invalid")
        linkinfo = entry.get("linkinfo", {})
        if not isinstance(linkinfo, dict):
            linkinfo = {}
        result.append(
            {
                "name": name,
                "index": _integer(entry.get("ifindex"), "ip-address", "ifindex"),
                "flags": flags,
                "administratively_up": "UP" in flags,
                "operational_state": (
                    entry.get("operstate") if isinstance(entry.get("operstate"), str) else None
                ),
                "mtu": _integer(entry.get("mtu"), "ip-address", "mtu"),
                "mac_address": (
                    str(entry["address"]).lower() if isinstance(entry.get("address"), str) else None
                ),
                "link_type": (
                    entry.get("link_type") if isinstance(entry.get("link_type"), str) else None
                ),
                "virtual_kind": (
                    linkinfo.get("info_kind")
                    if isinstance(linkinfo.get("info_kind"), str)
                    else None
                ),
                "addresses": addresses,
                "rx_bytes": _integer(rx.get("bytes"), "ip-address", "rx.bytes"),
                "rx_packets": _integer(rx.get("packets"), "ip-address", "rx.packets"),
                "rx_errors": _integer(rx.get("errors"), "ip-address", "rx.errors"),
                "rx_drops": _integer(rx.get("dropped"), "ip-address", "rx.dropped"),
                "tx_bytes": _integer(tx.get("bytes"), "ip-address", "tx.bytes"),
                "tx_packets": _integer(tx.get("packets"), "ip-address", "tx.packets"),
                "tx_errors": _integer(tx.get("errors"), "ip-address", "tx.errors"),
                "tx_drops": _integer(tx.get("dropped"), "ip-address", "tx.dropped"),
            }
        )
    return result


def parse_ip_route_json(raw: bytes) -> list[dict[str, object]]:
    document = _json(raw, "ip-route")
    if not isinstance(document, list):
        raise LinuxProviderError("ip-route", "invalid_output", "top-level value is not an array")
    result: list[dict[str, object]] = []
    for entry in document:
        if not isinstance(entry, dict):
            raise LinuxProviderError("ip-route", "invalid_output", "route entry is invalid")
        device = entry.get("dev")
        if not isinstance(device, str):
            continue
        validate_interface_name(device)
        destination = entry.get("dst", "default")
        gateway = entry.get("gateway")
        if not isinstance(destination, str) or (
            gateway is not None and not isinstance(gateway, str)
        ):
            raise LinuxProviderError("ip-route", "invalid_output", "route fields are invalid")
        result.append(
            {
                "interface": device,
                "destination": destination,
                "gateway": gateway,
                "metric": _integer(entry.get("metric"), "ip-route", "metric"),
                "protocol": (
                    entry.get("protocol") if isinstance(entry.get("protocol"), str) else None
                ),
            }
        )
    return result


def parse_iw_dev(raw: bytes) -> list[dict[str, object]]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise LinuxProviderError("iw-dev", "invalid_output", "iw output is not UTF-8") from error
    current_phy: str | None = None
    current: dict[str, object] | None = None
    result: list[dict[str, object]] = []
    for raw_line in lines:
        line = raw_line.strip()
        phy = re.fullmatch(r"phy#([0-9]+)", line)
        if phy:
            current_phy = f"phy{phy.group(1)}"
            current = None
            continue
        interface = re.fullmatch(r"Interface (.+)", line)
        if interface:
            name = validate_interface_name(interface.group(1))
            current = {"name": name, "wiphy": current_phy}
            result.append(current)
            continue
        if current is None:
            continue
        if line.startswith("ifindex ") and line[8:].isdigit():
            current["index"] = int(line[8:])
        elif line.startswith("addr ") and _MAC.fullmatch(line[5:].lower()):
            current["mac_address"] = line[5:].lower()
        elif line.startswith("type "):
            value = line[5:]
            if value in {"managed", "monitor", "AP", "P2P-client", "P2P-GO", "mesh point"}:
                current["type"] = value
        elif line.startswith("txpower "):
            match = re.match(r"txpower (-?[0-9]+(?:\.[0-9]+)?) dBm$", line)
            if match:
                current["tx_power_dbm"] = float(match.group(1))
    return result


def parse_iw_link(raw: bytes) -> dict[str, object]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise LinuxProviderError("iw-link", "invalid_output", "iw output is not UTF-8") from error
    meaningful = [line.strip() for line in lines if line.strip()]
    if not meaningful:
        raise LinuxProviderError("iw-link", "invalid_output", "empty_output")
    disconnected = [line for line in meaningful if line == "Not connected."]
    connected_lines = [line for line in meaningful if line.startswith("Connected to")]
    if disconnected:
        if len(disconnected) != 1 or connected_lines or len(meaningful) != 1:
            raise LinuxProviderError("iw-link", "invalid_output", "iw link output is contradictory")
        return {"connected": False}
    if len(connected_lines) != 1:
        raise LinuxProviderError(
            "iw-link", "invalid_output", "iw link omitted a valid connection state"
        )
    state_match = re.fullmatch(
        r"Connected to ([0-9a-fA-F:]{17})(?: \(on [^)]+\))?",
        connected_lines[0],
    )
    if state_match is None:
        raise LinuxProviderError(
            "iw-link", "invalid_output", "iw link connection state is truncated"
        )
    bssid = state_match.group(1).lower()
    if not _MAC.fullmatch(bssid):
        raise LinuxProviderError("iw-link", "invalid_output", "BSSID is invalid")
    result: dict[str, object] = {"connected": True, "bssid": bssid}
    phy_markers: set[str] = set()

    def assign(field: str, value: object) -> None:
        if field in result and result[field] != value:
            raise LinuxProviderError(
                "iw-link", "invalid_output", f"iw link field {field} is contradictory"
            )
        result[field] = value

    ignored_patterns = (
        r"(?:RX|TX): [0-9]+ bytes \([0-9]+ packets\)",
        r"inactive time: [0-9]+ ms",
        r"rx duration: [0-9]+ us",
        r"beacon signal avg: -?[0-9]+(?:\.[0-9]+)? dBm",
        r"beacon loss: [0-9]+",
        r"expected throughput: [0-9]+(?:\.[0-9]+)?(?: ?MBit/s|Mbps)",
        r"bss flags: .+",
        r"(?:dtim period|DTIM period): [0-9]+",
        r"(?:beacon int|beacon interval): ?[0-9]+",
        r"(?:authorized|authenticated|associated|short preamble|short slot time|"
        r"WMM/WME|MFP|TDLS peer): (?:yes|no)",
        r"preamble: (?:short|long)",
        r"connected time: [0-9]+ seconds",
    )
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line == connected_lines[0]:
            continue
        if line == "SSID:" or line.startswith("SSID: "):
            assign("ssid", line.removeprefix("SSID:").lstrip())
        elif re.fullmatch(r"freq: [0-9]+", line):
            assign("frequency_mhz", int(line[6:]))
        elif re.fullmatch(r"signal: -?[0-9]+(?:\.[0-9]+)? dBm", line):
            assign("signal_dbm", float(line.split()[1]))
        elif line.startswith("tx bitrate: ") or line.startswith("rx bitrate: "):
            direction = line[:2]
            match = re.search(r"([0-9]+(?:\.[0-9]+)?) MBit/s", line)
            if match is None:
                raise LinuxProviderError(
                    "iw-link", "invalid_output", "iw link bitrate is truncated"
                )
            assign(f"{direction}_bitrate_mbps", float(match.group(1)))
            upper = line.upper()
            for marker in ("EHT", "HE", "VHT", "MCS"):
                if marker in upper:
                    phy_markers.add(marker)
        elif not any(re.fullmatch(pattern, line) for pattern in ignored_patterns):
            raise LinuxProviderError(
                "iw-link", "invalid_output", "iw link contains an unknown field"
            )
    if phy_markers:
        result["phy_markers"] = sorted(phy_markers)
    return result


def parse_iw_info(raw: bytes) -> dict[str, object]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise LinuxProviderError("iw-info", "invalid_output", "iw output is not UTF-8") from error
    result: dict[str, object] = {}
    type_match = re.search(r"(?m)^\s*type (\S+(?: point)?)\s*$", text)
    if type_match:
        result["type"] = type_match.group(1)
    channel = re.search(
        r"(?m)^\s*channel ([0-9]+) \(([0-9]+) MHz\), "
        r"width: ([0-9]+(?:\+[0-9]+)?) MHz"
        r"(?:, center1: ([0-9]+) MHz)?"
        r"(?:, center2: ([0-9]+) MHz)?\s*$",
        text,
    )
    if channel:
        if "+" in channel.group(3):
            raise LinuxProviderError("iw-info", "unsupported", "80+80 MHz is not supported")
        result.update(
            {
                "channel": int(channel.group(1)),
                "frequency_mhz": int(channel.group(2)),
                "channel_width_mhz": int(channel.group(3)),
                "center_frequency_1_mhz": (
                    int(channel.group(4)) if channel.group(4) is not None else None
                ),
                "center_frequency_2_mhz": (
                    int(channel.group(5)) if channel.group(5) is not None else None
                ),
            }
        )
    return result


def parse_iw_phy_monitor_support(raw: bytes) -> bool:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise LinuxProviderError("iw-phy", "invalid_output", "iw output is not UTF-8") from error
    in_modes = False
    for raw_line in lines:
        line = raw_line.strip()
        if line == "Supported interface modes:":
            in_modes = True
            continue
        if in_modes and line.startswith("*"):
            if line[1:].strip() == "monitor":
                return True
            continue
        if in_modes and line and not raw_line.startswith((" ", "\t")):
            break
    return False


def parse_ethtool_driver(raw: bytes) -> dict[str, str]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise LinuxProviderError(
            "ethtool", "invalid_output", "ethtool output is not UTF-8"
        ) from error
    result: dict[str, str] = {}
    allowed = {"driver", "version", "firmware-version", "bus-info"}
    for line in lines:
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        if key in allowed and value:
            result[key.replace("-", "_")] = value[:256]
    if lines and not result:
        raise LinuxProviderError("ethtool", "invalid_output", "no recognized driver fields")
    return result


def parse_resolv_conf(raw: bytes) -> list[str]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise LinuxProviderError(
            "resolv-conf", "invalid_output", "resolver file is not UTF-8"
        ) from error
    servers: list[str] = []
    for line in lines:
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        parts = stripped.split()
        if parts[0] != "nameserver":
            continue
        if len(parts) != 2:
            raise LinuxProviderError(
                "resolv-conf", "invalid_output", "nameserver entry is malformed"
            )
        try:
            value = str(ip_address(parts[1]))
        except ValueError as error:
            raise LinuxProviderError(
                "resolv-conf", "invalid_output", "nameserver address is invalid"
            ) from error
        if value not in servers:
            servers.append(value)
    return servers


def infer_phy_standard(markers: object) -> str | None:
    values = set(markers) if isinstance(markers, list) else set()
    if "EHT" in values:
        return "802.11be"
    if "HE" in values:
        return "802.11ax"
    if "VHT" in values:
        return "802.11ac"
    if "MCS" in values:
        return "802.11n-or-newer"
    return None
