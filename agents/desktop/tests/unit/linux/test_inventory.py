from __future__ import annotations

import asyncio
import os
import shutil
import time
from collections.abc import Coroutine, Iterator
from contextvars import Context
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from wto_desktop_agent.platforms.linux.errors import LinuxProviderError
from wto_desktop_agent.platforms.linux.inventory import LinuxInventoryCollector
from wto_desktop_agent.platforms.linux.network_manager import NetworkManagerSnapshot
from wto_desktop_agent.ports.platform import CommandRequest, ProcessResult
from wto_desktop_agent.ports.plugins import CancellationToken

FIXTURES = Path(__file__).parents[2] / "fixtures" / "linux"


class FakeNetworkManager:
    def __init__(self, values: Iterator[NetworkManagerSnapshot | Exception]) -> None:
        self.values = values

    async def collect(self) -> NetworkManagerSnapshot:
        value = next(self.values)
        if isinstance(value, Exception):
            raise value
        return value


class FakeRunner:
    def __init__(self, values: dict[str, ProcessResult]) -> None:
        self.values = values
        self.calls: list[CommandRequest] = []

    async def run(self, request: CommandRequest, cancellation: CancellationToken) -> ProcessResult:
        del cancellation
        self.calls.append(request)
        return self.values[request.command_id]


class IwPoolRunner(FakeRunner):
    def __init__(
        self,
        *,
        delay_seconds: float = 0.0,
        blocked: bool = False,
        failures: frozenset[tuple[str, str]] = frozenset(),
        nonzero: frozenset[tuple[str, str]] = frozenset(),
    ) -> None:
        super().__init__({})
        self.delay_seconds = delay_seconds
        self.blocked = blocked
        self.failures = failures
        self.nonzero = nonzero
        self.release = asyncio.Event()
        self.started = asyncio.Event()
        self.active = 0
        self.max_active = 0

    async def run(self, request: CommandRequest, cancellation: CancellationToken) -> ProcessResult:
        del cancellation
        assert request.command_id in {"linux.iw.info", "linux.iw.link"}
        interface = str(request.arguments["interface"])
        key = (interface, request.command_id)
        self.calls.append(request)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.started.set()
        try:
            if self.blocked:
                await self.release.wait()
            await asyncio.sleep(self.delay_seconds)
            if key in self.failures:
                raise RuntimeError(f"controlled failure for {interface} {request.command_id}")
            if key in self.nonzero:
                return ProcessResult(1, b"", b"No such device")
            if request.command_id == "linux.iw.info":
                return ProcessResult(0, b"type managed\n", b"")
            return ProcessResult(0, b"Not connected.\n", b"")
        finally:
            self.active -= 1


class EttoolPoolRunner(FakeRunner):
    def __init__(
        self,
        *,
        delay_seconds: float = 0.0,
        blocked: bool = False,
        failures: frozenset[str] = frozenset(),
    ) -> None:
        super().__init__({})
        self.delay_seconds = delay_seconds
        self.blocked = blocked
        self.failures = failures
        self.release = asyncio.Event()
        self.started = asyncio.Event()
        self.active = 0
        self.max_active = 0
        self.completed: list[str] = []

    async def run(self, request: CommandRequest, cancellation: CancellationToken) -> ProcessResult:
        del cancellation
        assert request.command_id == "linux.ethtool.driver"
        interface = str(request.arguments["interface"])
        self.calls.append(request)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.started.set()
        try:
            if self.blocked:
                await self.release.wait()
            await asyncio.sleep(self.delay_seconds)
            if interface in self.failures:
                raise RuntimeError(f"controlled failure for {interface}")
            self.completed.append(interface)
            return ProcessResult(
                0,
                f"driver: {interface}\nversion: 1\n".encode(),
                b"",
            )
        finally:
            self.active -= 1


def _result(path: Path) -> ProcessResult:
    return ProcessResult(0, path.read_bytes(), b"")


def _nm(
    *,
    managed: bool = True,
    name: str = "wlan0",
    active_connections: list[str] | None = None,
    active_connections_status: str = "complete",
    source_errors: dict[str, str] | None = None,
) -> NetworkManagerSnapshot:
    connections = ["WTO Lab"] if active_connections is None else active_connections
    return NetworkManagerSnapshot(
        version="1.46.0",
        state=70,
        active_connections_status=active_connections_status,  # type: ignore[arg-type]
        source_errors=source_errors or {},
        interfaces=[
            {
                "name": name,
                "state": 100,
                "managed": managed,
                "driver": "iwlwifi",
                "mac_address": "02:00:00:00:00:02",
                "mtu": 1500,
                "active_connections": connections,
                "active_connections_status": active_connections_status,
                "addresses_config_families": ["ipv4", "ipv6"],
                "gateways_config_families": ["ipv4", "ipv6"],
                "dns_servers_config_families": ["ipv4", "ipv6"],
                "addresses": [{"family": "ipv4", "address": "198.51.100.4", "prefix_length": 24}],
                "gateways": ["198.51.100.1"],
                "dns_servers": ["192.0.2.53"],
                "wifi": True,
                "associated": True,
                "ssid_bytes": b"WTO Lab",
                "bssid": "aa:bb:cc:dd:ee:ff",
                "frequency_mhz": 5180,
                "signal_percent": 76,
                "bitrate_kbps": 650_000,
            }
        ],
    )


def _collector(
    tmp_path: Path,
    nm_values: list[NetworkManagerSnapshot | Exception],
    *,
    iw_link: bytes | None = None,
    commands: frozenset[str] | None = None,
    runner_override: FakeRunner | None = None,
) -> LinuxInventoryCollector:
    values = {
        "linux.ip.address-json": _result(FIXTURES / "ip" / "address.json"),
        "linux.ip.route-json": _result(FIXTURES / "ip" / "routes.json"),
        "linux.ip.route6-json": ProcessResult(0, b"[]", b""),
        "linux.iw.dev": _result(FIXTURES / "iw" / "dev.txt"),
        "linux.iw.link": ProcessResult(
            0,
            (iw_link if iw_link is not None else (FIXTURES / "iw" / "link.txt").read_bytes()),
            b"",
        ),
        "linux.iw.info": _result(FIXTURES / "iw" / "info.txt"),
        "linux.ethtool.driver": _result(FIXTURES / "ethtool" / "driver.txt"),
    }
    runner = runner_override or FakeRunner(values)
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 192.0.2.53\n", encoding="utf-8")
    sysfs = tmp_path / "sys"
    for name in ("eth0", "wlan0", "veth0", "wlan1"):
        (sysfs / name).mkdir(parents=True, exist_ok=True)
    (sysfs / "wlan0" / "device").mkdir(exist_ok=True)
    effective_commands = commands or frozenset(values)
    return LinuxInventoryCollector(
        FakeNetworkManager(iter(nm_values)),
        runner,
        commands=effective_commands,
        tools={"ip": True, "iw": True, "ethtool": True, "dumpcap": False},
        network_manager_installed=True,
        systemd_available=True,
        inventory_timeout_seconds=2,
        sysfs_root=sysfs,
        resolv_conf=resolv,
    )


def _sysfs_collector(
    tmp_path: Path,
    sysfs_root: Path,
    *,
    runner_override: FakeRunner | None = None,
) -> LinuxInventoryCollector:
    values = {
        "linux.ip.address-json": ProcessResult(0, b"[]", b""),
        "linux.ip.route-json": ProcessResult(0, b"[]", b""),
        "linux.ip.route6-json": ProcessResult(0, b"[]", b""),
        "linux.iw.dev": ProcessResult(0, b"", b""),
        "linux.ethtool.driver": ProcessResult(0, b"", b""),
    }
    resolv = tmp_path / "sysfs-resolv.conf"
    resolv.write_text("", encoding="utf-8")
    return LinuxInventoryCollector(
        FakeNetworkManager(
            iter([LinuxProviderError("networkmanager-dbus", "unavailable", "controlled")])
        ),
        runner_override or FakeRunner(values),
        commands=frozenset(values),
        tools={"ip": False, "iw": False, "ethtool": False},
        network_manager_installed=False,
        systemd_available=False,
        inventory_timeout_seconds=2,
        sysfs_root=sysfs_root,
        resolv_conf=resolv,
    )


def _ethtool_pool_collector(
    tmp_path: Path,
    runner: EttoolPoolRunner,
    *,
    timeout_seconds: float = 2,
) -> LinuxInventoryCollector:
    return LinuxInventoryCollector(
        FakeNetworkManager(iter([])),
        runner,
        commands=frozenset({"linux.ethtool.driver"}),
        tools={"ethtool": True},
        network_manager_installed=False,
        systemd_available=False,
        inventory_timeout_seconds=timeout_seconds,
        sysfs_root=tmp_path / "unused-sysfs",
        resolv_conf=tmp_path / "unused-resolv.conf",
    )


def _iw_pool_collector(
    tmp_path: Path,
    runner: IwPoolRunner,
    *,
    timeout_seconds: float = 2,
) -> LinuxInventoryCollector:
    return LinuxInventoryCollector(
        FakeNetworkManager(iter([])),
        runner,
        commands=frozenset({"linux.iw.info", "linux.iw.link"}),
        tools={"iw": True},
        network_manager_installed=False,
        systemd_available=False,
        inventory_timeout_seconds=timeout_seconds,
        sysfs_root=tmp_path / "unused-iw-sysfs",
        resolv_conf=tmp_path / "unused-iw-resolv.conf",
    )


def _live_iw_workers() -> list[asyncio.Task[object]]:
    return [
        task
        for task in asyncio.all_tasks()
        if task.get_name().startswith("linux-iw-detail-worker-") and not task.done()
    ]


def _live_ethtool_workers() -> list[asyncio.Task[object]]:
    return [
        task
        for task in asyncio.all_tasks()
        if task.get_name().startswith("linux-ethtool-worker-") and not task.done()
    ]


def _interface(snapshot: object, key: str) -> dict[str, object]:
    interfaces = snapshot.interfaces  # type: ignore[attr-defined]
    return next(item.fields for item in interfaces if item.interface_key == key)


@pytest.mark.asyncio
async def test_networkmanager_primary_merges_fallbacks_and_never_invents_missing_values(
    tmp_path: Path,
) -> None:
    snapshot = await _collector(tmp_path, [_nm()]).collect_inventory()
    wlan = _interface(snapshot, "wlan0")
    host = _interface(snapshot, "host:linux")

    assert wlan["wifi.ssid"].value["display"] == "WTO Lab"  # type: ignore[index,union-attr]
    assert wlan["wifi.rssi_measured"].value == -47.0  # type: ignore[attr-defined]
    assert wlan["wifi.rx_association_rate"].value == 780.0  # type: ignore[attr-defined]
    assert wlan["wifi.channel_width"].value == 80  # type: ignore[attr-defined]
    assert wlan["interface.physical"].value is True  # type: ignore[attr-defined]
    assert wlan["counter.sent_errors"].value == 0  # type: ignore[attr-defined]
    assert host["system.networkmanager.available"].value is True  # type: ignore[attr-defined]
    assert host["tool.dumpcap.installed"].value is False  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_absent_networkmanager_root_properties_are_unavailable_not_defaults(
    tmp_path: Path,
) -> None:
    nm = _nm()
    incomplete = NetworkManagerSnapshot(
        version=None,
        state=None,
        interfaces=nm.interfaces,
        active_connections_status=nm.active_connections_status,
        source_errors={
            "root:Version": "invalid_output",
            "root:State": "invalid_output",
        },
    )

    snapshot = await _collector(tmp_path, [incomplete]).collect_inventory()
    host = _interface(snapshot, "host:linux")

    assert host["system.networkmanager.version"].value is None  # type: ignore[attr-defined]
    assert host["system.networkmanager.version"].availability == "unavailable"  # type: ignore[attr-defined]
    assert host["system.networkmanager.state"].value is None  # type: ignore[attr-defined]
    assert host["system.networkmanager.state"].availability == "unavailable"  # type: ignore[attr-defined]
    assert snapshot.source_errors["networkmanager.root:Version"].code == "unknown"


@pytest.mark.asyncio
async def test_absent_networkmanager_association_does_not_override_iw_fallback(
    tmp_path: Path,
) -> None:
    nm = _nm()
    nm.interfaces[0].pop("associated")

    snapshot = await _collector(tmp_path, [nm]).collect_inventory()
    associated = _interface(snapshot, "wlan0")["wifi.associated"]

    assert associated.value is True  # type: ignore[attr-defined]
    assert associated.source.producer == "linux-iw"  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_empty_iw_link_keeps_independent_info_and_other_providers(
    tmp_path: Path,
) -> None:
    nm = _nm()
    nm.interfaces[0].pop("associated")
    collector = _collector(tmp_path, [nm], iw_link=b"")

    snapshot = await collector.collect_inventory()
    wlan = _interface(snapshot, "wlan0")

    associated = wlan["wifi.associated"]
    assert associated.value is None  # type: ignore[attr-defined]
    assert associated.availability == "unavailable"  # type: ignore[attr-defined]
    assert "empty_output" in associated.reason.detail  # type: ignore[attr-defined,union-attr]
    assert wlan["wifi.channel_width"].value == 80  # type: ignore[attr-defined]
    assert wlan["wifi.channel_width"].source.producer == "linux-iw"  # type: ignore[attr-defined]
    assert wlan["interface.mac_address"].value == "02:00:00:00:00:02"  # type: ignore[attr-defined]
    assert snapshot.source_errors["iw.link.wlan0"].detail.startswith("invalid_output")
    assert "iw.info.wlan0" not in snapshot.source_errors
    iw_commands = [
        call.command_id
        for call in collector.process_runner.calls  # type: ignore[attr-defined]
        if call.command_id in {"linux.iw.link", "linux.iw.info"}
    ]
    assert iw_commands == ["linux.iw.info", "linux.iw.link"]


@pytest.mark.asyncio
@pytest.mark.parametrize("diagnostic", [b"Not connected", b"No such device"])
async def test_nonzero_iw_link_is_transient_unavailable_not_disconnected(
    tmp_path: Path,
    diagnostic: bytes,
) -> None:
    nm = _nm()
    nm.interfaces[0].pop("associated")
    values = {
        "linux.ip.address-json": _result(FIXTURES / "ip" / "address.json"),
        "linux.ip.route-json": _result(FIXTURES / "ip" / "routes.json"),
        "linux.ip.route6-json": ProcessResult(0, b"[]", b""),
        "linux.iw.dev": _result(FIXTURES / "iw" / "dev.txt"),
        "linux.iw.link": ProcessResult(1, b"", diagnostic),
        "linux.iw.info": _result(FIXTURES / "iw" / "info.txt"),
        "linux.ethtool.driver": _result(FIXTURES / "ethtool" / "driver.txt"),
    }
    collector = _collector(
        tmp_path,
        [nm],
        runner_override=FakeRunner(values),
    )

    snapshot = await collector.collect_inventory()
    wlan = _interface(snapshot, "wlan0")

    associated = wlan["wifi.associated"]
    assert associated.value is None  # type: ignore[attr-defined]
    assert associated.availability == "unavailable"  # type: ignore[attr-defined]
    assert "transient_failure" in associated.reason.detail  # type: ignore[attr-defined,union-attr]
    assert wlan["wifi.channel"].value == 36  # type: ignore[attr-defined]
    assert wlan["wifi.interface_type"].value == "managed"  # type: ignore[attr-defined]
    assert "iw.link.wlan0" in snapshot.source_errors


@pytest.mark.asyncio
async def test_absent_networkmanager_ip_config_preserves_iproute_and_resolver_fallbacks(
    tmp_path: Path,
) -> None:
    nm = _nm()
    for key in (
        "addresses_config_families",
        "gateways_config_families",
        "dns_servers_config_families",
        "addresses",
        "gateways",
        "dns_servers",
    ):
        nm.interfaces[0].pop(key)
    collector = _collector(tmp_path, [nm])
    runner = collector.process_runner
    assert isinstance(runner, FakeRunner)
    runner.values["linux.ip.route-json"] = ProcessResult(
        0,
        b'[{"dst":"default","gateway":"198.51.100.1","dev":"wlan0"}]',
        b"",
    )

    snapshot = await collector.collect_inventory()
    wlan = _interface(snapshot, "wlan0")

    assert wlan["network.addresses"].source.producer == "linux-iproute2"  # type: ignore[attr-defined]
    assert wlan["network.gateways"].value == ["198.51.100.1"]  # type: ignore[attr-defined]
    assert wlan["network.gateways"].source.producer == "linux-iproute2"  # type: ignore[attr-defined]
    assert wlan["network.dns_servers"].value == ["192.0.2.53"]  # type: ignore[attr-defined]
    assert wlan["network.dns_servers"].source.producer == "linux-sysfs"  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_single_family_networkmanager_ip_config_does_not_replace_complete_fallback(
    tmp_path: Path,
) -> None:
    nm = _nm()
    interface = nm.interfaces[0]
    interface["addresses_config_families"] = ["ipv4"]
    interface["gateways_config_families"] = ["ipv4"]
    interface["dns_servers_config_families"] = ["ipv4"]
    interface["addresses"] = [{"family": "ipv4", "address": "203.0.113.9", "prefix_length": 24}]
    interface["gateways"] = []
    interface["dns_servers"] = []
    collector = _collector(tmp_path, [nm])
    runner = collector.process_runner
    assert isinstance(runner, FakeRunner)
    runner.values["linux.ip.route-json"] = ProcessResult(
        0,
        b'[{"dst":"default","gateway":"198.51.100.1","dev":"wlan0"}]',
        b"",
    )

    snapshot = await collector.collect_inventory()
    wlan = _interface(snapshot, "wlan0")

    addresses = wlan["network.addresses"]
    assert addresses.source.producer == "linux-iproute2"  # type: ignore[attr-defined]
    assert [entry["address"] for entry in addresses.value] == [  # type: ignore[attr-defined,union-attr]
        "198.51.100.4",
        "2001:db8::4",
    ]
    assert wlan["network.gateways"].value == ["198.51.100.1"]  # type: ignore[attr-defined]
    assert wlan["network.gateways"].source.producer == "linux-iproute2"  # type: ignore[attr-defined]
    assert wlan["network.dns_servers"].value == ["192.0.2.53"]  # type: ignore[attr-defined]
    assert wlan["network.dns_servers"].source.producer == "linux-sysfs"  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_complete_empty_active_connections_is_a_measured_empty_list(
    tmp_path: Path,
) -> None:
    snapshot = await _collector(
        tmp_path, [_nm(active_connections=[], active_connections_status="complete")]
    ).collect_inventory()

    connections = _interface(snapshot, "wlan0")["networkmanager.active_connections"]
    assert connections.value == []  # type: ignore[attr-defined]
    assert connections.availability == "measured"  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_partial_active_connections_preserve_known_values_without_measured_empty(
    tmp_path: Path,
) -> None:
    collector = _collector(
        tmp_path,
        [
            _nm(
                active_connections=["WTO Lab"],
                active_connections_status="partial",
                source_errors={"active-connection:/gone": "transient_disappearance"},
            )
        ],
    )
    snapshot = await collector.collect_inventory()

    connections = _interface(snapshot, "wlan0")["networkmanager.active_connections"]
    assert connections.value == ["WTO Lab"]  # type: ignore[attr-defined]
    assert connections.availability == "unknown"  # type: ignore[attr-defined]
    assert connections.confidence == "low"  # type: ignore[attr-defined]
    assert "networkmanager.active-connection:/gone" in snapshot.source_errors
    implementations = collector.capability_overrides()["wifi.connection.read"]["provider"][  # type: ignore[index]
        "implementations"
    ]
    assert [item["provider_id"] for item in implementations] == ["linux-iw"]


@pytest.mark.asyncio
async def test_unavailable_active_connections_are_null_not_measured_empty(
    tmp_path: Path,
) -> None:
    snapshot = await _collector(
        tmp_path,
        [
            _nm(
                active_connections=[],
                active_connections_status="unavailable",
                source_errors={"active-connection:/gone": "property_error"},
            )
        ],
    ).collect_inventory()

    connections = _interface(snapshot, "wlan0")["networkmanager.active_connections"]
    assert connections.value is None  # type: ignore[attr-defined]
    assert connections.availability == "unavailable"  # type: ignore[attr-defined]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind,expected_code",
    [
        ("unavailable", "provider_unavailable"),
        ("command_missing", "provider_unavailable"),
        ("permission_denied", "permission_denied"),
        ("transient_failure", "unknown"),
    ],
)
async def test_networkmanager_absent_inactive_dbus_missing_and_permission_denied_fall_back(
    tmp_path: Path, kind: str, expected_code: str
) -> None:
    error = LinuxProviderError("networkmanager-dbus", kind, "controlled")  # type: ignore[arg-type]
    snapshot = await _collector(tmp_path, [error]).collect_inventory()

    assert snapshot.source_errors["networkmanager"].code == expected_code
    assert _interface(snapshot, "wlan0")["wifi.bssid"].value == "aa:bb:cc:dd:ee:ff"  # type: ignore[attr-defined]
    host = _interface(snapshot, "host:linux")
    assert host["system.networkmanager.installed"].value is True  # type: ignore[attr-defined]
    assert host["system.networkmanager.available"].value is False  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_unmanaged_multiple_and_changed_active_wifi_interfaces_are_explicit(
    tmp_path: Path,
) -> None:
    collector = _collector(tmp_path, [_nm(managed=False), _nm(name="wlan1")])
    first = await collector.collect_inventory()
    second = await collector.collect_inventory()

    assert _interface(first, "wlan0")["networkmanager.managed"].value is False  # type: ignore[attr-defined]
    assert any(item.interface_key == "wlan1" for item in second.interfaces)
    assert len([item for item in first.interfaces if "wifi.adapter" in item.fields]) == 1


@pytest.mark.asyncio
async def test_disconnection_during_read_is_not_reported_as_zero(
    tmp_path: Path,
) -> None:
    snapshot = await _collector(tmp_path, [_nm()], iw_link=b"Not connected.\n").collect_inventory()
    wlan = _interface(snapshot, "wlan0")

    assert wlan["wifi.associated"].value is False  # type: ignore[attr-defined]
    assert wlan["wifi.rssi_measured"].value is None  # type: ignore[attr-defined]
    assert wlan["wifi.rssi_measured"].reason.detail == "interface_disconnected"  # type: ignore[attr-defined]
    for field_name in (
        "wifi.ssid",
        "wifi.bssid",
        "wifi.frequency",
        "wifi.channel",
        "wifi.channel_width",
        "wifi.signal_quality",
        "wifi.tx_association_rate",
        "wifi.rx_association_rate",
        "wifi.standard",
    ):
        assert wlan[field_name].value is None  # type: ignore[attr-defined]


@pytest.mark.asyncio
@pytest.mark.parametrize("resolver_state", ["missing", "oversized", "invalid"])
async def test_resolver_failures_are_unavailable_not_measured_empty(
    tmp_path: Path, resolver_state: str
) -> None:
    collector = _collector(
        tmp_path,
        [LinuxProviderError("networkmanager-dbus", "unavailable", "controlled")],
    )
    if resolver_state == "missing":
        collector.resolv_conf.unlink()
    elif resolver_state == "oversized":
        collector.resolv_conf.write_bytes(b"x" * 65_537)
    else:
        collector.resolv_conf.write_text("nameserver not-an-address\n", encoding="utf-8")

    snapshot = await collector.collect_inventory()
    dns = _interface(snapshot, "wlan0")["network.dns_servers"]

    assert dns.value is None  # type: ignore[attr-defined]
    assert dns.availability == "unavailable"  # type: ignore[attr-defined]
    assert "resolv_conf" in snapshot.source_errors


@pytest.mark.asyncio
async def test_valid_empty_resolver_is_measured_and_nm_dns_survives_resolver_failure(
    tmp_path: Path,
) -> None:
    unavailable = LinuxProviderError("networkmanager-dbus", "unavailable", "controlled")
    collector = _collector(tmp_path, [unavailable])
    collector.resolv_conf.write_text("search example.test\n", encoding="utf-8")
    empty_snapshot = await collector.collect_inventory()
    empty_dns = _interface(empty_snapshot, "wlan0")["network.dns_servers"]
    assert empty_dns.value == []  # type: ignore[attr-defined]
    assert empty_dns.availability == "measured"  # type: ignore[attr-defined]

    collector = _collector(tmp_path, [_nm()])
    collector.resolv_conf.unlink()
    nm_snapshot = await collector.collect_inventory()
    nm_dns = _interface(nm_snapshot, "wlan0")["network.dns_servers"]
    assert nm_dns.value == ["192.0.2.53"]  # type: ignore[attr-defined]
    assert nm_dns.source.producer == "linux-networkmanager"  # type: ignore[attr-defined]
    assert "resolv_conf" in nm_snapshot.source_errors


@pytest.mark.asyncio
async def test_permission_denied_resolver_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    collector = _collector(
        tmp_path,
        [LinuxProviderError("networkmanager-dbus", "unavailable", "controlled")],
    )
    real_read_bytes = Path.read_bytes

    def denied(path: Path) -> bytes:
        if path == collector.resolv_conf:
            raise PermissionError("controlled resolver denial")
        return real_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", denied)
    snapshot = await collector.collect_inventory()
    dns = _interface(snapshot, "wlan0")["network.dns_servers"]

    assert dns.value is None  # type: ignore[attr-defined]
    assert snapshot.source_errors["resolv_conf"].code == "permission_denied"


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_command", ["linux.ip.route-json", "linux.ip.route6-json"])
async def test_route_provider_failure_is_unavailable_by_family(
    tmp_path: Path, failed_command: str
) -> None:
    collector = _collector(
        tmp_path,
        [LinuxProviderError("networkmanager-dbus", "unavailable", "controlled")],
    )
    runner = collector.process_runner
    assert isinstance(runner, FakeRunner)
    runner.values[failed_command] = ProcessResult(1, b"", b"Operation not permitted")

    snapshot = await collector.collect_inventory()
    gateways = _interface(snapshot, "wlan0")["network.gateways"]

    assert gateways.value is None  # type: ignore[attr-defined]
    assert gateways.availability == "unavailable"  # type: ignore[attr-defined]
    error_key = "ip.route6" if failed_command.endswith("route6-json") else "ip.route"
    assert snapshot.source_errors[error_key].code == "permission_denied"


@pytest.mark.asyncio
async def test_successful_route_queries_without_gateway_are_measured_empty(
    tmp_path: Path,
) -> None:
    collector = _collector(
        tmp_path,
        [LinuxProviderError("networkmanager-dbus", "unavailable", "controlled")],
    )
    runner = collector.process_runner
    assert isinstance(runner, FakeRunner)
    runner.values["linux.ip.route-json"] = ProcessResult(0, b"[]", b"")
    runner.values["linux.ip.route6-json"] = ProcessResult(0, b"[]", b"")

    snapshot = await collector.collect_inventory()
    gateways = _interface(snapshot, "wlan0")["network.gateways"]

    assert gateways.value == []  # type: ignore[attr-defined]
    assert gateways.availability == "measured"  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_iw_unavailable_preserves_valid_networkmanager_association(
    tmp_path: Path,
) -> None:
    collector = _collector(tmp_path, [_nm()])
    collector.commands = collector.commands - {"linux.iw.link", "linux.iw.info"}

    snapshot = await collector.collect_inventory()
    wlan = _interface(snapshot, "wlan0")

    assert wlan["wifi.associated"].value is True  # type: ignore[attr-defined]
    assert wlan["wifi.ssid"].value["display"] == "WTO Lab"  # type: ignore[index,union-attr]
    assert "iw.wlan0" in snapshot.source_errors


@pytest.mark.asyncio
async def test_invalid_networkmanager_ssid_only_marks_that_field_unavailable(
    tmp_path: Path,
) -> None:
    nm = _nm()
    interface = nm.interfaces[0]
    interface.pop("ssid_bytes")
    interface["ssid_error"] = "invalid_output"
    interface["frequency_mhz"] = 5935
    collector = _collector(tmp_path, [nm])
    collector.commands = collector.commands - {"linux.iw.link", "linux.iw.info"}

    snapshot = await collector.collect_inventory()
    wlan = _interface(snapshot, "wlan0")

    assert wlan["wifi.ssid"].value is None  # type: ignore[attr-defined]
    assert wlan["wifi.ssid"].reason.detail.startswith("invalid_output")  # type: ignore[attr-defined,union-attr]
    assert wlan["wifi.associated"].value is True  # type: ignore[attr-defined]
    assert wlan["wifi.bssid"].value == "aa:bb:cc:dd:ee:ff"  # type: ignore[attr-defined]
    assert wlan["wifi.frequency"].value == 5935  # type: ignore[attr-defined]
    assert wlan["wifi.signal_quality"].value == 76  # type: ignore[attr-defined]
    assert wlan["wifi.tx_association_rate"].value == 650_000  # type: ignore[attr-defined]
    assert wlan["wifi.channel"].value == 2  # type: ignore[attr-defined]
    assert wlan["wifi.band"].value == "6GHz"  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_networkmanager_preserves_non_utf8_ssid_bytes_and_safe_display(
    tmp_path: Path,
) -> None:
    nm = _nm()
    nm.interfaces[0]["ssid_bytes"] = b"lab\x00\xff"
    collector = _collector(tmp_path, [nm])
    collector.commands = collector.commands - {"linux.iw.link", "linux.iw.info"}

    snapshot = await collector.collect_inventory()
    value = _interface(snapshot, "wlan0")["wifi.ssid"].value  # type: ignore[attr-defined]

    assert value == {"bytes_base64": "bGFiAP8=", "display": "lab\x00\ufffd"}


@pytest.mark.asyncio
async def test_missing_iw_ethtool_and_invalid_ip_output_fail_soft_per_source(
    tmp_path: Path,
) -> None:
    values = {
        "linux.ip.address-json": ProcessResult(0, b"not-json", b""),
        "linux.ip.route-json": ProcessResult(1, b"", b"Operation not permitted"),
        "linux.ip.route6-json": ProcessResult(0, b"[]", b""),
    }
    runner = FakeRunner(values)
    collector = _collector(
        tmp_path,
        [_nm()],
        commands=frozenset(values),
        runner_override=runner,
    )
    snapshot = await collector.collect_inventory()

    assert snapshot.source_errors["ip.address"].code == "unknown"
    assert snapshot.source_errors["ip.route"].code == "permission_denied"
    assert snapshot.source_errors["iw.dev"].detail.startswith("command_missing")
    assert "ethtool.wlan0" in snapshot.source_errors


@pytest.mark.asyncio
@pytest.mark.parametrize("interface_count", [0, 1, 7, 8, 17])
async def test_iw_detail_pool_has_fixed_concurrency_and_preserves_input_order(
    tmp_path: Path,
    interface_count: int,
) -> None:
    runner = IwPoolRunner(delay_seconds=0.001)
    collector = _iw_pool_collector(tmp_path, runner)
    interfaces = tuple(f"w{index:04d}" for index in reversed(range(interface_count)))

    results = await collector._bounded_iw_details(interfaces, time.monotonic() + 2)

    assert [name for name, _result in results] == list(interfaces)
    assert runner.max_active == min(interface_count, 8)
    assert len(runner.calls) == interface_count * 2
    observed: dict[str, list[str]] = {}
    for call in runner.calls:
        interface = str(call.arguments["interface"])
        observed.setdefault(interface, []).append(call.command_id)
    assert set(observed) == set(interfaces)
    assert all(commands == ["linux.iw.info", "linux.iw.link"] for commands in observed.values())
    assert runner.active == 0
    assert _live_iw_workers() == []


@pytest.mark.asyncio
async def test_iw_detail_pool_uses_eight_tasks_for_4096_interfaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = IwPoolRunner()
    collector = _iw_pool_collector(tmp_path, runner, timeout_seconds=30)
    created: list[asyncio.Task[object]] = []
    original_create_task = asyncio.create_task

    def tracking_create_task(
        coro: Coroutine[Any, Any, object],
        *,
        name: str | None = None,
        context: Context | None = None,
    ) -> asyncio.Task[object]:
        task = original_create_task(coro, name=name, context=context)
        created.append(task)
        return task

    monkeypatch.setattr(
        "wto_desktop_agent.platforms.linux.inventory.asyncio.create_task",
        tracking_create_task,
    )
    interfaces = tuple(f"w{index:04d}" for index in reversed(range(4096)))

    results = await collector._bounded_iw_details(interfaces, time.monotonic() + 30)

    assert [name for name, _result in results] == list(interfaces)
    assert len(runner.calls) == 8192
    assert runner.max_active <= 8
    assert len(created) == 8
    assert all(task.done() for task in created)
    assert runner.active == 0
    assert _live_iw_workers() == []


@pytest.mark.asyncio
async def test_collect_inventory_uses_eight_iw_tasks_for_4096_vifs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    iw_dev = b"".join(
        (
            f"phy#0\n\tInterface w{index:04d}\n" f"\t\tifindex {index + 1}\n\t\ttype managed\n"
        ).encode()
        for index in range(4096)
    )

    class InventoryRunner(IwPoolRunner):
        async def run(
            self, request: CommandRequest, cancellation: CancellationToken
        ) -> ProcessResult:
            if request.command_id in {"linux.iw.info", "linux.iw.link"}:
                return await super().run(request, cancellation)
            del cancellation
            self.calls.append(request)
            outputs = {
                "linux.ip.address-json": b"[]",
                "linux.ip.route-json": b"[]",
                "linux.ip.route6-json": b"[]",
                "linux.iw.dev": iw_dev,
            }
            return ProcessResult(0, outputs[request.command_id], b"")

    runner = InventoryRunner()
    sysfs = tmp_path / "empty-iw-sysfs"
    sysfs.mkdir()
    resolv = tmp_path / "empty-iw-resolv.conf"
    resolv.write_text("", encoding="utf-8")
    collector = LinuxInventoryCollector(
        FakeNetworkManager(
            iter(
                [
                    NetworkManagerSnapshot(
                        version="1.46.0",
                        state=70,
                        interfaces=[],
                        active_connections_status="complete",
                    )
                ]
            )
        ),
        runner,
        commands=frozenset(
            {
                "linux.ip.address-json",
                "linux.ip.route-json",
                "linux.ip.route6-json",
                "linux.iw.dev",
                "linux.iw.info",
                "linux.iw.link",
            }
        ),
        tools={"ip": True, "iw": True, "ethtool": False},
        network_manager_installed=True,
        systemd_available=True,
        inventory_timeout_seconds=30,
        sysfs_root=sysfs,
        resolv_conf=resolv,
    )

    async def no_ethtool(
        interfaces: tuple[str, ...], deadline: float
    ) -> list[tuple[str, dict[str, str] | BaseException]]:
        del interfaces, deadline
        return []

    def no_sysfs_fields(interface: str, now: datetime, deadline: float) -> dict[str, object]:
        del interface, now, deadline
        return {}

    monkeypatch.setattr(collector, "_bounded_ethtool", no_ethtool)
    monkeypatch.setattr(collector, "_sysfs_fields", no_sysfs_fields)
    created: list[asyncio.Task[object]] = []
    original_create_task = asyncio.create_task

    def tracking_create_task(
        coro: Coroutine[Any, Any, object],
        *,
        name: str | None = None,
        context: Context | None = None,
    ) -> asyncio.Task[object]:
        task = original_create_task(coro, name=name, context=context)
        created.append(task)
        return task

    monkeypatch.setattr(
        "wto_desktop_agent.platforms.linux.inventory.asyncio.create_task",
        tracking_create_task,
    )

    snapshot = await collector.collect_inventory()

    detail_calls = [
        call for call in runner.calls if call.command_id in {"linux.iw.info", "linux.iw.link"}
    ]
    assert len(detail_calls) == 8192
    assert runner.max_active <= 8
    assert len(created) == 8
    assert all(task.done() for task in created)
    assert sum("wifi.adapter" in item.fields for item in snapshot.interfaces) == 4096
    assert runner.active == 0
    assert _live_iw_workers() == []


@pytest.mark.asyncio
async def test_iw_detail_pool_global_deadline_stops_blocked_probes_and_new_work(
    tmp_path: Path,
) -> None:
    runner = IwPoolRunner(blocked=True)
    collector = _iw_pool_collector(tmp_path, runner, timeout_seconds=1)
    interfaces = tuple(f"w{index:04d}" for index in range(64))

    results = await collector._bounded_iw_details(interfaces, time.monotonic() + 0.05)

    assert len(results) == len(interfaces)
    assert 0 < len(runner.calls) <= 8
    assert {call.command_id for call in runner.calls} == {"linux.iw.info"}
    for _name, result in results:
        assert not isinstance(result, BaseException)
        link, info = result
        assert isinstance(link, LinuxProviderError)
        assert isinstance(info, LinuxProviderError)
        assert link.detail == "inventory total timeout expired"
        assert info.detail == "inventory total timeout expired"
    assert runner.active == 0
    assert _live_iw_workers() == []


@pytest.mark.asyncio
async def test_iw_detail_pool_cancellation_drains_workers(tmp_path: Path) -> None:
    runner = IwPoolRunner(blocked=True)
    collector = _iw_pool_collector(tmp_path, runner, timeout_seconds=10)
    operation = asyncio.create_task(
        collector._bounded_iw_details(
            tuple(f"w{index:04d}" for index in range(64)),
            time.monotonic() + 10,
        )
    )
    await asyncio.wait_for(runner.started.wait(), timeout=1)

    operation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await operation

    assert runner.active == 0
    assert _live_iw_workers() == []


@pytest.mark.asyncio
async def test_iw_detail_pool_isolates_failures_and_disappearing_interfaces(
    tmp_path: Path,
) -> None:
    runner = IwPoolRunner(
        failures=frozenset({("w0002", "linux.iw.info")}),
        nonzero=frozenset(
            {
                ("w0003", "linux.iw.info"),
                ("w0003", "linux.iw.link"),
            }
        ),
    )
    collector = _iw_pool_collector(tmp_path, runner)
    interfaces = ("w0003", "w0001", "w0002")

    results = await collector._bounded_iw_details(interfaces, time.monotonic() + 2)

    assert [name for name, _result in results] == list(interfaces)
    by_name = dict(results)
    disappeared = by_name["w0003"]
    assert not isinstance(disappeared, BaseException)
    assert all(isinstance(result, LinuxProviderError) for result in disappeared)
    failed = by_name["w0002"]
    assert not isinstance(failed, BaseException)
    failed_link, failed_info = failed
    assert isinstance(failed_link, dict)
    assert isinstance(failed_info, RuntimeError)
    healthy = by_name["w0001"]
    assert not isinstance(healthy, BaseException)
    assert all(isinstance(result, dict) for result in healthy)
    observed: dict[str, list[str]] = {}
    for call in runner.calls:
        interface = str(call.arguments["interface"])
        observed.setdefault(interface, []).append(call.command_id)
    assert observed == {
        "w0003": ["linux.iw.info", "linux.iw.link"],
        "w0001": ["linux.iw.info", "linux.iw.link"],
        "w0002": ["linux.iw.info", "linux.iw.link"],
    }
    assert runner.active == 0
    assert _live_iw_workers() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("interface_count", [0, 1, 7, 8, 17])
async def test_ethtool_pool_has_fixed_concurrency_and_deterministic_order(
    tmp_path: Path,
    interface_count: int,
) -> None:
    runner = EttoolPoolRunner(delay_seconds=0.001)
    collector = _ethtool_pool_collector(tmp_path, runner)
    interfaces = tuple(f"eth{index:04d}" for index in reversed(range(interface_count)))

    results = await collector._bounded_ethtool(interfaces, time.monotonic() + 2)

    assert [name for name, _result in results] == sorted(interfaces)
    assert runner.max_active == min(interface_count, 8)
    assert len(runner.calls) == interface_count
    assert runner.active == 0
    assert _live_ethtool_workers() == []
    assert all(result["driver"] == name for name, result in results if isinstance(result, dict))


@pytest.mark.asyncio
async def test_ethtool_pool_uses_eight_tasks_for_4096_interfaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = EttoolPoolRunner()
    collector = _ethtool_pool_collector(tmp_path, runner, timeout_seconds=10)
    created: list[asyncio.Task[object]] = []
    original_create_task = asyncio.create_task

    def tracking_create_task(
        coro: Coroutine[Any, Any, object],
        *,
        name: str | None = None,
        context: Context | None = None,
    ) -> asyncio.Task[object]:
        task = original_create_task(coro, name=name, context=context)
        created.append(task)
        return task

    monkeypatch.setattr(
        "wto_desktop_agent.platforms.linux.inventory.asyncio.create_task",
        tracking_create_task,
    )
    interfaces = tuple(f"eth{index:04d}" for index in reversed(range(4096)))

    results = await collector._bounded_ethtool(interfaces, time.monotonic() + 10)

    assert len(results) == 4096
    assert len(runner.calls) == 4096
    assert runner.max_active <= 8
    assert len(created) == 8
    assert all(task.done() for task in created)
    assert _live_ethtool_workers() == []


@pytest.mark.asyncio
async def test_ethtool_pool_global_deadline_stops_blocked_probes_and_new_work(
    tmp_path: Path,
) -> None:
    runner = EttoolPoolRunner(blocked=True)
    collector = _ethtool_pool_collector(tmp_path, runner, timeout_seconds=1)
    interfaces = tuple(f"eth{index:04d}" for index in range(64))

    results = await collector._bounded_ethtool(interfaces, time.monotonic() + 0.05)

    assert len(results) == len(interfaces)
    assert 0 < len(runner.calls) <= 8
    assert all(
        isinstance(result, LinuxProviderError)
        and result.detail == "inventory total timeout expired"
        for _name, result in results
    )
    assert runner.active == 0
    assert _live_ethtool_workers() == []


@pytest.mark.asyncio
async def test_ethtool_pool_cancellation_drains_workers(
    tmp_path: Path,
) -> None:
    runner = EttoolPoolRunner(blocked=True)
    collector = _ethtool_pool_collector(tmp_path, runner, timeout_seconds=10)
    operation = asyncio.create_task(
        collector._bounded_ethtool(
            tuple(f"eth{index:04d}" for index in range(64)),
            time.monotonic() + 10,
        )
    )
    await runner.started.wait()

    operation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await operation

    assert runner.active == 0
    assert _live_ethtool_workers() == []


@pytest.mark.asyncio
async def test_ethtool_pool_isolates_probe_failure_and_preserves_order(
    tmp_path: Path,
) -> None:
    runner = EttoolPoolRunner(failures=frozenset({"eth0002"}))
    collector = _ethtool_pool_collector(tmp_path, runner)

    results = await collector._bounded_ethtool(
        ("eth0003", "eth0001", "eth0002"),
        time.monotonic() + 2,
    )

    assert [name for name, _result in results] == ["eth0001", "eth0002", "eth0003"]
    assert isinstance(results[1][1], RuntimeError)
    assert set(runner.completed) == {"eth0001", "eth0003"}
    assert len(runner.calls) == 3
    assert runner.active == 0
    assert _live_ethtool_workers() == []


@pytest.mark.asyncio
async def test_sysfs_seeds_interfaces_when_all_external_providers_are_empty(
    tmp_path: Path,
) -> None:
    sysfs = tmp_path / "sysfs-only"
    for name in ("eth0", "lo", "wlan9", "bad interface"):
        (sysfs / name).mkdir(parents=True, exist_ok=True)

    snapshot = await _sysfs_collector(tmp_path, sysfs).collect_inventory()

    assert [item.interface_key for item in snapshot.interfaces] == [
        "eth0",
        "lo",
        "wlan9",
        "host:linux",
    ]
    wlan = _interface(snapshot, "wlan9")
    assert wlan["interface.name"].source.producer == "linux-sysfs"  # type: ignore[attr-defined]
    assert wlan["interface.physical"].value is False  # type: ignore[attr-defined]
    assert "wifi.associated" not in wlan


@pytest.mark.asyncio
async def test_empty_sysfs_is_measured_empty_and_external_fallback_survives_unavailable_root(
    tmp_path: Path,
) -> None:
    empty = tmp_path / "empty-sysfs"
    empty.mkdir()
    empty_snapshot = await _sysfs_collector(tmp_path, empty).collect_inventory()
    assert [item.interface_key for item in empty_snapshot.interfaces] == ["host:linux"]
    assert "sysfs.interfaces" not in empty_snapshot.source_errors

    collector = _collector(tmp_path, [_nm()])
    collector.sysfs_root = tmp_path / "missing-sysfs"
    fallback_snapshot = await collector.collect_inventory()
    assert any(item.interface_key == "wlan0" for item in fallback_snapshot.interfaces)
    assert "sysfs.interfaces" in fallback_snapshot.source_errors


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="sysfs symlink semantics require POSIX")
async def test_sysfs_accepts_anchored_symlink_and_rejects_escape_and_dangling(
    tmp_path: Path,
) -> None:
    anchor = tmp_path / "sysroot"
    class_net = anchor / "class" / "net"
    valid_target = anchor / "devices" / "virtual" / "net" / "lo"
    escaped_target = tmp_path / "outside" / "wlan0"
    valid_target.mkdir(parents=True)
    escaped_target.mkdir(parents=True)
    class_net.mkdir(parents=True)
    (class_net / "lo").symlink_to(valid_target, target_is_directory=True)
    (class_net / "wlan0").symlink_to(escaped_target, target_is_directory=True)
    (class_net / "eth9").symlink_to(anchor / "missing", target_is_directory=True)

    snapshot = await _sysfs_collector(tmp_path, class_net).collect_inventory()

    assert [item.interface_key for item in snapshot.interfaces] == ["lo", "host:linux"]


@pytest.mark.asyncio
async def test_sysfs_interface_disappearance_does_not_abort_inventory(tmp_path: Path) -> None:
    sysfs = tmp_path / "disappearing-sysfs"
    disappearing = sysfs / "wlan9"
    disappearing.mkdir(parents=True)
    values = {
        "linux.ip.address-json": ProcessResult(0, b"[]", b""),
        "linux.ip.route-json": ProcessResult(0, b"[]", b""),
        "linux.ip.route6-json": ProcessResult(0, b"[]", b""),
        "linux.iw.dev": ProcessResult(0, b"", b""),
        "linux.ethtool.driver": ProcessResult(0, b"", b""),
    }

    class DisappearingRunner(FakeRunner):
        removed = False

        async def run(
            self, request: CommandRequest, cancellation: CancellationToken
        ) -> ProcessResult:
            if not self.removed:
                shutil.rmtree(disappearing)
                self.removed = True
            return await super().run(request, cancellation)

    snapshot = await _sysfs_collector(
        tmp_path,
        sysfs,
        runner_override=DisappearingRunner(values),
    ).collect_inventory()

    assert any(item.interface_key == "wlan9" for item in snapshot.interfaces)
    assert "sysfs.wlan9" in snapshot.source_errors
    assert "interface.physical" not in _interface(snapshot, "wlan9")


def test_sysfs_discovery_enforces_entry_limit_and_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sysfs = tmp_path / "limited-sysfs"
    (sysfs / "eth0").mkdir(parents=True)
    (sysfs / "eth1").mkdir()
    collector = _sysfs_collector(tmp_path, sysfs)
    monkeypatch.setattr("wto_desktop_agent.platforms.linux.inventory._MAX_SYSFS_INTERFACES", 1)

    with pytest.raises(LinuxProviderError) as limited:
        collector._discover_sysfs_interfaces(time.monotonic() + 1)
    assert limited.value.detail == "sysfs interface limit exceeded"
    monkeypatch.setattr("wto_desktop_agent.platforms.linux.inventory._MAX_SYSFS_INTERFACES", 4096)
    with pytest.raises(LinuxProviderError) as expired:
        collector._discover_sysfs_interfaces(time.monotonic() - 1)
    assert expired.value.detail == "sysfs discovery timed out"


def test_sysfs_discovery_stops_consuming_at_the_entry_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sysfs = tmp_path / "bounded-sysfs"
    sysfs.mkdir()
    collector = _sysfs_collector(tmp_path, sysfs)
    consumed = 0

    class BoundedScan:
        def __enter__(self) -> BoundedScan:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def __iter__(self) -> Iterator[object]:
            nonlocal consumed
            for name in ("eth0", "eth1", "eth2"):
                consumed += 1
                if consumed > 2:
                    raise AssertionError("scandir consumed beyond the configured limit")
                yield type("Entry", (), {"name": name})()

    monkeypatch.setattr(
        "wto_desktop_agent.platforms.linux.inventory.os.scandir",
        lambda _root: BoundedScan(),
    )
    monkeypatch.setattr("wto_desktop_agent.platforms.linux.inventory._MAX_SYSFS_INTERFACES", 1)

    with pytest.raises(LinuxProviderError) as limited:
        collector._discover_sysfs_interfaces(time.monotonic() + 1)

    assert limited.value.detail == "sysfs interface limit exceeded"
    assert consumed == 2


def test_sysfs_enrichment_checks_the_global_deadline_before_reading(
    tmp_path: Path,
) -> None:
    sysfs = tmp_path / "deadline-sysfs"
    (sysfs / "eth0").mkdir(parents=True)
    collector = _sysfs_collector(tmp_path, sysfs)

    with pytest.raises(LinuxProviderError) as expired:
        collector._sysfs_fields("eth0", datetime.now(UTC), time.monotonic() - 1)

    assert expired.value.detail == "inventory total timeout expired"
