from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from wto_desktop_agent.platforms.linux import network_manager as module
from wto_desktop_agent.platforms.linux.errors import LinuxProviderError
from wto_desktop_agent.platforms.linux.network_manager import NetworkManagerDbusProvider

ROOT = "/org/freedesktop/NetworkManager"
DEVICE = "/org/freedesktop/NetworkManager/Devices/1"
ACTIVE_GOOD = "/org/freedesktop/NetworkManager/ActiveConnection/1"
ACTIVE_GONE = "/org/freedesktop/NetworkManager/ActiveConnection/2"
ACCESS_POINT = "/org/freedesktop/NetworkManager/AccessPoint/1"
IP4_CONFIG = "/org/freedesktop/NetworkManager/IP4Config/1"
IP6_CONFIG = "/org/freedesktop/NetworkManager/IP6Config/1"


class _DbusError(RuntimeError):
    def __init__(self, error_type: str) -> None:
        super().__init__(error_type)
        self.type = error_type


class _Hang:
    def __init__(self) -> None:
        self.entered = asyncio.Event()

    async def wait(self) -> None:
        self.entered.set()
        await asyncio.Event().wait()


class _Properties:
    def __init__(self, bus: _Bus, path: str) -> None:
        self.bus = bus
        self.path = path

    async def call_get_all(self, interface: str) -> dict[str, object]:
        value = self.bus.properties[(self.path, interface)]
        if isinstance(value, BaseException):
            raise value
        if isinstance(value, _Hang):
            await value.wait()
            raise AssertionError("unreachable")
        return value


class _Manager:
    def __init__(self, devices: list[str]) -> None:
        self.devices = devices

    async def call_get_all_devices(self) -> list[str]:
        return self.devices


class _Proxy:
    def __init__(self, bus: _Bus, path: str) -> None:
        self.bus = bus
        self.path = path

    def get_interface(self, name: str) -> object:
        if name == "org.freedesktop.DBus.Properties":
            return _Properties(self.bus, self.path)
        if name == "org.freedesktop.NetworkManager" and self.path == ROOT:
            return _Manager(self.bus.devices)
        raise AssertionError(f"unexpected interface {name} for {self.path}")


class _Bus:
    def __init__(self, active_paths: list[str], active_values: dict[str, object]) -> None:
        self.devices = [DEVICE]
        self.disconnected = False
        self.properties: dict[tuple[str, str], Any] = {
            (
                ROOT,
                "org.freedesktop.NetworkManager",
            ): {
                "Version": "1.46.0",
                "State": 70,
                "ActiveConnections": active_paths,
            },
            (
                DEVICE,
                "org.freedesktop.NetworkManager.Device",
            ): {
                "Interface": "wlan0",
                "DeviceType": 1,
                "State": 100,
                "Managed": True,
                "Driver": "test",
                "Ip4Config": "/",
                "Ip6Config": "/",
            },
        }
        for path, value in active_values.items():
            self.properties[(path, "org.freedesktop.NetworkManager.Connection.Active")] = value

    async def connect(self) -> _Bus:
        return self

    async def introspect(self, service: str, path: str) -> object:
        del service
        if (
            path != ROOT
            and path not in self.devices
            and not path.startswith("/org/freedesktop/NetworkManager/ActiveConnection/")
            and not any(property_path == path for property_path, _ in self.properties)
        ):
            raise _DbusError("org.freedesktop.DBus.Error.UnknownObject")
        return object()

    def get_proxy_object(self, service: str, path: str, introspection: object) -> _Proxy:
        del service, introspection
        return _Proxy(self, path)

    def disconnect(self) -> None:
        self.disconnected = True


def _install_bus(monkeypatch: pytest.MonkeyPatch, bus: _Bus) -> None:
    aio = SimpleNamespace(MessageBus=lambda **kwargs: bus)
    constants = SimpleNamespace(BusType=SimpleNamespace(SYSTEM="system"))
    real_import = module.importlib.import_module

    def import_module(name: str) -> object:
        if name == "dbus_next.aio":
            return aio
        if name == "dbus_next.constants":
            return constants
        return real_import(name)

    monkeypatch.setattr(module.importlib, "import_module", import_module)


class _WirelessProvider(NetworkManagerDbusProvider):
    def __init__(
        self,
        ssid: object,
        *,
        include_active_access_point: bool = True,
        include_strength: bool = True,
    ) -> None:
        super().__init__()
        self.ssid = ssid
        self.include_active_access_point = include_active_access_point
        self.include_strength = include_strength

    async def _object(self, bus: Any, path: str) -> object:
        del bus
        assert path == ACCESS_POINT
        return object()

    async def _properties(self, proxy_object: Any, interface: str) -> dict[str, Any]:
        del proxy_object
        if interface == "org.freedesktop.NetworkManager.Device.Wireless":
            result: dict[str, Any] = {"Bitrate": 433_000}
            if self.include_active_access_point:
                result["ActiveAccessPoint"] = ACCESS_POINT
            return result
        if interface == "org.freedesktop.NetworkManager.AccessPoint":
            result = {
                "Ssid": self.ssid,
                "HwAddress": "AA:BB:CC:DD:EE:FF",
                "Frequency": 5935,
                "MaxBitrate": 1_200_000,
            }
            if self.include_strength:
                result["Strength"] = 81
            return result
        raise AssertionError(interface)


@pytest.mark.asyncio
async def test_valid_zero_active_connections_is_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus = _Bus([], {})
    _install_bus(monkeypatch, bus)

    snapshot = await NetworkManagerDbusProvider(total_timeout_seconds=0.2).collect()

    assert snapshot.active_connections_status == "complete"
    assert snapshot.interfaces[0]["active_connections"] == []
    assert snapshot.interfaces[0]["active_connections_status"] == "complete"
    assert "addresses" not in snapshot.interfaces[0]
    assert "gateways" not in snapshot.interfaces[0]
    assert "dns_servers" not in snapshot.interfaces[0]
    assert "addresses_config_families" not in snapshot.interfaces[0]
    assert "gateways_config_families" not in snapshot.interfaces[0]
    assert "dns_servers_config_families" not in snapshot.interfaces[0]
    assert snapshot.source_errors == {}
    assert bus.disconnected is True


@pytest.mark.asyncio
async def test_single_ip_configuration_is_explicitly_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus = _Bus([], {})
    device = bus.properties[(DEVICE, "org.freedesktop.NetworkManager.Device")]
    device["Ip4Config"] = IP4_CONFIG
    bus.properties[(IP4_CONFIG, "org.freedesktop.NetworkManager.IP4Config")] = {
        "AddressData": [{"address": "198.51.100.4", "prefix": 24}],
        "Gateway": "198.51.100.1",
        "NameserverData": [{"address": "192.0.2.53"}],
    }
    _install_bus(monkeypatch, bus)

    snapshot = await NetworkManagerDbusProvider(total_timeout_seconds=0.2).collect()

    interface = snapshot.interfaces[0]
    assert interface["addresses_config_families"] == ["ipv4"]
    assert interface["gateways_config_families"] == ["ipv4"]
    assert interface["dns_servers_config_families"] == ["ipv4"]
    assert interface["addresses"] == [
        {"family": "ipv4", "address": "198.51.100.4", "prefix_length": 24}
    ]
    assert interface["gateways"] == ["198.51.100.1"]
    assert interface["dns_servers"] == ["192.0.2.53"]


@pytest.mark.asyncio
async def test_ip_config_paths_without_valid_properties_are_not_authoritative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus = _Bus([], {})
    device = bus.properties[(DEVICE, "org.freedesktop.NetworkManager.Device")]
    device["Ip4Config"] = IP4_CONFIG
    device["Ip6Config"] = IP6_CONFIG
    bus.properties[(IP4_CONFIG, "org.freedesktop.NetworkManager.IP4Config")] = {
        "AddressData": "invalid",
        "Gateway": 0,
        "NameserverData": None,
    }
    bus.properties[(IP6_CONFIG, "org.freedesktop.NetworkManager.IP6Config")] = {}
    _install_bus(monkeypatch, bus)

    snapshot = await NetworkManagerDbusProvider(total_timeout_seconds=0.2).collect()

    interface = snapshot.interfaces[0]
    for key in (
        "addresses",
        "gateways",
        "dns_servers",
        "addresses_config_families",
        "gateways_config_families",
        "dns_servers_config_families",
    ):
        assert key not in interface


@pytest.mark.asyncio
async def test_omitted_active_connections_root_property_is_unavailable_not_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus = _Bus([], {})
    del bus.properties[(ROOT, "org.freedesktop.NetworkManager")]["ActiveConnections"]
    _install_bus(monkeypatch, bus)

    snapshot = await NetworkManagerDbusProvider(total_timeout_seconds=0.2).collect()

    assert snapshot.active_connections_status == "unavailable"
    assert snapshot.interfaces[0]["active_connections"] == []
    assert snapshot.interfaces[0]["active_connections_status"] == "unavailable"
    assert snapshot.source_errors["active-connections:root-property"] == "property_error"


@pytest.mark.asyncio
async def test_omitted_root_version_and_state_are_not_synthesized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus = _Bus([], {})
    root = bus.properties[(ROOT, "org.freedesktop.NetworkManager")]
    del root["Version"]
    del root["State"]
    _install_bus(monkeypatch, bus)

    snapshot = await NetworkManagerDbusProvider(total_timeout_seconds=0.2).collect()

    assert snapshot.version is None
    assert snapshot.state is None
    assert snapshot.source_errors["root:Version"] == "invalid_output"
    assert snapshot.source_errors["root:State"] == "invalid_output"


@pytest.mark.asyncio
async def test_omitted_device_properties_are_not_synthesized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus = _Bus([], {})
    device = bus.properties[(DEVICE, "org.freedesktop.NetworkManager.Device")]
    del device["State"]
    del device["Managed"]
    _install_bus(monkeypatch, bus)

    snapshot = await NetworkManagerDbusProvider(total_timeout_seconds=0.2).collect()

    interface = snapshot.interfaces[0]
    assert "state" not in interface
    assert "managed" not in interface


@pytest.mark.asyncio
async def test_one_disappearing_active_connection_is_unavailable_not_complete_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus = _Bus(
        [ACTIVE_GONE],
        {ACTIVE_GONE: _DbusError("org.freedesktop.DBus.Error.UnknownObject")},
    )
    _install_bus(monkeypatch, bus)

    snapshot = await NetworkManagerDbusProvider(total_timeout_seconds=0.2).collect()

    assert snapshot.active_connections_status == "unavailable"
    assert snapshot.interfaces[0]["active_connections"] == []
    assert snapshot.interfaces[0]["active_connections_status"] == "unavailable"
    assert snapshot.source_errors[f"active-connection:{ACTIVE_GONE}"] == ("transient_disappearance")


@pytest.mark.asyncio
async def test_known_active_connections_survive_one_disappearance_as_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus = _Bus(
        [ACTIVE_GOOD, ACTIVE_GONE],
        {
            ACTIVE_GOOD: {"Id": "WTO Lab", "Devices": [DEVICE]},
            ACTIVE_GONE: _DbusError("org.freedesktop.DBus.Error.UnknownObject"),
        },
    )
    _install_bus(monkeypatch, bus)

    snapshot = await NetworkManagerDbusProvider(total_timeout_seconds=0.2).collect()

    assert snapshot.active_connections_status == "partial"
    assert snapshot.interfaces[0]["active_connections"] == ["WTO Lab"]
    assert snapshot.interfaces[0]["active_connections_status"] == "partial"
    assert snapshot.source_errors[f"active-connection:{ACTIVE_GONE}"] == ("transient_disappearance")


@pytest.mark.asyncio
async def test_active_connection_property_failure_is_explicitly_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus = _Bus([ACTIVE_GONE], {ACTIVE_GONE: RuntimeError("controlled property failure")})
    _install_bus(monkeypatch, bus)

    snapshot = await NetworkManagerDbusProvider(total_timeout_seconds=0.2).collect()

    assert snapshot.active_connections_status == "unavailable"
    assert snapshot.source_errors[f"active-connection:{ACTIVE_GONE}"] == "property_error"


@pytest.mark.asyncio
async def test_active_connection_omitted_devices_property_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus = _Bus([ACTIVE_GOOD], {ACTIVE_GOOD: {"Id": "WTO Lab"}})
    _install_bus(monkeypatch, bus)

    snapshot = await NetworkManagerDbusProvider(total_timeout_seconds=0.2).collect()

    assert snapshot.active_connections_status == "unavailable"
    assert snapshot.interfaces[0]["active_connections"] == []
    assert snapshot.interfaces[0]["active_connections_status"] == "unavailable"
    assert snapshot.source_errors[f"active-connection:{ACTIVE_GOOD}"] == "property_error"


@pytest.mark.asyncio
async def test_active_connection_timeout_is_provider_unavailable_not_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hanging = _Hang()
    bus = _Bus([ACTIVE_GONE], {ACTIVE_GONE: hanging})
    _install_bus(monkeypatch, bus)
    provider = NetworkManagerDbusProvider(total_timeout_seconds=0.03)

    with pytest.raises(LinuxProviderError) as captured:
        await provider.collect()

    assert hanging.entered.is_set()
    assert captured.value.kind == "transient_failure"
    assert captured.value.detail == "NetworkManager total query timed out"
    assert bus.disconnected is True


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"WTO Lab", b"WTO Lab"),
        (bytearray(b"WTO Lab"), b"WTO Lab"),
        (memoryview(b"WTO Lab"), b"WTO Lab"),
        ([87, 84, 79, 0, 255], b"WTO\x00\xff"),
        (b"", b""),
    ],
)
def test_networkmanager_ssid_accepts_real_dbus_byte_array_forms(
    payload: object, expected: bytes
) -> None:
    assert module._ssid_bytes(payload) == expected


@pytest.mark.parametrize(
    "payload",
    [
        True,
        "WTO Lab",
        {"ssid": b"WTO Lab"},
        [87, "T", 79],
        [True],
        [-1],
        [256],
        b"x" * 33,
        memoryview(bytearray(4)).cast("H"),
    ],
)
def test_networkmanager_ssid_rejects_ambiguous_or_out_of_range_values(
    payload: object,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        module._ssid_bytes(payload)


@pytest.mark.asyncio
async def test_invalid_ssid_keeps_association_and_radio_properties() -> None:
    result: dict[str, object] = {}

    await _WirelessProvider("not-a-byte-array")._merge_wireless(None, object(), result)

    assert result == {
        "wifi": True,
        "bitrate_kbps": 433_000,
        "associated": True,
        "bssid": "aa:bb:cc:dd:ee:ff",
        "frequency_mhz": 5935,
        "signal_percent": 81,
        "max_bitrate_kbps": 1_200_000,
        "ssid_error": "invalid_output",
    }


@pytest.mark.asyncio
async def test_omitted_access_point_strength_is_not_synthesized_as_zero() -> None:
    result: dict[str, object] = {}

    await _WirelessProvider(b"WTO Lab", include_strength=False)._merge_wireless(
        None, object(), result
    )

    assert result["associated"] is True
    assert "signal_percent" not in result


@pytest.mark.asyncio
async def test_omitted_active_access_point_does_not_mean_disconnected() -> None:
    result: dict[str, object] = {}

    await _WirelessProvider(b"WTO Lab", include_active_access_point=False)._merge_wireless(
        None, object(), result
    )

    assert result["wifi"] is True
    assert result["bitrate_kbps"] == 433_000
    assert "associated" not in result


@pytest.mark.asyncio
async def test_non_utf8_and_nul_ssid_are_preserved_as_raw_bytes() -> None:
    result: dict[str, object] = {}

    await _WirelessProvider(b"lab\x00\xff")._merge_wireless(None, object(), result)

    assert result["ssid_bytes"] == b"lab\x00\xff"
    assert "ssid_error" not in result
