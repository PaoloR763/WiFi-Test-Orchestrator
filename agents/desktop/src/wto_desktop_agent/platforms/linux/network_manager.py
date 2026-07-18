from __future__ import annotations

import asyncio
import importlib
from dataclasses import dataclass, field
from typing import Any, Literal, cast

from wto_desktop_agent.platforms.linux.errors import LinuxProviderError

_SERVICE = "org.freedesktop.NetworkManager"
_ROOT = "/org/freedesktop/NetworkManager"
_MANAGER = "org.freedesktop.NetworkManager"
_DEVICE = "org.freedesktop.NetworkManager.Device"
_WIRELESS = "org.freedesktop.NetworkManager.Device.Wireless"
_ACCESS_POINT = "org.freedesktop.NetworkManager.AccessPoint"
_IP4_CONFIG = "org.freedesktop.NetworkManager.IP4Config"
_IP6_CONFIG = "org.freedesktop.NetworkManager.IP6Config"
_ACTIVE_CONNECTION = "org.freedesktop.NetworkManager.Connection.Active"

ActiveConnectionsStatus = Literal["complete", "partial", "unavailable"]


@dataclass(frozen=True)
class ActiveConnectionsResult:
    by_device: dict[str, list[str]]
    status: ActiveConnectionsStatus
    source_errors: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class NetworkManagerSnapshot:
    version: str | None
    state: int | None
    interfaces: list[dict[str, object]]
    active_connections_status: ActiveConnectionsStatus
    source_errors: dict[str, str] = field(default_factory=dict)


def _unwrap(value: Any) -> Any:
    if hasattr(value, "value"):
        return _unwrap(value.value)
    if isinstance(value, dict):
        return {str(key): _unwrap(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_unwrap(item) for item in value]
    return value


def _category(error: Exception) -> str:
    name = str(getattr(error, "type", ""))
    text = f"{name} {type(error).__name__} {error}".casefold()
    if "accessdenied" in text or "auth" in text or "permission" in text:
        return "permission_denied"
    if "serviceunknown" in text or "namehasnoowner" in text:
        return "unavailable"
    if "filenotfound" in text or "no such file" in text or "connection refused" in text:
        return "unavailable"
    if "noreply" in text or "disconnected" in text or "timeout" in text:
        return "transient_failure"
    return "transient_failure"


def _active_connection_error_category(error: Exception) -> str:
    name = str(getattr(error, "type", ""))
    text = f"{name} {type(error).__name__} {error}".casefold()
    if "unknownobject" in text or "unknownconnection" in text:
        return "transient_disappearance"
    if "noreply" in text or "timeout" in text:
        return "timeout"
    category = _category(error)
    if category in {"permission_denied", "unavailable"}:
        return category
    if "disconnected" in text:
        return "transient_failure"
    return "property_error"


def _ssid_bytes(value: object) -> bytes:
    """Validate NetworkManager's D-Bus ``ay`` value without text normalization."""

    if isinstance(value, bytes):
        result = value
    elif isinstance(value, bytearray):
        result = bytes(value)
    elif isinstance(value, memoryview):
        if value.ndim != 1 or value.itemsize != 1:
            raise ValueError("access point SSID byte view is invalid")
        result = value.tobytes()
    elif isinstance(value, list):
        if not all(type(item) is int and 0 <= item <= 255 for item in value):
            raise ValueError("access point SSID byte list is invalid")
        result = bytes(value)
    else:
        raise TypeError("access point SSID is not a D-Bus byte array")
    if len(result) > 32:
        raise ValueError("access point SSID exceeds the IEEE 802.11 limit")
    return result


class NetworkManagerDbusProvider:
    """Structured NetworkManager provider using the system D-Bus.

    Imports are lazy so Windows packaging and type checking never import a Linux
    session dependency. No command-line fallback is hidden in this provider.
    """

    def __init__(self, *, total_timeout_seconds: float | None = None) -> None:
        if total_timeout_seconds is not None and total_timeout_seconds <= 0:
            raise ValueError("NetworkManager timeout must be positive")
        self._total_timeout_seconds = total_timeout_seconds

    async def collect(self) -> NetworkManagerSnapshot:
        try:
            if self._total_timeout_seconds is None:
                return await self._collect()
            async with asyncio.timeout(self._total_timeout_seconds):
                return await self._collect()
        except TimeoutError as error:
            raise LinuxProviderError(
                "networkmanager-dbus",
                "transient_failure",
                "NetworkManager total query timed out",
            ) from error

    async def _collect(self) -> NetworkManagerSnapshot:
        bus: Any = None
        try:
            aio = importlib.import_module("dbus_next.aio")
            constants = importlib.import_module("dbus_next.constants")
            bus = aio.MessageBus(bus_type=constants.BusType.SYSTEM)
            bus = await bus.connect()
            root_object = await self._object(bus, _ROOT)
            manager = root_object.get_interface(_MANAGER)
            root_properties = await self._properties(root_object, _MANAGER)
            try:
                paths = await manager.call_get_all_devices()
            except AttributeError:
                paths = await manager.call_get_devices()
            active_paths = root_properties.get("ActiveConnections")
            if not isinstance(active_paths, list):
                active_connections = ActiveConnectionsResult(
                    {},
                    "unavailable",
                    {"active-connections:root-property": "property_error"},
                )
            else:
                active_connections = await self._active_connections(bus, active_paths)
            interfaces: list[dict[str, object]] = []
            errors = dict(active_connections.source_errors)
            version_value = root_properties.get("Version")
            state_value = root_properties.get("State")
            version = (
                version_value[:64] if isinstance(version_value, str) and version_value else None
            )
            state = state_value if type(state_value) is int else None
            if version is None:
                errors["root:Version"] = "invalid_output"
            if state is None:
                errors["root:State"] = "invalid_output"
            for path_value in paths:
                path = str(path_value)
                try:
                    interfaces.append(await self._device(bus, path, active_connections))
                except Exception as error:
                    errors[path] = _category(error)
            return NetworkManagerSnapshot(
                version=version,
                state=state,
                interfaces=interfaces,
                active_connections_status=active_connections.status,
                source_errors=errors,
            )
        except ModuleNotFoundError as error:
            raise LinuxProviderError(
                "networkmanager-dbus", "command_missing", "dbus-next is not installed"
            ) from error
        except Exception as error:
            category = _category(error)
            raise LinuxProviderError(
                "networkmanager-dbus",
                category,  # type: ignore[arg-type]
                "NetworkManager system D-Bus query failed",
            ) from error
        finally:
            if bus is not None:
                try:
                    bus.disconnect()
                except Exception:
                    bus = None

    async def _object(self, bus: Any, path: str) -> Any:
        introspection = await bus.introspect(_SERVICE, path)
        return bus.get_proxy_object(_SERVICE, path, introspection)

    async def _properties(self, proxy_object: Any, interface: str) -> dict[str, Any]:
        properties = proxy_object.get_interface("org.freedesktop.DBus.Properties")
        value = _unwrap(await properties.call_get_all(interface))
        if not isinstance(value, dict):
            raise LinuxProviderError(
                "networkmanager-dbus",
                "invalid_output",
                "D-Bus properties were not a mapping",
            )
        return cast(dict[str, Any], value)

    async def _active_connections(self, bus: Any, paths: list[object]) -> ActiveConnectionsResult:
        result: dict[str, list[str]] = {}
        errors: dict[str, str] = {}
        completed = 0
        for item in paths:
            path = str(item)
            try:
                if not path.startswith("/"):
                    raise ValueError("active connection path is invalid")
                proxy = await self._object(bus, path)
                properties = await self._properties(proxy, _ACTIVE_CONNECTION)
                name = str(properties.get("Id", ""))
                devices = properties.get("Devices")
                if not name or not isinstance(devices, list):
                    raise ValueError("active connection properties are incomplete")
                for device in devices:
                    device_path = str(device)
                    if not device_path.startswith("/"):
                        raise ValueError("active connection device path is invalid")
                    result.setdefault(device_path, []).append(name)
                completed += 1
            except Exception as error:  # one changing connection must not discard valid peers
                errors[f"active-connection:{path}"] = _active_connection_error_category(error)
                continue
        status: ActiveConnectionsStatus
        if not errors:
            status = "complete"
        elif completed:
            status = "partial"
        else:
            status = "unavailable"
        return ActiveConnectionsResult(result, status, errors)

    async def _device(
        self, bus: Any, path: str, active_connections: ActiveConnectionsResult
    ) -> dict[str, object]:
        proxy = await self._object(bus, path)
        values = await self._properties(proxy, _DEVICE)
        interface_value = values.get("Interface")
        if not isinstance(interface_value, str) or not interface_value:
            raise LinuxProviderError(
                "networkmanager-dbus", "invalid_output", "device omitted Interface"
            )
        interface = interface_value
        result: dict[str, object] = {
            "name": interface,
            "device_path": path,
            "active_connections": active_connections.by_device.get(path, []),
            "active_connections_status": active_connections.status,
        }
        for source_name, target in (
            ("DeviceType", "device_type"),
            ("State", "state"),
            ("Mtu", "mtu"),
        ):
            value = values.get(source_name)
            if type(value) is int:
                result[target] = value
        managed = values.get("Managed")
        if type(managed) is bool:
            result["managed"] = managed
        for source_name, target in (
            ("Driver", "driver"),
            ("DriverVersion", "driver_version"),
            ("FirmwareVersion", "firmware_version"),
        ):
            value = values.get(source_name)
            if isinstance(value, str) and value:
                result[target] = value
        mac_address = values.get("HwAddress")
        if isinstance(mac_address, str) and mac_address:
            result["mac_address"] = mac_address.lower()
        for key, interface_name in (
            ("Ip4Config", _IP4_CONFIG),
            ("Ip6Config", _IP6_CONFIG),
        ):
            config_path = values.get(key)
            if isinstance(config_path, str) and config_path != "/":
                await self._merge_ip_configuration(bus, config_path, interface_name, result)
        if result.get("device_type") == 2:
            await self._merge_wireless(bus, proxy, result)
        return result

    async def _merge_ip_configuration(
        self, bus: Any, path: str, interface: str, result: dict[str, object]
    ) -> None:
        proxy = await self._object(bus, path)
        values = await self._properties(proxy, interface)
        family = "ipv4" if interface == _IP4_CONFIG else "ipv6"
        raw_addresses = values.get("AddressData")
        if isinstance(raw_addresses, list) and all(
            isinstance(address, dict)
            and isinstance(address.get("address"), str)
            and type(address.get("prefix")) is int
            for address in raw_addresses
        ):
            addresses = result.setdefault("addresses", [])
            address_families = result.setdefault("addresses_config_families", [])
            assert isinstance(addresses, list)
            assert isinstance(address_families, list)
            address_families.append(family)
            addresses.extend(
                {
                    "family": family,
                    "address": address["address"],
                    "prefix_length": address["prefix"],
                }
                for address in raw_addresses
            )
        gateway = values.get("Gateway")
        if isinstance(gateway, str):
            gateways = result.setdefault("gateways", [])
            gateway_families = result.setdefault("gateways_config_families", [])
            assert isinstance(gateways, list)
            assert isinstance(gateway_families, list)
            gateway_families.append(family)
            if gateway:
                gateways.append(gateway)
        raw_nameservers = values.get("NameserverData")
        if isinstance(raw_nameservers, list) and all(
            isinstance(nameserver, dict) and isinstance(nameserver.get("address"), str)
            for nameserver in raw_nameservers
        ):
            dns_servers = result.setdefault("dns_servers", [])
            dns_families = result.setdefault("dns_servers_config_families", [])
            assert isinstance(dns_servers, list)
            assert isinstance(dns_families, list)
            dns_families.append(family)
            dns_servers.extend(nameserver["address"] for nameserver in raw_nameservers)

    async def _merge_wireless(self, bus: Any, proxy: Any, result: dict[str, object]) -> None:
        values = await self._properties(proxy, _WIRELESS)
        result["wifi"] = True
        bitrate = values.get("Bitrate")
        if type(bitrate) is int:
            result["bitrate_kbps"] = bitrate
        access_point_path = values.get("ActiveAccessPoint")
        if not isinstance(access_point_path, str):
            return
        if access_point_path == "/":
            result["associated"] = False
            return
        ap_proxy = await self._object(bus, access_point_path)
        ap = await self._properties(ap_proxy, _ACCESS_POINT)
        result["associated"] = True
        bssid = ap.get("HwAddress")
        if isinstance(bssid, str) and bssid:
            result["bssid"] = bssid.lower()
        for source_name, target in (
            ("Frequency", "frequency_mhz"),
            ("Strength", "signal_percent"),
            ("MaxBitrate", "max_bitrate_kbps"),
        ):
            value = ap.get(source_name)
            if type(value) is int:
                result[target] = value
        if "Ssid" in ap:
            try:
                result["ssid_bytes"] = _ssid_bytes(ap["Ssid"])
            except (TypeError, ValueError):
                # Association and radio properties remain useful when only the SSID
                # payload is malformed. Inventory reports this field independently.
                result["ssid_error"] = "invalid_output"
