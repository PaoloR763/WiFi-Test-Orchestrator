from __future__ import annotations

import asyncio
import base64
import time
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

from wto_desktop_agent.domain.telemetry import (
    InterfaceSnapshot,
    InventorySnapshot,
    NormalizedObservation,
    ObservationReason,
    ObservationSource,
    WifiScanEntry,
    WifiScanSnapshot,
)
from wto_desktop_agent.platforms.windows.frequency import frequency_to_channel
from wto_desktop_agent.platforms.windows.native_wifi.errors import NativeWifiError
from wto_desktop_agent.platforms.windows.netsh import parse_netsh_interfaces
from wto_desktop_agent.platforms.windows.phy import phy_type_to_standard
from wto_desktop_agent.platforms.windows.powershell import parse_powershell_inventory
from wto_desktop_agent.ports.platform import CommandRequest, ProcessRunner
from wto_desktop_agent.ports.plugins import CancellationToken

NATIVE_SOURCE = ObservationSource(
    plane="telemetry", producer="windows-native-wifi", method="wlanapi", version="1.0.0"
)
IP_HELPER_SOURCE = ObservationSource(
    plane="telemetry", producer="windows-ip-helper", method="GetIfTable2", version="1.0.0"
)
POWERSHELL_SOURCE = ObservationSource(
    plane="telemetry", producer="windows-powershell", method="net-cmdlets-json", version="1.0.0"
)
NETSH_SOURCE = ObservationSource(
    plane="telemetry", producer="windows-netsh", method="localized-read-fallback", version="1.0.0"
)
DERIVED_SOURCE = ObservationSource(
    plane="telemetry",
    producer="wto-desktop-agent",
    method="frequency-channel-mapping",
    version="1.0.0",
)
PHY_DERIVED_SOURCE = ObservationSource(
    plane="telemetry",
    producer="wto-desktop-agent",
    method="dot11-phy-enum-mapping",
    version="1.0.0",
)


def _reason(error: Exception, default: str = "unknown") -> ObservationReason:
    if isinstance(error, NativeWifiError):
        code = {
            "access_denied": "permission_denied",
            "service_stopped": "provider_unavailable",
            "invalid_state": "blocked",
            "timeout": "blocked",
            "unsupported": "not_exposed_by_platform",
        }.get(error.category, default)
        return ObservationReason(code=code, detail=f"{error.operation} Win32={error.code}")  # type: ignore[arg-type]
    return ObservationReason(code=default, detail=type(error).__name__)  # type: ignore[arg-type]


def _observed(
    value: Any,
    unit: str,
    source: ObservationSource,
    collected_at: datetime,
    *,
    confidence: str = "high",
) -> NormalizedObservation:
    return NormalizedObservation.measured(
        value,
        unit,
        source,
        collected_at,
        confidence=confidence,  # type: ignore[arg-type]
    )


def _missing(
    unit: str,
    source: ObservationSource,
    collected_at: datetime,
    code: str = "not_exposed_by_platform",
    detail: str | None = None,
) -> NormalizedObservation:
    return NormalizedObservation.missing(
        unit,
        source,
        collected_at,
        ObservationReason(code=code, detail=detail),  # type: ignore[arg-type]
    )


class WindowsInventoryCollector:
    def __init__(
        self,
        native_wifi: Any,
        ip_helper: Any,
        process_runner: ProcessRunner,
        *,
        inventory_timeout_seconds: float = 30.0,
        scan_cooldown_seconds: float = 60.0,
        scan_timeout_seconds: float = 8.0,
    ) -> None:
        self.native_wifi = native_wifi
        self.ip_helper = ip_helper
        self.process_runner = process_runner
        self.inventory_timeout_seconds = inventory_timeout_seconds
        self.scan_cooldown_seconds = scan_cooldown_seconds
        self.scan_timeout_seconds = scan_timeout_seconds
        self._scan_locks: dict[str, asyncio.Lock] = {}
        self._last_scan: dict[str, float] = {}
        self._privacy_denied = False
        self._native_available = False
        self._native_probe_error: str | None = None

    def invalidate_runtime_state(self) -> None:
        self._last_scan.clear()
        self._privacy_denied = False
        self._native_probe_error = None

    async def collect_inventory(self) -> InventorySnapshot:
        started = datetime.now(UTC)
        source_errors: dict[str, ObservationReason] = {}
        native_interfaces: list[dict[str, object]] = []
        native_connections: dict[str, dict[str, object] | Exception] = {}
        ip_interfaces: list[dict[str, object]] = []
        ps_adapters: list[dict[str, object]] = []
        netsh_interfaces: list[dict[str, object]] = []

        try:
            native_interfaces = await asyncio.to_thread(self.native_wifi.interfaces)
            self._native_available = True
            for interface in native_interfaces:
                guid = str(interface["guid"])
                try:
                    native_connections[guid] = await asyncio.to_thread(
                        self.native_wifi.connection, guid
                    )
                except Exception as error:
                    native_connections[guid] = error
                    if isinstance(error, NativeWifiError) and error.category == "access_denied":
                        self._privacy_denied = True
        except Exception as error:
            source_errors["native_wifi"] = _reason(error)
            if isinstance(error, NativeWifiError) and error.category == "access_denied":
                self._privacy_denied = True
        try:
            ip_interfaces = await asyncio.to_thread(self.ip_helper.interfaces)
        except Exception as error:
            source_errors["ip_helper"] = _reason(error)
        try:
            ps_result = await self.process_runner.run(
                CommandRequest(
                    command_id="windows.powershell.network_inventory",
                    arguments={},
                    timeout_seconds=self.inventory_timeout_seconds,
                ),
                CancellationToken(),
            )
            if ps_result.return_code != 0:
                raise RuntimeError("PowerShell inventory returned a nonzero status")
            ps_adapters = [
                adapter.model_dump(mode="json")
                for adapter in parse_powershell_inventory(ps_result.stdout).adapters
            ]
        except Exception as error:
            source_errors["powershell"] = _reason(error)

        if not self._privacy_denied:
            try:
                netsh_result = await self.process_runner.run(
                    CommandRequest(
                        command_id="windows.netsh.wlan_show_interfaces",
                        arguments={},
                        timeout_seconds=10.0,
                    ),
                    CancellationToken(),
                )
                if netsh_result.return_code == 0:
                    netsh_interfaces = [
                        item.__dict__ for item in parse_netsh_interfaces(netsh_result.stdout)
                    ]
            except Exception as error:
                source_errors["netsh"] = _reason(error)

        merged: dict[str, dict[str, NormalizedObservation]] = {}
        now = datetime.now(UTC)

        for adapter in ps_adapters:
            key = _adapter_key(adapter.get("interface_guid"), adapter.get("interface_index"))
            fields = merged.setdefault(key, {})
            _set_if_value(
                fields, "interface.guid", adapter.get("interface_guid"), "1", POWERSHELL_SOURCE, now
            )
            _set_if_value(
                fields,
                "interface.index",
                adapter.get("interface_index"),
                "1",
                POWERSHELL_SOURCE,
                now,
            )
            for name, unit in (
                ("name", "1"),
                ("description", "1"),
                ("status", "1"),
                ("virtual", "1"),
                ("hardware_interface", "1"),
                ("manufacturer", "1"),
                ("model", "1"),
                ("driver_description", "1"),
                ("driver_provider", "1"),
                ("driver_version", "1"),
                ("mac_address", "1"),
                ("link_speed", "1"),
            ):
                _set_if_value(
                    fields, f"interface.{name}", adapter.get(name), unit, POWERSHELL_SOURCE, now
                )
            for name in (
                "received_bytes",
                "sent_bytes",
                "received_packets",
                "sent_packets",
                "received_errors",
                "sent_errors",
                "received_discards",
                "sent_discards",
            ):
                unit = "By" if name.endswith("bytes") else "1"
                if adapter.get("statistics_available"):
                    _set_if_value(
                        fields, f"counter.{name}", adapter.get(name), unit, POWERSHELL_SOURCE, now
                    )
                else:
                    fields[f"counter.{name}"] = _missing(
                        unit,
                        POWERSHELL_SOURCE,
                        now,
                        "provider_unavailable",
                        "Get-NetAdapterStatistics failed for this adapter",
                    )
            addresses = adapter.get("addresses") or []
            fields["network.addresses"] = (
                _observed(addresses, "1", POWERSHELL_SOURCE, now)
                if adapter.get("addresses_available")
                else _missing(
                    "1",
                    POWERSHELL_SOURCE,
                    now,
                    "provider_unavailable",
                    "Get-NetIPAddress failed for this adapter",
                )
            )
            routes = cast(list[dict[str, object]], adapter.get("routes") or [])
            gateways = cast(list[str], adapter.get("gateways") or []) or [
                str(route["next_hop"])
                for route in routes
                if route.get("destination_prefix") in {"0.0.0.0/0", "::/0"}
                and route.get("next_hop") not in {"0.0.0.0", "::"}  # noqa: S104
            ]
            fields["network.gateways"] = (
                _observed(gateways, "1", POWERSHELL_SOURCE, now)
                if adapter.get("routes_available") or adapter.get("ip_configuration_available")
                else _missing(
                    "1",
                    POWERSHELL_SOURCE,
                    now,
                    "provider_unavailable",
                    "Get-NetRoute and Get-NetIPConfiguration failed for this adapter",
                )
            )
            fields["network.dns_servers"] = (
                _observed(adapter.get("dns_servers") or [], "1", POWERSHELL_SOURCE, now)
                if adapter.get("dns_available")
                else _missing(
                    "1",
                    POWERSHELL_SOURCE,
                    now,
                    "provider_unavailable",
                    "Get-DnsClientServerAddress failed for this adapter",
                )
            )

        for adapter in ip_interfaces:
            key = _adapter_key(adapter.get("guid"), adapter.get("interface_index"))
            fields = merged.setdefault(key, {})
            for name, target, unit in (
                ("guid", "interface.guid", "1"),
                ("interface_index", "interface.index", "1"),
                ("name", "interface.name", "1"),
                ("description", "interface.description", "1"),
                ("state", "interface.status_code", "1"),
                ("type", "interface.type_code", "1"),
                ("physical_medium", "interface.physical_medium_code", "1"),
                ("tx_link_speed_bps", "interface.tx_link_speed", "bit/s"),
                ("rx_link_speed_bps", "interface.rx_link_speed", "bit/s"),
                ("received_bytes", "counter.received_bytes", "By"),
                ("sent_bytes", "counter.sent_bytes", "By"),
                ("received_packets", "counter.received_packets", "1"),
                ("sent_packets", "counter.sent_packets", "1"),
                ("received_errors", "counter.received_errors", "1"),
                ("sent_errors", "counter.sent_errors", "1"),
                ("received_discards", "counter.received_discards", "1"),
                ("sent_discards", "counter.sent_discards", "1"),
            ):
                if adapter.get(name) is not None:
                    fields[target] = _observed(adapter[name], unit, IP_HELPER_SOURCE, now)

        netsh_by_guid = {item.get("guid"): item for item in netsh_interfaces if item.get("guid")}
        for native in native_interfaces:
            guid = str(native["guid"])
            fields = merged.setdefault(guid, {})
            fields["interface.guid"] = _observed(guid, "1", NATIVE_SOURCE, now)
            fields["wifi.adapter"] = _observed(True, "1", NATIVE_SOURCE, now)
            fields["wifi.interface_state_code"] = _observed(
                _integer(native["state"]), "1", NATIVE_SOURCE, now
            )
            fields["interface.description"] = _observed(
                str(native["description"]), "1", NATIVE_SOURCE, now
            )
            try:
                capability = await asyncio.to_thread(self.native_wifi.interface_capability, guid)
                fields["wifi.known_capabilities"] = _observed(capability, "1", NATIVE_SOURCE, now)
            except Exception as error:
                fields["wifi.known_capabilities"] = _missing(
                    "1", NATIVE_SOURCE, now, detail=type(error).__name__
                )
            connection_result = native_connections.get(guid)
            try:
                if isinstance(connection_result, Exception):
                    raise connection_result
                if connection_result is None:
                    raise RuntimeError("Native Wi-Fi connection result is unavailable")
                await self._merge_connection(fields, guid, connection_result, now)
            except NativeWifiError as error:
                if error.category == "access_denied":
                    self._privacy_denied = True
                    privacy_reason = "permission_denied"
                    for field_name, unit in _WIFI_PRIVATE_FIELDS.items():
                        fields[field_name] = _missing(
                            unit,
                            NATIVE_SOURCE,
                            now,
                            privacy_reason,
                            "Windows location/privacy access denied",
                        )
                elif error.category == "invalid_state":
                    fields["wifi.associated"] = _observed(False, "1", NATIVE_SOURCE, now)
                else:
                    source_errors[f"native_connection.{guid}"] = _reason(error)
            except Exception as error:
                source_errors[f"native_connection.{guid}"] = _reason(error)

            if not self._privacy_denied and guid in netsh_by_guid:
                self._merge_netsh_fallback(fields, netsh_by_guid[guid], now)

        finished = datetime.now(UTC)
        return InventorySnapshot(
            snapshot_id=str(uuid4()),
            started_at=started,
            finished_at=finished,
            interfaces=[
                InterfaceSnapshot(interface_key=key, fields=fields)
                for key, fields in sorted(merged.items())
            ],
            source_errors=source_errors,
        )

    async def _merge_connection(
        self,
        fields: dict[str, NormalizedObservation],
        guid: str,
        connection: dict[str, object],
        now: datetime,
    ) -> None:
        fields["wifi.associated"] = _observed(True, "1", NATIVE_SOURCE, now)
        ssid_bytes = _byte_string(connection["ssid_bytes"])
        fields["wifi.ssid"] = _observed(
            {
                "bytes_base64": base64.b64encode(ssid_bytes).decode("ascii"),
                "display": connection.get("ssid_display"),
            },
            "1",
            NATIVE_SOURCE,
            now,
        )
        for source_name, field_name, unit in (
            ("bssid", "wifi.bssid", "1"),
            ("signal_quality", "wifi.signal_quality", "%"),
            ("phy_type", "wifi.phy_type_code", "1"),
            ("rx_rate_kbps", "wifi.rx_association_rate", "kbit/s"),
            ("tx_rate_kbps", "wifi.tx_association_rate", "kbit/s"),
        ):
            fields[field_name] = _observed(connection[source_name], unit, NATIVE_SOURCE, now)
        standard = phy_type_to_standard(_integer(connection["phy_type"]))
        if standard is not None:
            fields["wifi.standard"] = NormalizedObservation(
                value=standard,
                unit="1",
                source=PHY_DERIVED_SOURCE,
                availability="estimated",
                confidence="medium",
                reason=ObservationReason(
                    code="unknown", detail="Derived from the Native Wi-Fi DOT11_PHY_TYPE enum"
                ),
                collected_at=now,
            )
        quality = _integer(connection["signal_quality"])
        estimated = quality / 2.0 - 100.0
        fields["wifi.rssi_estimated"] = NormalizedObservation(
            value=estimated,
            unit="dBm",
            source=ObservationSource(
                plane="telemetry",
                producer="wto-desktop-agent",
                method="signal-quality-linear-estimate",
                version="1.0.0",
            ),
            availability="estimated",
            confidence="low",
            reason=ObservationReason(
                code="unknown", detail="Derived from Native Wi-Fi signal quality; not direct RSSI"
            ),
            collected_at=now,
        )
        try:
            bss_entries = await asyncio.to_thread(self.native_wifi.bss_entries, guid)
            current = next(
                (entry for entry in bss_entries if entry["bssid"] == connection["bssid"]), None
            )
            if current:
                fields["wifi.rssi_measured"] = _observed(
                    current["rssi_dbm"], "dBm", NATIVE_SOURCE, now
                )
                frequency_khz = int(current["frequency_khz"])
                if frequency_khz > 0:
                    frequency_mhz = frequency_khz // 1000
                    fields["wifi.frequency"] = _observed(frequency_mhz, "MHz", NATIVE_SOURCE, now)
                    channel = frequency_to_channel(frequency_mhz)
                    if channel:
                        fields["wifi.channel"] = NormalizedObservation(
                            value=channel.channel,
                            unit="1",
                            source=DERIVED_SOURCE,
                            availability="estimated",
                            confidence="high",
                            reason=ObservationReason(
                                code="unknown", detail="Derived from measured center frequency"
                            ),
                            collected_at=now,
                        )
                        fields["wifi.band"] = NormalizedObservation(
                            value=channel.band,
                            unit="1",
                            source=DERIVED_SOURCE,
                            availability="estimated",
                            confidence="high",
                            reason=ObservationReason(
                                code="unknown", detail="Derived from measured center frequency"
                            ),
                            collected_at=now,
                        )
        except NativeWifiError as error:
            if error.category == "access_denied":
                self._privacy_denied = True
        fields.setdefault(
            "wifi.channel_width",
            _missing("MHz", NATIVE_SOURCE, now, detail="Driver/API did not expose channel width"),
        )

    def _merge_netsh_fallback(
        self,
        fields: dict[str, NormalizedObservation],
        interface: dict[str, object],
        now: datetime,
    ) -> None:
        mapping = {
            "ssid": ("wifi.ssid_display_fallback", "1"),
            "bssid": ("wifi.bssid", "1"),
            "signal_quality": ("wifi.signal_quality", "%"),
            "channel": ("wifi.channel", "1"),
            "receive_rate_mbps": ("wifi.rx_association_rate", "Mbit/s"),
            "transmit_rate_mbps": ("wifi.tx_association_rate", "Mbit/s"),
        }
        for source_name, (target_name, unit) in mapping.items():
            if target_name not in fields and interface.get(source_name) is not None:
                fields[target_name] = _observed(
                    interface[source_name], unit, NETSH_SOURCE, now, confidence="low"
                )

    async def scan(self, interface_guid: str, cancellation: CancellationToken) -> WifiScanSnapshot:
        started = datetime.now(UTC)
        normalized_guid = interface_guid.strip("{}").lower()
        if self._privacy_denied:
            return WifiScanSnapshot(
                interface_guid=normalized_guid,
                started_at=started,
                finished_at=datetime.now(UTC),
                entries=[],
                reason=ObservationReason(
                    code="permission_denied",
                    detail="Windows location/privacy access was denied; fallbacks are suppressed",
                ),
            )
        lock = self._scan_locks.setdefault(normalized_guid, asyncio.Lock())
        if lock.locked():
            return WifiScanSnapshot(
                interface_guid=normalized_guid,
                started_at=started,
                finished_at=datetime.now(UTC),
                entries=[],
                reason=ObservationReason(
                    code="blocked", detail="scan already active for interface"
                ),
            )
        async with lock:
            elapsed = time.monotonic() - self._last_scan.get(normalized_guid, -1e12)
            if elapsed < self.scan_cooldown_seconds:
                return WifiScanSnapshot(
                    interface_guid=normalized_guid,
                    started_at=started,
                    finished_at=datetime.now(UTC),
                    entries=[],
                    reason=ObservationReason(code="blocked", detail="scan cooldown is active"),
                )
            if cancellation.cancelled:
                raise asyncio.CancelledError
            try:
                state = await asyncio.to_thread(self.native_wifi.interface_state, normalized_guid)
                if state == 0:
                    return WifiScanSnapshot(
                        interface_guid=normalized_guid,
                        started_at=started,
                        finished_at=datetime.now(UTC),
                        entries=[],
                        reason=ObservationReason(
                            code="blocked", detail="Wi-Fi adapter is disabled or not ready"
                        ),
                    )
                await asyncio.to_thread(
                    self.native_wifi.scan, normalized_guid, self.scan_timeout_seconds
                )
                self._last_scan[normalized_guid] = time.monotonic()
                raw_entries = await asyncio.to_thread(self.native_wifi.bss_entries, normalized_guid)
            except NativeWifiError as error:
                if error.category == "access_denied":
                    self._privacy_denied = True
                return WifiScanSnapshot(
                    interface_guid=normalized_guid,
                    started_at=started,
                    finished_at=datetime.now(UTC),
                    entries=[],
                    reason=_reason(error),
                )
            if cancellation.cancelled:
                raise asyncio.CancelledError
            deduplicated: dict[str, dict[str, object]] = {}
            for entry in raw_entries:
                bssid = str(entry["bssid"])
                existing = deduplicated.get(bssid)
                if existing is None or _integer(entry["rssi_dbm"]) > _integer(existing["rssi_dbm"]):
                    deduplicated[bssid] = entry
            finished = datetime.now(UTC)
            return WifiScanSnapshot(
                interface_guid=normalized_guid,
                started_at=started,
                finished_at=finished,
                entries=[
                    _scan_entry(normalized_guid, entry, finished) for entry in deduplicated.values()
                ],
            )

    def capability_overrides(self) -> dict[str, dict[str, object]]:
        if not self._native_available:
            try:
                self.native_wifi.interfaces()
                self._native_available = True
            except Exception as error:
                self._native_probe_error = type(error).__name__
        technical = "supported" if self._native_available else "unknown"
        permission_status = "denied" if self._privacy_denied else "conditional"
        permission_reason = (
            {"code": "permission_denied", "detail": "Windows location/privacy access denied"}
            if self._privacy_denied
            else {"code": "permission_missing", "detail": "Location access may be required"}
        )
        provider = {
            "status": "available" if self._native_available else "unknown",
            "implementations": (
                [
                    {
                        "provider_id": "windows-native-wifi",
                        "provider_version": "1.0.0",
                        "method": "wlanapi",
                    }
                ]
                if self._native_available
                else []
            ),
            "reason": None if self._native_available else {"code": "unknown"},
        }
        common = {
            "technical_support": {
                "status": technical,
                "reason": None if self._native_available else {"code": "unknown"},
            },
            "implementation_status": {"status": "implemented", "reason": None},
            "permission_requirement": {
                "status": permission_status,
                "permissions": ["windows.location"],
                "reason": permission_reason,
            },
            "user_interaction": {
                "status": "conditional",
                "reason": {"code": "user_interaction_required"},
            },
            "background_execution": {"status": "continuous", "reason": None},
            "provider": provider,
            "limitations": {
                "status": "known",
                "max_concurrency": 1,
                "reason": {
                    "code": "unknown",
                    "detail": "Fields depend on OS, hardware, driver and privacy state",
                },
            },
        }
        scan = {**common}
        scan["background_execution"] = {"status": "bounded", "reason": None}
        scan["limitations"] = {
            "status": "known",
            "max_duration_seconds": max(1, int(self.scan_timeout_seconds)),
            "max_concurrency": 1,
            "reason": {"code": "unknown", "detail": "Per-interface cooldown applies"},
        }
        return {
            "wifi.connection.read": common,
            "wifi.scan": scan,
            "wifi.rssi.read": common,
        }


_WIFI_PRIVATE_FIELDS = {
    "wifi.ssid": "1",
    "wifi.bssid": "1",
    "wifi.signal_quality": "%",
    "wifi.rssi_measured": "dBm",
    "wifi.frequency": "MHz",
    "wifi.channel": "1",
    "wifi.band": "1",
    "wifi.rx_association_rate": "kbit/s",
    "wifi.tx_association_rate": "kbit/s",
}


def _adapter_key(guid: object, index: object) -> str:
    if guid:
        return str(guid).strip("{}").lower()
    return f"ifindex:{_integer(index) if index is not None else 0}"


def _integer(value: object) -> int:
    if isinstance(value, int | str | bytes | bytearray):
        return int(value)
    raise ValueError("structured provider returned a non-integer value")


def _byte_string(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    raise ValueError("Native Wi-Fi returned a non-byte SSID")


def _set_if_value(
    fields: dict[str, NormalizedObservation],
    name: str,
    value: object,
    unit: str,
    source: ObservationSource,
    now: datetime,
) -> None:
    if value is not None:
        fields[name] = _observed(value, unit, source, now)


def _scan_entry(interface_guid: str, entry: dict[str, object], now: datetime) -> WifiScanEntry:
    ssid_bytes = _byte_string(entry["ssid_bytes"])
    fields: dict[str, NormalizedObservation] = {
        "wifi.rssi_measured": _observed(entry["rssi_dbm"], "dBm", NATIVE_SOURCE, now),
        "wifi.signal_quality": _observed(entry["signal_quality"], "%", NATIVE_SOURCE, now),
        "wifi.phy_type_code": _observed(entry["phy_type"], "1", NATIVE_SOURCE, now),
    }
    fields["wifi.ssid"] = (
        _observed(
            {
                "bytes_base64": base64.b64encode(ssid_bytes).decode("ascii"),
                "display": entry.get("ssid_display"),
            },
            "1",
            NATIVE_SOURCE,
            now,
        )
        if ssid_bytes
        else _missing("1", NATIVE_SOURCE, now, detail="Hidden network did not disclose its SSID")
    )
    standard = phy_type_to_standard(_integer(entry["phy_type"]))
    if standard is not None:
        fields["wifi.standard"] = NormalizedObservation(
            value=standard,
            unit="1",
            source=PHY_DERIVED_SOURCE,
            availability="estimated",
            confidence="medium",
            reason=ObservationReason(
                code="unknown", detail="Derived from the Native Wi-Fi DOT11_PHY_TYPE enum"
            ),
            collected_at=now,
        )
    frequency_khz = _integer(entry["frequency_khz"])
    if frequency_khz > 0:
        frequency_mhz = frequency_khz // 1000
        fields["wifi.frequency"] = _observed(frequency_mhz, "MHz", NATIVE_SOURCE, now)
        channel = frequency_to_channel(frequency_mhz)
        if channel:
            fields["wifi.channel"] = NormalizedObservation(
                value=channel.channel,
                unit="1",
                source=DERIVED_SOURCE,
                availability="estimated",
                confidence="high",
                reason=ObservationReason(
                    code="unknown", detail="Derived from measured center frequency"
                ),
                collected_at=now,
            )
            fields["wifi.band"] = NormalizedObservation(
                value=channel.band,
                unit="1",
                source=DERIVED_SOURCE,
                availability="estimated",
                confidence="high",
                reason=ObservationReason(
                    code="unknown", detail="Derived from measured center frequency"
                ),
                collected_at=now,
            )
    return WifiScanEntry(
        interface_guid=interface_guid,
        bssid=str(entry["bssid"]),
        fields=fields,
    )
