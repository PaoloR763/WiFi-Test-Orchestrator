from __future__ import annotations

import asyncio
import base64
import os
import stat
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from uuid import uuid4

from wto_desktop_agent.domain.errors import PluginUnavailableError
from wto_desktop_agent.domain.telemetry import (
    InterfaceSnapshot,
    InventorySnapshot,
    NormalizedObservation,
    ObservationReason,
    ObservationSource,
    WifiScanSnapshot,
)
from wto_desktop_agent.platforms.linux.errors import LinuxProviderError
from wto_desktop_agent.platforms.linux.frequency import frequency_to_channel
from wto_desktop_agent.platforms.linux.network_manager import NetworkManagerSnapshot
from wto_desktop_agent.platforms.linux.parsers import (
    infer_phy_standard,
    parse_ethtool_driver,
    parse_ip_address_json,
    parse_ip_route_json,
    parse_iw_dev,
    parse_iw_info,
    parse_iw_link,
    parse_resolv_conf,
    validate_interface_name,
)
from wto_desktop_agent.ports.platform import CommandRequest, ProcessRunner
from wto_desktop_agent.ports.plugins import CancellationToken

NM_SOURCE = ObservationSource(
    plane="telemetry", producer="linux-networkmanager", method="dbus", version="1.0.0"
)
IP_SOURCE = ObservationSource(
    plane="telemetry", producer="linux-iproute2", method="json", version="1.0.0"
)
IW_SOURCE = ObservationSource(
    plane="telemetry", producer="linux-iw", method="nl80211-cli", version="1.0.0"
)
ETHTOOL_SOURCE = ObservationSource(
    plane="telemetry", producer="linux-ethtool", method="driver-info", version="1.0.0"
)
SYSFS_SOURCE = ObservationSource(
    plane="telemetry", producer="linux-sysfs", method="read-only", version="1.0.0"
)
DERIVED_SOURCE = ObservationSource(
    plane="telemetry",
    producer="wto-desktop-agent",
    method="linux-field-normalization",
    version="1.0.0",
)

_MAX_SYSFS_INTERFACES = 4096
_MAX_SYSFS_ATTRIBUTE_BYTES = 128
_MAX_ETHTOOL_WORKERS = 8
_MAX_IW_DETAIL_WORKERS = 8

_IwDetailResult = tuple[
    dict[str, object] | BaseException,
    dict[str, object] | BaseException,
]


def _inventory_deadline_error(command_id: str) -> LinuxProviderError:
    return LinuxProviderError(
        command_id,
        "transient_failure",
        "inventory total timeout expired",
    )


@dataclass
class _InventoryDeadlineState:
    """Sticky global-deadline state shared by one bounded worker pool."""

    deadline: float
    global_deadline_observed: bool = False

    def observe_global_deadline(self) -> None:
        self.global_deadline_observed = True

    def remaining(self) -> float:
        if self.global_deadline_observed:
            raise _inventory_deadline_error("linux-inventory")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            self.observe_global_deadline()
            raise _inventory_deadline_error("linux-inventory")
        return remaining


class NetworkManagerProvider(Protocol):
    async def collect(self) -> NetworkManagerSnapshot: ...


ReadinessState = Literal[
    "installed",
    "available",
    "permission_denied",
    "provider_failed",
    "unsupported",
    "command_missing",
    "transient_failure",
]


@dataclass(frozen=True)
class ProviderReadiness:
    installed: bool
    state: ReadinessState
    detail: str | None = None

    @property
    def available(self) -> bool:
        return self.state == "available"


def _observed(
    value: Any,
    unit: str,
    source: ObservationSource,
    now: datetime,
    *,
    confidence: str = "high",
) -> NormalizedObservation:
    return NormalizedObservation.measured(
        value, unit, source, now, confidence=cast(Any, confidence)
    )


def _missing(
    unit: str,
    source: ObservationSource,
    now: datetime,
    code: str,
    detail: str,
) -> NormalizedObservation:
    return NormalizedObservation.missing(
        unit,
        source,
        now,
        ObservationReason(code=cast(Any, code), detail=detail[:256]),
    )


def _provider_reason(error: Exception) -> ObservationReason:
    if isinstance(error, LinuxProviderError):
        code = {
            "permission_denied": "permission_denied",
            "unavailable": "provider_unavailable",
            "command_missing": "provider_unavailable",
            "unsupported": "not_exposed_by_platform",
            "interface_disconnected": "blocked",
            "transient_failure": "unknown",
            "invalid_output": "unknown",
        }[error.kind]
        return ObservationReason(code=cast(Any, code), detail=f"{error.kind}: {error.detail}"[:256])
    if isinstance(error, PermissionError):
        return ObservationReason(code="permission_denied", detail=type(error).__name__)
    if isinstance(error, PluginUnavailableError):
        return ObservationReason(code="provider_unavailable", detail="command_missing")
    return ObservationReason(code="unknown", detail=f"transient_failure: {type(error).__name__}")


def _network_manager_source_reason(path: str, category: str) -> ObservationReason:
    code = {
        "permission_denied": "permission_denied",
        "unavailable": "provider_unavailable",
    }.get(category, "unknown")
    subject = "active connection" if path.startswith("active-connection:") else "object"
    return ObservationReason(
        code=cast(Any, code),
        detail=f"{category}: NetworkManager {subject} query incomplete"[:256],
    )


def _active_connections_observation(
    item: dict[str, object], status: str, now: datetime
) -> NormalizedObservation:
    raw = item.get("active_connections")
    if not isinstance(raw, list) or not all(isinstance(name, str) and name for name in raw):
        return _missing(
            "1",
            NM_SOURCE,
            now,
            "provider_unavailable",
            "active connection output was invalid",
        )
    values = list(raw)
    if status == "complete":
        return _observed(values, "1", NM_SOURCE, now)
    if status == "partial":
        return NormalizedObservation(
            value=values,
            unit="1",
            source=NM_SOURCE,
            availability="unknown",
            confidence="low",
            reason=ObservationReason(
                code="unknown",
                detail="NetworkManager active connection query was partial",
            ),
            collected_at=now,
        )
    return _missing(
        "1",
        NM_SOURCE,
        now,
        "provider_unavailable",
        "NetworkManager active connection query was unavailable",
    )


class LinuxInventoryCollector:
    def __init__(
        self,
        network_manager: NetworkManagerProvider,
        process_runner: ProcessRunner,
        *,
        commands: frozenset[str],
        tools: dict[str, bool],
        network_manager_installed: bool,
        systemd_available: bool,
        inventory_timeout_seconds: float,
        tool_readiness: dict[str, ProviderReadiness] | None = None,
        sysfs_root: Path = Path("/sys/class/net"),
        resolv_conf: Path = Path("/etc/resolv.conf"),
    ) -> None:
        self.network_manager = network_manager
        self.process_runner = process_runner
        self.commands = commands
        self.tools = dict(tools)
        self.network_manager_installed = network_manager_installed
        self.systemd_available = systemd_available
        self.inventory_timeout_seconds = inventory_timeout_seconds
        self.sysfs_root = sysfs_root
        self.resolv_conf = resolv_conf
        self._initial_readiness: dict[str, ProviderReadiness] = {
            "networkmanager": ProviderReadiness(
                network_manager_installed,
                "installed" if network_manager_installed else "command_missing",
            ),
            "iw": (tool_readiness or {}).get(
                "iw",
                ProviderReadiness(
                    bool(self.tools.get("iw", False)),
                    "installed" if self.tools.get("iw", False) else "command_missing",
                ),
            ),
        }
        self._readiness = dict(self._initial_readiness)

    @staticmethod
    def _failure_readiness(error: BaseException, *, installed: bool) -> ProviderReadiness:
        if isinstance(error, LinuxProviderError):
            state = cast(
                ReadinessState,
                {
                    "permission_denied": "permission_denied",
                    "command_missing": "command_missing",
                    "unsupported": "unsupported",
                    "transient_failure": "transient_failure",
                    "interface_disconnected": "provider_failed",
                    "unavailable": "provider_failed",
                    "invalid_output": "provider_failed",
                }[error.kind],
            )
            return ProviderReadiness(installed, state, error.kind)
        if isinstance(error, PermissionError):
            return ProviderReadiness(installed, "permission_denied", "permission_denied")
        if isinstance(error, TimeoutError):
            return ProviderReadiness(installed, "transient_failure", "timeout")
        if isinstance(error, ValueError):
            return ProviderReadiness(installed, "provider_failed", "invalid_output")
        return ProviderReadiness(installed, "transient_failure", type(error).__name__)

    def _reset_readiness(self) -> None:
        self._readiness = dict(self._initial_readiness)

    def _iw_failure_readiness(self, error: BaseException) -> ProviderReadiness:
        initial = self._initial_readiness["iw"]
        if (
            isinstance(error, LinuxProviderError)
            and error.kind == "command_missing"
            and initial.state in {"permission_denied", "provider_failed"}
        ):
            return initial
        return self._failure_readiness(error, installed=initial.installed)

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LinuxProviderError(
                "linux-inventory",
                "transient_failure",
                "inventory total timeout expired",
            )
        return remaining

    async def _network_manager(self, deadline: float) -> NetworkManagerSnapshot:
        try:
            async with asyncio.timeout(self._remaining(deadline)):
                return await self.network_manager.collect()
        except TimeoutError as error:
            raise LinuxProviderError(
                "networkmanager-dbus",
                "transient_failure",
                "NetworkManager total query timed out",
            ) from error

    async def _command(
        self,
        command_id: str,
        arguments: dict[str, object],
        *,
        deadline: float | None = None,
    ) -> bytes:
        if command_id not in self.commands:
            raise LinuxProviderError(command_id, "command_missing", "command is not installed")
        result = await self.process_runner.run(
            CommandRequest(
                command_id=command_id,
                arguments=arguments,
                timeout_seconds=(
                    min(self.inventory_timeout_seconds, self._remaining(deadline))
                    if deadline is not None
                    else self.inventory_timeout_seconds
                ),
            ),
            CancellationToken(),
        )
        if result.return_code != 0:
            diagnostic = result.stderr[:512].decode("utf-8", errors="replace").casefold()
            kind = (
                "permission_denied"
                if "permission" in diagnostic or "operation not permitted" in diagnostic
                else "transient_failure"
            )
            raise LinuxProviderError(command_id, cast(Any, kind), "command returned nonzero")
        return result.stdout

    async def collect_inventory(self) -> InventorySnapshot:
        started = datetime.now(UTC)
        deadline = time.monotonic() + self.inventory_timeout_seconds
        self._reset_readiness()
        now = started
        source_errors: dict[str, ObservationReason] = {}
        nm: NetworkManagerSnapshot | None = None
        ip_interfaces: list[dict[str, object]] = []
        routes: list[dict[str, object]] = []
        route4_available = False
        route6_available = False
        iw_interfaces: list[dict[str, object]] = []

        try:
            async with asyncio.timeout(self._remaining(deadline)):
                sysfs_interfaces = await asyncio.to_thread(
                    self._discover_sysfs_interfaces,
                    deadline,
                )
        except Exception as error:
            sysfs_interfaces = []
            source_errors["sysfs.interfaces"] = _provider_reason(error)

        initial = await asyncio.gather(
            self._network_manager(deadline),
            self._command("linux.ip.address-json", {}, deadline=deadline),
            self._command("linux.ip.route-json", {}, deadline=deadline),
            self._command("linux.ip.route6-json", {}, deadline=deadline),
            self._command("linux.iw.dev", {}, deadline=deadline),
            return_exceptions=True,
        )
        nm_result, address_result, route_result, route6_result, iw_result = initial
        if isinstance(nm_result, BaseException):
            source_errors["networkmanager"] = _provider_reason(cast(Exception, nm_result))
            self._readiness["networkmanager"] = self._failure_readiness(
                nm_result, installed=self.network_manager_installed
            )
        else:
            nm = nm_result
            self.network_manager_installed = True
            self._readiness["networkmanager"] = (
                ProviderReadiness(True, "available")
                if nm.active_connections_status == "complete"
                else ProviderReadiness(
                    True,
                    "transient_failure",
                    f"active_connections_{nm.active_connections_status}",
                )
            )
            for path, category in nm.source_errors.items():
                source_errors[f"networkmanager.{path}"] = _network_manager_source_reason(
                    path, category
                )
        try:
            if isinstance(address_result, BaseException):
                raise address_result
            ip_interfaces = parse_ip_address_json(address_result)
        except BaseException as error:
            source_errors["ip.address"] = _provider_reason(cast(Exception, error))
        try:
            if isinstance(route_result, BaseException):
                raise route_result
            routes = parse_ip_route_json(route_result)
            route4_available = True
        except BaseException as error:
            source_errors["ip.route"] = _provider_reason(cast(Exception, error))
        try:
            if isinstance(route6_result, BaseException):
                raise route6_result
            routes.extend(parse_ip_route_json(route6_result))
            route6_available = True
        except BaseException as error:
            source_errors["ip.route6"] = _provider_reason(cast(Exception, error))
        try:
            if isinstance(iw_result, BaseException):
                raise iw_result
            iw_interfaces = parse_iw_dev(iw_result)
            self._readiness["iw"] = ProviderReadiness(True, "available")
        except BaseException as error:
            source_errors["iw.dev"] = _provider_reason(cast(Exception, error))
            self._readiness["iw"] = self._iw_failure_readiness(error)

        merged: dict[str, dict[str, NormalizedObservation]] = {
            name: {"interface.name": _observed(name, "1", SYSFS_SOURCE, now)}
            for name in sysfs_interfaces
        }
        for item in ip_interfaces:
            name = str(item["name"])
            fields = merged.setdefault(name, {})
            mapping = (
                ("index", "interface.index", "1"),
                ("administratively_up", "interface.administratively_up", "1"),
                ("operational_state", "interface.operational_state", "1"),
                ("mtu", "interface.mtu", "By"),
                ("mac_address", "interface.mac_address", "1"),
                ("link_type", "interface.link_type", "1"),
                ("virtual_kind", "interface.virtual_kind", "1"),
                ("addresses", "network.addresses", "1"),
                ("rx_bytes", "counter.received_bytes", "By"),
                ("rx_packets", "counter.received_packets", "1"),
                ("rx_errors", "counter.received_errors", "1"),
                ("rx_drops", "counter.received_drops", "1"),
                ("tx_bytes", "counter.sent_bytes", "By"),
                ("tx_packets", "counter.sent_packets", "1"),
                ("tx_errors", "counter.sent_errors", "1"),
                ("tx_drops", "counter.sent_drops", "1"),
            )
            fields["interface.name"] = _observed(name, "1", IP_SOURCE, now)
            for source_name, target, unit in mapping:
                if item.get(source_name) is not None:
                    fields[target] = _observed(item[source_name], unit, IP_SOURCE, now)
            if route4_available and route6_available:
                gateways = [
                    route["gateway"]
                    for route in routes
                    if route["interface"] == name
                    and route["destination"] == "default"
                    and route.get("gateway") is not None
                ]
                fields["network.gateways"] = _observed(gateways, "1", IP_SOURCE, now)
            else:
                failed_families = ",".join(
                    family
                    for family, available in (
                        ("ipv4", route4_available),
                        ("ipv6", route6_available),
                    )
                    if not available
                )
                fields["network.gateways"] = _missing(
                    "1",
                    IP_SOURCE,
                    now,
                    "provider_unavailable",
                    f"route query failed for {failed_families}",
                )

        if nm is not None:
            for item in nm.interfaces:
                try:
                    name = validate_interface_name(str(item["name"]))
                except (KeyError, ValueError):
                    source_errors["networkmanager.interface"] = ObservationReason(
                        code="unknown",
                        detail="invalid_output: NetworkManager interface name was invalid",
                    )
                    continue
                fields = merged.setdefault(name, {})
                fields["interface.name"] = _observed(name, "1", NM_SOURCE, now)
                nm_mapping = (
                    ("state", "networkmanager.device_state", "1"),
                    ("managed", "networkmanager.managed", "1"),
                    ("driver", "interface.driver", "1"),
                    ("driver_version", "interface.driver_version", "1"),
                    ("firmware_version", "interface.firmware_version", "1"),
                    ("mac_address", "interface.mac_address", "1"),
                    ("mtu", "interface.mtu", "By"),
                )
                for source_name, target, unit in nm_mapping:
                    if item.get(source_name) is not None:
                        fields[target] = _observed(item[source_name], unit, NM_SOURCE, now)
                for source_name, target in (
                    ("addresses", "network.addresses"),
                    ("gateways", "network.gateways"),
                    ("dns_servers", "network.dns_servers"),
                ):
                    value = item.get(source_name)
                    raw_families = item.get(f"{source_name}_config_families")
                    field_configuration_complete = (
                        isinstance(raw_families, list)
                        and len(raw_families) == 2
                        and all(type(family) is str for family in raw_families)
                        and set(raw_families) == {"ipv4", "ipv6"}
                    )
                    if value is None or not field_configuration_complete:
                        continue
                    fields[target] = _observed(value, "1", NM_SOURCE, now)
                fields["networkmanager.active_connections"] = _active_connections_observation(
                    item,
                    str(
                        item.get(
                            "active_connections_status",
                            nm.active_connections_status,
                        )
                    ),
                    now,
                )
                if item.get("wifi"):
                    self._merge_nm_wifi(fields, item, now)

        iw_by_name = {str(item["name"]): item for item in iw_interfaces}
        iw_names = tuple(iw_by_name)
        iw_details = await self._bounded_iw_details(iw_names, deadline)
        for name, result in iw_details:
            fields = merged.setdefault(name, {})
            base = iw_by_name[name]
            fields["wifi.adapter"] = _observed(True, "1", IW_SOURCE, now)
            for source_name, target, unit in (
                ("wiphy", "wifi.wiphy", "1"),
                ("type", "wifi.interface_type", "1"),
                ("tx_power_dbm", "wifi.tx_power", "dBm"),
            ):
                if base.get(source_name) is not None:
                    fields[target] = _observed(base[source_name], unit, IW_SOURCE, now)
            if isinstance(result, BaseException):
                source_errors[f"iw.{name}"] = _provider_reason(cast(Exception, result))
                continue
            link_result, info_result = result
            info: dict[str, object] = {}
            if isinstance(info_result, BaseException):
                info_reason = _provider_reason(cast(Exception, info_result))
                source_errors[f"iw.info.{name}"] = info_reason
                source_errors.setdefault(f"iw.{name}", info_reason)
            else:
                info = info_result
                self._merge_iw_info(fields, info, now)
            if isinstance(link_result, BaseException):
                reason = _provider_reason(cast(Exception, link_result))
                source_errors[f"iw.link.{name}"] = reason
                source_errors.setdefault(f"iw.{name}", reason)
                fields.setdefault(
                    "wifi.associated",
                    _missing(
                        "1", IW_SOURCE, now, reason.code, reason.detail or "iw link unavailable"
                    ),
                )
                fields.setdefault(
                    "wifi.active",
                    _missing(
                        "1", IW_SOURCE, now, reason.code, reason.detail or "iw link unavailable"
                    ),
                )
            else:
                self._merge_iw_wifi(fields, link_result, info, now)

        ethtool_results = await self._bounded_ethtool(tuple(merged), deadline)
        for name, ethtool_result in ethtool_results:
            if isinstance(ethtool_result, BaseException):
                source_errors[f"ethtool.{name}"] = _provider_reason(cast(Exception, ethtool_result))
                continue
            for source_name, target in (
                ("driver", "interface.driver"),
                ("version", "interface.driver_version"),
                ("firmware_version", "interface.firmware_version"),
                ("bus_info", "interface.bus_info"),
            ):
                if ethtool_result.get(source_name) and target not in merged[name]:
                    merged[name][target] = _observed(
                        ethtool_result[source_name], "1", ETHTOOL_SOURCE, now
                    )

        for name, fields in merged.items():
            try:
                self._remaining(deadline)
            except LinuxProviderError as error:
                source_errors["sysfs.enrichment"] = _provider_reason(error)
                break
            try:
                sysfs_fields = self._sysfs_fields(name, now, deadline)
            except Exception as error:
                source_errors[f"sysfs.{name}"] = _provider_reason(error)
                continue
            for key, observation in sysfs_fields.items():
                fields.setdefault(key, observation)

        dns = self._resolver_servers(source_errors)
        for fields in merged.values():
            if dns is None:
                fields.setdefault(
                    "network.dns_servers",
                    _missing(
                        "1",
                        SYSFS_SOURCE,
                        now,
                        "provider_unavailable",
                        "resolver configuration could not be measured",
                    ),
                )
            else:
                fields.setdefault("network.dns_servers", _observed(dns, "1", SYSFS_SOURCE, now))
        for fields in merged.values():
            if "wifi.adapter" in fields:
                self._complete_wifi_absence(fields, now)

        host_fields = self._host_fields(nm, now)
        finished = datetime.now(UTC)
        interfaces = [
            InterfaceSnapshot(interface_key=key, fields=fields)
            for key, fields in sorted(merged.items())
        ]
        interfaces.append(InterfaceSnapshot(interface_key="host:linux", fields=host_fields))
        return InventorySnapshot(
            snapshot_id=str(uuid4()),
            started_at=started,
            finished_at=finished,
            interfaces=interfaces,
            source_errors=source_errors,
        )

    async def _iw_details(
        self,
        interface: str,
        deadline_state: _InventoryDeadlineState,
    ) -> _IwDetailResult:
        try:
            info_raw = await self._command(
                "linux.iw.info",
                {"interface": interface},
                deadline=deadline_state.deadline,
            )
        except Exception as error:
            info: dict[str, object] | BaseException = error
        else:
            try:
                info = parse_iw_info(info_raw)
            except Exception as error:
                info = error

        try:
            deadline_state.remaining()
        except LinuxProviderError:
            return _inventory_deadline_error("linux.iw.link"), info

        try:
            link_raw = await self._command(
                "linux.iw.link",
                {"interface": interface},
                deadline=deadline_state.deadline,
            )
        except Exception as error:
            link: dict[str, object] | BaseException = error
        else:
            try:
                link = parse_iw_link(link_raw)
            except Exception as error:
                link = error

        return link, info

    async def _bounded_iw_details(
        self,
        interfaces: tuple[str, ...],
        deadline: float,
    ) -> list[tuple[str, _IwDetailResult | BaseException]]:
        """Probe iw details with at most eight index-backed workers."""

        ordered = tuple(interfaces)
        if not ordered:
            return []

        worker_count = min(_MAX_IW_DETAIL_WORKERS, len(ordered))
        results: list[_IwDetailResult | BaseException | None] = [None] * len(ordered)
        next_index = 0
        deadline_state = _InventoryDeadlineState(deadline)

        def deadline_result() -> _IwDetailResult:
            return (
                _inventory_deadline_error("linux.iw.link"),
                _inventory_deadline_error("linux.iw.info"),
            )

        try:
            deadline_state.remaining()
        except LinuxProviderError:
            return [(interface, deadline_result()) for interface in ordered]

        async def worker() -> None:
            nonlocal next_index
            while True:
                if deadline_state.global_deadline_observed:
                    return
                try:
                    deadline_state.remaining()
                except LinuxProviderError:
                    return
                index = next_index
                if index >= len(ordered):
                    return
                next_index += 1
                interface = ordered[index]
                if deadline_state.global_deadline_observed:
                    return
                try:
                    remaining = deadline_state.remaining()
                except LinuxProviderError:
                    return
                timeout_scope = asyncio.timeout(remaining)
                try:
                    async with timeout_scope:
                        results[index] = await self._iw_details(interface, deadline_state)
                except TimeoutError as error:
                    if timeout_scope.expired():
                        deadline_state.observe_global_deadline()
                        results[index] = deadline_result()
                    else:
                        results[index] = error
                except Exception as error:
                    results[index] = error

        workers: list[asyncio.Task[None]] = []
        try:
            for index in range(worker_count):
                coroutine = worker()
                try:
                    task = asyncio.create_task(
                        coroutine,
                        name=f"linux-iw-detail-worker-{index}",
                    )
                except BaseException:
                    coroutine.close()
                    raise
                workers.append(task)
            await asyncio.gather(*workers)
        except BaseException:
            for task in workers:
                task.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            raise

        completed: list[tuple[str, _IwDetailResult | BaseException]] = []
        for index, interface in enumerate(ordered):
            result = results[index]
            if result is None:
                result = deadline_result()
            completed.append((interface, result))
        return completed

    async def _ethtool(self, interface: str, deadline: float) -> dict[str, str]:
        raw = await self._command(
            "linux.ethtool.driver", {"interface": interface}, deadline=deadline
        )
        return parse_ethtool_driver(raw)

    async def _bounded_ethtool(
        self,
        interfaces: tuple[str, ...],
        deadline: float,
    ) -> list[tuple[str, dict[str, str] | BaseException]]:
        """Probe driver metadata with at most eight index-backed workers."""

        ordered = tuple(interfaces)
        if not ordered:
            return []

        worker_count = min(_MAX_ETHTOOL_WORKERS, len(ordered))
        results: list[dict[str, str] | BaseException | None] = [None] * len(ordered)
        next_index = 0
        deadline_state = _InventoryDeadlineState(deadline)

        def deadline_error() -> LinuxProviderError:
            return _inventory_deadline_error("linux.ethtool.driver")

        try:
            deadline_state.remaining()
        except LinuxProviderError:
            return [(interface, deadline_error()) for interface in ordered]

        async def worker() -> None:
            nonlocal next_index
            while True:
                if deadline_state.global_deadline_observed:
                    return
                try:
                    deadline_state.remaining()
                except LinuxProviderError:
                    return
                index = next_index
                if index >= len(ordered):
                    return
                next_index += 1
                interface = ordered[index]
                if deadline_state.global_deadline_observed:
                    return
                try:
                    remaining = deadline_state.remaining()
                except LinuxProviderError:
                    return
                timeout_scope = asyncio.timeout(remaining)
                try:
                    async with timeout_scope:
                        results[index] = await self._ethtool(interface, deadline)
                except TimeoutError as error:
                    if timeout_scope.expired():
                        deadline_state.observe_global_deadline()
                        results[index] = deadline_error()
                    else:
                        results[index] = error
                except Exception as error:
                    results[index] = error

        workers: list[asyncio.Task[None]] = []
        try:
            for index in range(worker_count):
                coroutine = worker()
                try:
                    task = asyncio.create_task(
                        coroutine,
                        name=f"linux-ethtool-worker-{index}",
                    )
                except BaseException:
                    coroutine.close()
                    raise
                workers.append(task)
            await asyncio.gather(*workers)
        except BaseException:
            for task in workers:
                task.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            raise

        completed: list[tuple[str, dict[str, str] | BaseException]] = []
        for index, interface in enumerate(ordered):
            result = results[index]
            if result is None:
                result = deadline_error()
            completed.append((interface, result))
        return completed

    async def refresh_readiness(self) -> None:
        """Run the same provider entry points used by inventory without trusting presence."""

        deadline = time.monotonic() + self.inventory_timeout_seconds
        self._reset_readiness()
        nm_result, iw_result = await asyncio.gather(
            self._network_manager(deadline),
            self._command("linux.iw.dev", {}, deadline=deadline),
            return_exceptions=True,
        )
        if isinstance(nm_result, BaseException):
            self._readiness["networkmanager"] = self._failure_readiness(
                nm_result, installed=self.network_manager_installed
            )
        else:
            self.network_manager_installed = True
            self._readiness["networkmanager"] = (
                ProviderReadiness(True, "available")
                if nm_result.active_connections_status == "complete"
                else ProviderReadiness(
                    True,
                    "transient_failure",
                    f"active_connections_{nm_result.active_connections_status}",
                )
            )
        if isinstance(iw_result, BaseException):
            self._readiness["iw"] = self._iw_failure_readiness(iw_result)
        else:
            try:
                parse_iw_dev(iw_result)
            except Exception as error:
                self._readiness["iw"] = self._iw_failure_readiness(error)
            else:
                self._readiness["iw"] = ProviderReadiness(True, "available")

    def _merge_nm_wifi(
        self,
        fields: dict[str, NormalizedObservation],
        item: dict[str, object],
        now: datetime,
    ) -> None:
        fields["wifi.adapter"] = _observed(True, "1", NM_SOURCE, now)
        associated = item.get("associated")
        if type(associated) is not bool:
            return
        fields["wifi.associated"] = _observed(associated, "1", NM_SOURCE, now)
        fields["wifi.active"] = _observed(associated, "1", NM_SOURCE, now)
        if not associated:
            return
        ssid_bytes = item.get("ssid_bytes")
        if item.get("ssid_error") == "invalid_output":
            fields["wifi.ssid"] = _missing(
                "1",
                NM_SOURCE,
                now,
                "unknown",
                "invalid_output: NetworkManager access point SSID was invalid",
            )
        elif isinstance(ssid_bytes, bytes):
            fields["wifi.ssid"] = _observed(
                {
                    "bytes_base64": base64.b64encode(ssid_bytes).decode("ascii"),
                    "display": ssid_bytes.decode("utf-8", errors="replace"),
                },
                "1",
                NM_SOURCE,
                now,
            )
        for source_name, target, unit in (
            ("bssid", "wifi.bssid", "1"),
            ("frequency_mhz", "wifi.frequency", "MHz"),
            ("signal_percent", "wifi.signal_quality", "%"),
            ("bitrate_kbps", "wifi.tx_association_rate", "kbit/s"),
        ):
            value = item.get(source_name)
            valid = isinstance(value, str) if source_name == "bssid" else type(value) is int
            if valid:
                fields[target] = _observed(value, unit, NM_SOURCE, now)
        frequency = item.get("frequency_mhz")
        if type(frequency) is int:
            channel = frequency_to_channel(frequency)
            if channel is not None:
                fields.setdefault(
                    "wifi.channel",
                    _observed(channel.channel, "1", DERIVED_SOURCE, now, confidence="medium"),
                )
                fields.setdefault(
                    "wifi.band",
                    _observed(channel.band, "1", DERIVED_SOURCE, now, confidence="medium"),
                )

    def _merge_iw_wifi(
        self,
        fields: dict[str, NormalizedObservation],
        link: dict[str, object],
        info: dict[str, object],
        now: datetime,
    ) -> None:
        connected = link.get("connected")
        if type(connected) is not bool:
            raise ValueError("iw link connection state is unavailable")
        associated = connected
        fields["wifi.associated"] = _observed(associated, "1", IW_SOURCE, now)
        fields["wifi.active"] = _observed(associated, "1", IW_SOURCE, now)
        if not associated:
            for name, unit in (
                ("wifi.ssid", "1"),
                ("wifi.ssid_display_fallback", "1"),
                ("wifi.bssid", "1"),
                ("wifi.frequency", "MHz"),
                ("wifi.channel", "1"),
                ("wifi.channel_width", "MHz"),
                ("wifi.band", "1"),
                ("wifi.rssi_measured", "dBm"),
                ("wifi.signal_quality", "%"),
                ("wifi.tx_association_rate", "Mbit/s"),
                ("wifi.rx_association_rate", "Mbit/s"),
                ("wifi.standard", "1"),
            ):
                fields[name] = _missing(
                    unit,
                    IW_SOURCE,
                    now,
                    "blocked",
                    "interface_disconnected",
                )
            if info.get("type") is not None:
                fields["wifi.interface_type"] = _observed(info["type"], "1", IW_SOURCE, now)
            return
        for source_name, target, unit in (
            ("bssid", "wifi.bssid", "1"),
            ("ssid", "wifi.ssid_display_fallback", "1"),
            ("frequency_mhz", "wifi.frequency", "MHz"),
            ("signal_dbm", "wifi.rssi_measured", "dBm"),
            ("tx_bitrate_mbps", "wifi.tx_association_rate", "Mbit/s"),
            ("rx_bitrate_mbps", "wifi.rx_association_rate", "Mbit/s"),
        ):
            if link.get(source_name) is not None:
                fields[target] = _observed(link[source_name], unit, IW_SOURCE, now)
        for source_name, target, unit in (
            ("channel", "wifi.channel", "1"),
            ("channel_width_mhz", "wifi.channel_width", "MHz"),
            ("frequency_mhz", "wifi.frequency", "MHz"),
            ("type", "wifi.interface_type", "1"),
        ):
            if info.get(source_name) is not None:
                fields[target] = _observed(info[source_name], unit, IW_SOURCE, now)
        frequency = link.get("frequency_mhz") or info.get("frequency_mhz")
        if isinstance(frequency, int):
            channel = frequency_to_channel(frequency)
            if channel is not None:
                fields.setdefault(
                    "wifi.channel",
                    _observed(channel.channel, "1", DERIVED_SOURCE, now, confidence="medium"),
                )
                fields["wifi.band"] = _observed(
                    channel.band, "1", DERIVED_SOURCE, now, confidence="medium"
                )
        standard = infer_phy_standard(link.get("phy_markers"))
        if standard:
            fields["wifi.standard"] = NormalizedObservation(
                value=standard,
                unit="1",
                source=DERIVED_SOURCE,
                availability="estimated",
                confidence="medium",
                reason=ObservationReason(
                    code="unknown", detail="Inferred from iw association rate markers"
                ),
                collected_at=now,
            )

    @staticmethod
    def _merge_iw_info(
        fields: dict[str, NormalizedObservation],
        info: dict[str, object],
        now: datetime,
    ) -> None:
        for source_name, target, unit in (
            ("channel", "wifi.channel", "1"),
            ("channel_width_mhz", "wifi.channel_width", "MHz"),
            ("frequency_mhz", "wifi.frequency", "MHz"),
            ("type", "wifi.interface_type", "1"),
        ):
            if info.get(source_name) is not None:
                fields.setdefault(
                    target,
                    _observed(info[source_name], unit, IW_SOURCE, now),
                )
        frequency = info.get("frequency_mhz")
        if isinstance(frequency, int):
            channel = frequency_to_channel(frequency)
            if channel is not None:
                fields.setdefault(
                    "wifi.channel",
                    _observed(
                        channel.channel,
                        "1",
                        DERIVED_SOURCE,
                        now,
                        confidence="medium",
                    ),
                )
                fields.setdefault(
                    "wifi.band",
                    _observed(
                        channel.band,
                        "1",
                        DERIVED_SOURCE,
                        now,
                        confidence="medium",
                    ),
                )

    def _complete_wifi_absence(
        self, fields: dict[str, NormalizedObservation], now: datetime
    ) -> None:
        associated = fields.get("wifi.associated")
        disconnected = associated is not None and associated.value is False
        code = "blocked" if disconnected else "provider_unavailable"
        detail = "interface_disconnected" if disconnected else "field unavailable from providers"
        for name, unit in (
            ("wifi.ssid", "1"),
            ("wifi.bssid", "1"),
            ("wifi.frequency", "MHz"),
            ("wifi.channel", "1"),
            ("wifi.channel_width", "MHz"),
            ("wifi.band", "1"),
            ("wifi.rssi_measured", "dBm"),
            ("wifi.tx_association_rate", "Mbit/s"),
            ("wifi.rx_association_rate", "Mbit/s"),
            ("wifi.standard", "1"),
        ):
            fields.setdefault(name, _missing(unit, IW_SOURCE, now, code, detail))

    def _sysfs_anchor(self) -> Path:
        root = self.sysfs_root.absolute()
        if root.name == "net" and root.parent.name == "class":
            return root.parent.parent
        return root.parent

    @staticmethod
    def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
        return (left.st_dev, left.st_ino, stat.S_IFMT(left.st_mode)) == (
            right.st_dev,
            right.st_ino,
            stat.S_IFMT(right.st_mode),
        )

    def _anchored_target(self, path: Path, *, require_directory: bool) -> Path:
        try:
            anchor = self._sysfs_anchor().resolve(strict=True)
            target = path.resolve(strict=True)
            target.relative_to(anchor)
        except (OSError, ValueError) as error:
            raise LinuxProviderError(
                "linux-sysfs",
                "invalid_output",
                "sysfs entry escaped its trusted tree or disappeared",
            ) from error
        metadata = target.stat()
        if require_directory and not stat.S_ISDIR(metadata.st_mode):
            raise LinuxProviderError(
                "linux-sysfs",
                "invalid_output",
                "sysfs interface target is not a directory",
            )
        return target

    def _discover_sysfs_interfaces(self, deadline: float) -> list[str]:
        root = self.sysfs_root.absolute()
        try:
            before = root.lstat()
        except OSError as error:
            raise LinuxProviderError(
                "linux-sysfs", "unavailable", "sysfs interface root is unavailable"
            ) from error
        if not stat.S_ISDIR(before.st_mode):
            raise LinuxProviderError(
                "linux-sysfs", "invalid_output", "sysfs interface root is not a directory"
            )
        discovered: list[os.DirEntry[str]] = []
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    if time.monotonic() >= deadline:
                        raise LinuxProviderError(
                            "linux-sysfs", "transient_failure", "sysfs discovery timed out"
                        )
                    if len(discovered) >= _MAX_SYSFS_INTERFACES:
                        raise LinuxProviderError(
                            "linux-sysfs", "invalid_output", "sysfs interface limit exceeded"
                        )
                    discovered.append(entry)
        except LinuxProviderError:
            raise
        except OSError as error:
            raise LinuxProviderError(
                "linux-sysfs", "unavailable", "sysfs interface root cannot be enumerated"
            ) from error
        names: list[str] = []
        for entry in sorted(discovered, key=lambda item: item.name):
            if time.monotonic() >= deadline:
                raise LinuxProviderError(
                    "linux-sysfs", "transient_failure", "sysfs discovery timed out"
                )
            try:
                name = validate_interface_name(entry.name)
                entry_metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(entry_metadata.st_mode):
                    target = self._anchored_target(Path(entry.path), require_directory=True)
                    followed = entry.stat(follow_symlinks=True)
                    if not self._same_identity(followed, target.stat()):
                        raise LinuxProviderError(
                            "linux-sysfs",
                            "invalid_output",
                            "sysfs interface identity changed during discovery",
                        )
                elif not stat.S_ISDIR(entry_metadata.st_mode):
                    continue
            except (OSError, ValueError, LinuxProviderError):
                continue
            names.append(name)
        try:
            after = root.lstat()
        except OSError as error:
            raise LinuxProviderError(
                "linux-sysfs", "transient_failure", "sysfs root disappeared"
            ) from error
        if not self._same_identity(before, after):
            raise LinuxProviderError(
                "linux-sysfs", "transient_failure", "sysfs root identity changed"
            )
        return names

    @staticmethod
    def _read_sysfs_attribute(path: Path) -> str:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise LinuxProviderError(
                "linux-sysfs", "invalid_output", "sysfs attribute is not a regular file"
            )
        with path.open("rb") as handle:
            raw = handle.read(_MAX_SYSFS_ATTRIBUTE_BYTES + 1)
        if len(raw) > _MAX_SYSFS_ATTRIBUTE_BYTES:
            raise LinuxProviderError(
                "linux-sysfs", "invalid_output", "sysfs attribute exceeded its size limit"
            )
        try:
            return raw.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise LinuxProviderError(
                "linux-sysfs", "invalid_output", "sysfs attribute was not ASCII"
            ) from error

    def _sysfs_fields(
        self, interface: str, now: datetime, deadline: float
    ) -> dict[str, NormalizedObservation]:
        self._remaining(deadline)
        validate_interface_name(interface)
        result: dict[str, NormalizedObservation] = {}
        entry = self.sysfs_root.absolute() / interface
        root = self._anchored_target(entry, require_directory=True)
        before = root.stat()
        device = root / "device"
        try:
            device.lstat()
        except FileNotFoundError:
            physical = False
            device_target: Path | None = None
        else:
            physical = True
            device_target = self._anchored_target(device, require_directory=True)
        result["interface.physical"] = _observed(physical, "1", SYSFS_SOURCE, now)
        result["interface.virtual"] = _observed(not physical, "1", SYSFS_SOURCE, now)
        if device_target is not None:
            self._remaining(deadline)
            driver = device_target / "driver"
            try:
                driver.lstat()
            except FileNotFoundError:
                pass
            else:
                driver_target = self._anchored_target(driver, require_directory=True)
                result["interface.driver"] = _observed(driver_target.name, "1", SYSFS_SOURCE, now)
            identifiers: dict[str, str] = {}
            for filename in (
                "vendor",
                "device",
                "subsystem_vendor",
                "subsystem_device",
                "modalias",
            ):
                self._remaining(deadline)
                path = device_target / filename
                try:
                    identifiers[filename] = self._read_sysfs_attribute(path)
                except FileNotFoundError:
                    continue
            if identifiers:
                result["interface.chipset_identifiers"] = _observed(
                    identifiers, "1", SYSFS_SOURCE, now
                )
        self._remaining(deadline)
        after = root.stat()
        if not self._same_identity(before, after):
            raise LinuxProviderError(
                "linux-sysfs", "transient_failure", "sysfs interface identity changed"
            )
        return result

    def _resolver_servers(self, errors: dict[str, ObservationReason]) -> list[str] | None:
        try:
            raw = self.resolv_conf.read_bytes()
            if len(raw) > 65_536:
                raise LinuxProviderError("resolv-conf", "invalid_output", "resolver file too large")
            return parse_resolv_conf(raw)
        except Exception as error:
            errors["resolv_conf"] = _provider_reason(error)
            return None

    def _host_fields(
        self, nm: NetworkManagerSnapshot | None, now: datetime
    ) -> dict[str, NormalizedObservation]:
        fields = {
            "system.networkmanager.installed": _observed(
                self.network_manager_installed, "1", DERIVED_SOURCE, now
            ),
            "system.networkmanager.available": _observed(nm is not None, "1", DERIVED_SOURCE, now),
            "system.systemd.available": _observed(self.systemd_available, "1", DERIVED_SOURCE, now),
        }
        if nm is not None:
            if nm.state is None:
                fields["system.networkmanager.state"] = _missing(
                    "1", NM_SOURCE, now, "unknown", "invalid_output: State was absent"
                )
            else:
                fields["system.networkmanager.state"] = _observed(nm.state, "1", NM_SOURCE, now)
            if nm.version is None:
                fields["system.networkmanager.version"] = _missing(
                    "1", NM_SOURCE, now, "unknown", "invalid_output: Version was absent"
                )
            else:
                fields["system.networkmanager.version"] = _observed(nm.version, "1", NM_SOURCE, now)
        elif self.network_manager_installed:
            fields["system.networkmanager.state"] = _missing(
                "1",
                NM_SOURCE,
                now,
                "provider_unavailable",
                "installed_but_inactive_or_dbus_unavailable",
            )
        for name, available in sorted(self.tools.items()):
            fields[f"tool.{name}.installed"] = _observed(available, "1", DERIVED_SOURCE, now)
        return fields

    async def scan(self, interface_guid: str, cancellation: CancellationToken) -> WifiScanSnapshot:
        del cancellation
        now = datetime.now(UTC)
        return WifiScanSnapshot(
            interface_guid=interface_guid,
            started_at=now,
            finished_at=now,
            entries=[],
            reason=ObservationReason(
                code="not_implemented",
                detail=(
                    "Linux active scan is not exposed until a non-disruptive policy is contracted"
                ),
            ),
        )

    def capability_overrides(self) -> dict[str, dict[str, object]]:
        network_manager = self._readiness["networkmanager"]
        iw = self._readiness["iw"]
        provider_available = network_manager.available or iw.available
        provider_implementations: list[dict[str, str]] = []
        if network_manager.available:
            provider_implementations.append(
                {
                    "provider_id": "linux-networkmanager",
                    "provider_version": "1.0.0",
                    "method": "dbus",
                }
            )
        if iw.available:
            provider_implementations.append(
                {
                    "provider_id": "linux-iw",
                    "provider_version": "1.0.0",
                    "method": "nl80211",
                }
            )
        failures = (network_manager, iw)
        failure_state = next(
            (
                priority
                for priority in (
                    "permission_denied",
                    "transient_failure",
                    "provider_failed",
                    "unsupported",
                    "command_missing",
                    "installed",
                )
                if any(state.state == priority for state in failures)
            ),
            "provider_failed",
        )
        reason_code = {
            "permission_denied": "permission_denied",
            "unsupported": "not_exposed_by_platform",
        }.get(failure_state, "provider_unavailable")
        provider_reason = (
            None
            if provider_available
            else {
                "code": reason_code,
                "detail": failure_state,
            }
        )
        any_installed = network_manager.installed or iw.installed
        common: dict[str, object] = {
            "technical_support": {
                "status": ("conditional" if provider_available or any_installed else "unknown"),
                "reason": provider_reason,
            },
            "implementation_status": {"status": "implemented", "reason": None},
            "permission_requirement": {
                "status": "conditional",
                "permissions": ["network.read"],
                "reason": None,
            },
            "user_interaction": {"status": "none", "reason": None},
            "background_execution": {"status": "continuous", "reason": None},
            "provider": {
                "status": "available" if provider_available else "unavailable",
                "implementations": provider_implementations,
                "reason": provider_reason,
            },
            "limitations": {
                "status": "known",
                "max_concurrency": 1,
                "reason": {
                    "code": "unknown",
                    "detail": (
                        "Fields depend on NetworkManager, kernel, driver and association state"
                    ),
                },
            },
        }
        scan = {
            **common,
            "implementation_status": {
                "status": "not_implemented",
                "reason": {"code": "not_implemented"},
            },
            "provider": {
                "status": "unavailable",
                "implementations": [],
                "reason": {"code": "provider_unavailable"},
            },
            "background_execution": {"status": "bounded", "reason": None},
        }
        return {
            "wifi.connection.read": common,
            "wifi.rssi.read": common,
            "wifi.scan": scan,
        }

    async def capability_overrides_async(self) -> dict[str, dict[str, object]]:
        await self.refresh_readiness()
        return self.capability_overrides()
