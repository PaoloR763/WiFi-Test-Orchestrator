from __future__ import annotations

import asyncio
import os
import stat
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from wto_desktop_agent.application.capabilities import CapabilityRegistry
from wto_desktop_agent.platforms.linux.errors import LinuxProviderError
from wto_desktop_agent.platforms.linux.inventory import (
    LinuxInventoryCollector,
    ProviderReadiness,
)
from wto_desktop_agent.platforms.linux.network_manager import (
    NetworkManagerDbusProvider,
    NetworkManagerSnapshot,
)
from wto_desktop_agent.platforms.linux.tooling import inspect_tool
from wto_desktop_agent.ports.platform import CommandRequest, ProcessResult
from wto_desktop_agent.ports.plugins import CancellationToken

FIXTURES = Path(__file__).parents[2] / "fixtures" / "linux"


class _StaticNetworkManager:
    def __init__(self, value: NetworkManagerSnapshot | BaseException) -> None:
        self.value = value

    async def collect(self) -> NetworkManagerSnapshot:
        if isinstance(self.value, BaseException):
            raise self.value
        return self.value


class _HangingNetworkManager:
    async def collect(self) -> NetworkManagerSnapshot:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


class _Runner:
    def __init__(self, values: dict[str, ProcessResult]) -> None:
        self.values = values
        self.calls: list[CommandRequest] = []

    async def run(self, request: CommandRequest, cancellation: CancellationToken) -> ProcessResult:
        del cancellation
        self.calls.append(request)
        return self.values[request.command_id]


def _snapshot() -> NetworkManagerSnapshot:
    return NetworkManagerSnapshot(
        version="1.46.0", state=70, interfaces=[], active_connections_status="complete"
    )


def _collector(
    tmp_path: Path,
    network_manager: Any,
    *,
    iw_result: ProcessResult | None = None,
    timeout: float = 0.2,
    iw_readiness: ProviderReadiness | None = None,
    include_iw_commands: bool = True,
) -> tuple[LinuxInventoryCollector, _Runner]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    values = {
        "linux.ip.address-json": ProcessResult(
            0, (FIXTURES / "ip" / "address.json").read_bytes(), b""
        ),
        "linux.ip.route-json": ProcessResult(
            0, (FIXTURES / "ip" / "routes.json").read_bytes(), b""
        ),
        "linux.ip.route6-json": ProcessResult(0, b"[]", b""),
        "linux.iw.dev": iw_result
        or ProcessResult(0, (FIXTURES / "iw" / "dev.txt").read_bytes(), b""),
        "linux.iw.link": ProcessResult(0, (FIXTURES / "iw" / "link.txt").read_bytes(), b""),
        "linux.iw.info": ProcessResult(0, (FIXTURES / "iw" / "info.txt").read_bytes(), b""),
        "linux.ethtool.driver": ProcessResult(
            0, (FIXTURES / "ethtool" / "driver.txt").read_bytes(), b""
        ),
    }
    runner = _Runner(values)
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 192.0.2.53\n", encoding="utf-8")
    sysfs = tmp_path / "sys"
    for name in ("eth0", "wlan0", "veth0"):
        (sysfs / name).mkdir(parents=True, exist_ok=True)
    commands = frozenset(values)
    if not include_iw_commands:
        commands = frozenset(item for item in commands if not item.startswith("linux.iw."))
    collector = LinuxInventoryCollector(
        network_manager,
        runner,
        commands=commands,
        tools={"ip": True, "iw": True, "ethtool": True},
        network_manager_installed=True,
        systemd_available=True,
        inventory_timeout_seconds=timeout,
        tool_readiness={"iw": iw_readiness or ProviderReadiness(True, "installed")},
        sysfs_root=sysfs,
        resolv_conf=resolv,
    )
    return collector, runner


class _ManifestPlatform:
    platform_id = "linux"

    def __init__(self, collector: LinuxInventoryCollector) -> None:
        self.collector = collector
        self.calls = 0

    def capability_overrides(self) -> dict[str, dict[str, object]]:
        self.calls += 1
        return self.collector.capability_overrides()


@pytest.mark.asyncio
async def test_manifest_availability_requires_successful_productive_readiness(
    tmp_path: Path,
) -> None:
    collector, _ = _collector(tmp_path, _StaticNetworkManager(_snapshot()))
    platform = _ManifestPlatform(collector)
    registry = CapabilityRegistry(platform)  # type: ignore[arg-type]

    initial = {entry["id"]: entry for entry in registry.entries()}
    assert initial["wifi.connection.read"]["provider"]["status"] == "unavailable"  # type: ignore[index]
    assert platform.calls == 1

    await collector.collect_inventory()
    measured = {entry["id"]: entry for entry in registry.entries()}
    connection = measured["wifi.connection.read"]
    assert connection["provider"]["status"] == "available"  # type: ignore[index]
    assert {
        item["provider_id"] for item in connection["provider"]["implementations"]  # type: ignore[index]
    } == {"linux-networkmanager", "linux-iw"}


@pytest.mark.asyncio
async def test_permission_denied_and_invalid_self_check_never_advertise_available(
    tmp_path: Path,
) -> None:
    denied = LinuxProviderError("networkmanager-dbus", "permission_denied", "controlled")
    collector, _ = _collector(
        tmp_path,
        _StaticNetworkManager(denied),
        iw_result=ProcessResult(1, b"", b"Operation not permitted"),
    )
    await collector.collect_inventory()
    connection = collector.capability_overrides()["wifi.connection.read"]
    assert connection["provider"]["status"] == "unavailable"  # type: ignore[index]
    assert connection["provider"]["reason"]["code"] == "permission_denied"  # type: ignore[index]

    invalid_root = tmp_path / "invalid"
    invalid_root.mkdir()
    invalid, _ = _collector(
        invalid_root,
        _StaticNetworkManager(
            LinuxProviderError("networkmanager-dbus", "unavailable", "controlled")
        ),
        iw_result=ProcessResult(0, b"\xff", b""),
    )
    await invalid.collect_inventory()
    failed = invalid.capability_overrides()["wifi.connection.read"]
    assert failed["provider"]["status"] == "unavailable"  # type: ignore[index]
    assert failed["provider"]["reason"]["detail"] == "provider_failed"  # type: ignore[index]


@pytest.mark.skipif(os.name != "posix", reason="execute permission semantics require POSIX")
def test_installed_but_non_executable_iw_is_not_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from wto_desktop_agent.platforms.linux import tooling

    iw = tmp_path / "iw"
    iw.write_text("not executable", encoding="utf-8")
    iw.chmod(0o600)
    real_lstat = Path.lstat

    def trusted_lstat(path: Path) -> os.stat_result:
        metadata = real_lstat(path)
        values = list(metadata)
        values[4] = tooling._ROOT_UID
        if not stat.S_ISLNK(metadata.st_mode):
            values[0] = metadata.st_mode & ~0o022
        return os.stat_result(values)

    monkeypatch.setattr(tooling, "_lstat", trusted_lstat)
    monkeypatch.setattr(tooling, "TRUSTED_EXECUTABLE_ROOTS", (tmp_path,))
    monkeypatch.setitem(tooling.TRUSTED_TOOL_CANDIDATES, "iw", (iw,))
    status = inspect_tool("iw")
    assert status.installed is True
    assert status.access == "denied"
    assert status.ready is False
    assert status.reason == "permission_denied"

    collector, _ = _collector(
        tmp_path / "collector",
        _StaticNetworkManager(
            LinuxProviderError("networkmanager-dbus", "unavailable", "controlled")
        ),
        iw_readiness=ProviderReadiness(True, "permission_denied", status.reason),
        include_iw_commands=False,
    )
    asyncio.run(collector.collect_inventory())
    connection = collector.capability_overrides()["wifi.connection.read"]
    assert connection["provider"]["status"] == "unavailable"  # type: ignore[index]
    assert connection["provider"]["reason"]["code"] == "permission_denied"  # type: ignore[index]


@pytest.mark.asyncio
async def test_networkmanager_total_timeout_keeps_cli_fallbacks_and_loop_progressing(
    tmp_path: Path,
) -> None:
    collector, runner = _collector(tmp_path, _HangingNetworkManager(), timeout=0.08)
    ticks = 0
    stop = asyncio.Event()

    async def ticker() -> None:
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            await asyncio.sleep(0.005)

    progress = asyncio.create_task(ticker())
    started = time.monotonic()
    try:
        snapshot = await collector.collect_inventory()
    finally:
        stop.set()
        await progress
    assert time.monotonic() - started < 0.4
    assert snapshot.source_errors["networkmanager"].detail.startswith("transient_failure")
    assert {call.command_id for call in runner.calls}.issuperset(
        {
            "linux.ip.address-json",
            "linux.ip.route-json",
            "linux.ip.route6-json",
            "linux.iw.dev",
        }
    )
    assert any(item.interface_key == "wlan0" for item in snapshot.interfaces)
    assert ticks >= 3


class _DbusProperties:
    def __init__(self, bus: _DbusBus) -> None:
        self.bus = bus

    async def call_get_all(self, interface: str) -> dict[str, object]:
        del interface
        if self.bus.stage == "property":
            await self.bus.block()
        if self.bus.stage == "disconnect":
            raise RuntimeError("D-Bus disconnected")
        return {"Version": "1.46.0", "State": 70, "ActiveConnections": []}


class _DbusManager:
    async def call_get_all_devices(self) -> list[str]:
        return []


class _DbusProxy:
    def __init__(self, bus: _DbusBus) -> None:
        self.bus = bus

    def get_interface(self, name: str) -> object:
        if name == "org.freedesktop.DBus.Properties":
            return _DbusProperties(self.bus)
        return _DbusManager()


class _DbusBus:
    def __init__(self, stage: str, entered: asyncio.Event, release: asyncio.Event) -> None:
        self.stage = stage
        self.entered = entered
        self.release = release
        self.disconnected = False

    async def block(self) -> None:
        self.entered.set()
        await self.release.wait()

    async def connect(self) -> _DbusBus:
        if self.stage == "connect":
            await self.block()
        return self

    async def introspect(self, service: str, path: str) -> object:
        del service, path
        if self.stage == "introspection":
            await self.block()
        return object()

    def get_proxy_object(self, service: str, path: str, introspection: object) -> _DbusProxy:
        del service, path, introspection
        return _DbusProxy(self)

    def disconnect(self) -> None:
        self.disconnected = True


def _install_dbus(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    entered: asyncio.Event,
    release: asyncio.Event,
) -> _DbusBus:
    from wto_desktop_agent.platforms.linux import network_manager as module

    bus = _DbusBus(stage, entered, release)
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
    return bus


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["connect", "introspection", "property"])
async def test_real_networkmanager_provider_bounds_every_dbus_stage(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    bus = _install_dbus(monkeypatch, stage, entered, release)
    provider = NetworkManagerDbusProvider(total_timeout_seconds=0.05)
    ticks = 0
    stop = asyncio.Event()

    async def ticker() -> None:
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            await asyncio.sleep(0.005)

    progress = asyncio.create_task(ticker())
    try:
        with pytest.raises(LinuxProviderError) as captured:
            await provider.collect()
    finally:
        release.set()
        stop.set()
        await progress
    assert entered.is_set()
    assert captured.value.kind == "transient_failure"
    assert bus.disconnected is True
    assert ticks >= 3


@pytest.mark.asyncio
async def test_networkmanager_disconnect_is_normalized_and_leaves_no_provider_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    bus = _install_dbus(monkeypatch, "disconnect", entered, release)
    provider = NetworkManagerDbusProvider(total_timeout_seconds=0.1)
    with pytest.raises(LinuxProviderError) as captured:
        await provider.collect()
    assert captured.value.kind == "transient_failure"
    assert bus.disconnected is True
    await asyncio.sleep(0)
    current = asyncio.current_task()
    assert all(task is current or task.done() for task in asyncio.all_tasks())
