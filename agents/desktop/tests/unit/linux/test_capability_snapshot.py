from __future__ import annotations

import asyncio
import subprocess
import threading
from pathlib import Path

import pytest

from wto_desktop_agent.application.capabilities import CapabilityRegistry
from wto_desktop_agent.config import AgentSettings
from wto_desktop_agent.platforms.linux.capability_manifest import (
    linux_capability_overrides,
)
from wto_desktop_agent.platforms.linux.capture import UnavailableControlPlaneAuthorization
from wto_desktop_agent.platforms.linux.service_manager import LinuxServiceManager
from wto_desktop_agent.platforms.linux.tooling import ToolStatus


class _CountingServiceManager(LinuxServiceManager):
    def __init__(
        self,
        tmp_path: Path,
        clock: list[float],
        *,
        value: str = "active",
        entered: threading.Event | None = None,
        release: threading.Event | None = None,
    ) -> None:
        super().__init__(
            "endpoint",
            tmp_path,
            status_ttl_seconds=5.0,
            monotonic=lambda: clock[0],
        )
        self.value = value
        self.calls = 0
        self.entered = entered
        self.release = release

    def _query_status(self) -> str:
        self.calls += 1
        if self.entered is not None:
            self.entered.set()
        if self.release is not None:
            self.release.wait(2.0)
        return self.value


class _SyncPlatform:
    platform_id = "linux"

    def __init__(self, manager: _CountingServiceManager) -> None:
        self.manager = manager
        self.calls = 0
        self.snapshot: dict[str, dict[str, object]] = {}

    def capability_overrides(self) -> dict[str, dict[str, object]]:
        self.calls += 1
        self.manager.status()
        return self.snapshot


class _AsyncPlatform(_SyncPlatform):
    async def capability_overrides_async(self) -> dict[str, dict[str, object]]:
        self.calls += 1
        await self.manager.status_async()
        return self.snapshot


def test_registry_uses_one_immutable_override_snapshot_for_all_15_entries(tmp_path: Path) -> None:
    clock = [10.0]
    manager = _CountingServiceManager(tmp_path, clock)
    platform = _SyncPlatform(manager)
    platform.snapshot = {
        "wifi.connection.read": {
            "provider": {
                "status": "available",
                "implementations": [],
                "reason": None,
            }
        }
    }
    entries = CapabilityRegistry(platform).entries()  # type: ignore[arg-type]
    platform.snapshot["wifi.connection.read"]["provider"] = {"status": "unavailable"}

    assert len(entries) == 15
    assert platform.calls == 1
    assert manager.calls == 1
    connection = next(item for item in entries if item["id"] == "wifi.connection.read")
    assert connection["provider"]["status"] == "available"  # type: ignore[index]


def test_systemd_status_ttl_reuse_expiry_and_explicit_invalidation(tmp_path: Path) -> None:
    clock = [10.0]
    manager = _CountingServiceManager(tmp_path, clock)
    assert manager.status() == "active"
    assert manager.status() == "active"
    assert manager.calls == 1
    clock[0] = 15.1
    assert manager.status() == "active"
    assert manager.calls == 2
    manager.invalidate_status()
    assert manager.status() == "active"
    assert manager.calls == 3


def test_productive_systemd_status_uses_one_subprocess_per_ttl_miss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [10.0]
    manager = LinuxServiceManager(
        "endpoint", tmp_path, status_ttl_seconds=5.0, monotonic=lambda: clock[0]
    )
    manager._systemctl = Path("/usr/bin/systemctl")
    calls: list[tuple[str, ...]] = []
    real_is_dir = Path.is_dir

    def is_dir(path: Path) -> bool:
        if path == Path("/run/systemd/system"):
            return True
        return real_is_dir(path)

    def run(*arguments: str) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        return subprocess.CompletedProcess(
            ["systemctl", *arguments],
            0,
            stdout="LoadState=loaded\nActiveState=active\n",
            stderr="",
        )

    monkeypatch.setattr(Path, "is_dir", is_dir)
    monkeypatch.setattr(manager, "_run", run)
    assert manager.status() == "active"
    assert manager.status() == "active"
    assert len(calls) == 1
    assert calls[0].count("--property=LoadState") == 1
    assert calls[0].count("--property=ActiveState") == 1


def test_systemd_failure_is_cached_and_does_not_create_a_capability_storm(tmp_path: Path) -> None:
    clock = [10.0]
    manager = _CountingServiceManager(tmp_path, clock, value="unknown")
    platform = _SyncPlatform(manager)
    registry = CapabilityRegistry(platform)  # type: ignore[arg-type]
    registry.entries()
    registry.entries()
    assert platform.calls == 2
    assert manager.calls == 1


@pytest.mark.asyncio
async def test_async_registry_keeps_event_loop_progressing_during_systemd_query(
    tmp_path: Path,
) -> None:
    clock = [10.0]
    entered = threading.Event()
    release = threading.Event()
    manager = _CountingServiceManager(
        tmp_path,
        clock,
        entered=entered,
        release=release,
    )
    platform = _AsyncPlatform(manager)
    registry = CapabilityRegistry(platform)  # type: ignore[arg-type]
    task = asyncio.create_task(registry.entries_async())
    assert await asyncio.to_thread(entered.wait, 0.5)
    await asyncio.sleep(0.03)
    assert not task.done()
    release.set()
    entries = await task
    assert len(entries) == 15
    assert manager.calls == 1


def _tool(name: str) -> ToolStatus:
    return ToolStatus(name, None, False, False, "missing", False, reason="command_missing")


@pytest.mark.parametrize("service_state", ["unknown", "unavailable"])
def test_unknown_or_unavailable_systemd_state_is_unavailable_not_installed(
    tmp_path: Path, service_state: str
) -> None:
    settings = AgentSettings(
        environment="test",
        server_url="http://testserver",
        state_dir=tmp_path,
    )
    overrides = linux_capability_overrides(
        settings,
        service_state=service_state,
        dumpcap=_tool("dumpcap"),
        flent=_tool("flent"),
        netperf=_tool("netperf"),
        tcpreplay=_tool("tcpreplay"),
        monitor_interfaces=frozenset(),
        effective_capabilities=frozenset(),
        agent_id=None,
        authorization=UnavailableControlPlaneAuthorization(),
    )
    background = overrides["execution.background.continuous"]
    assert background["provider"]["status"] == "unavailable"  # type: ignore[index]
    assert background["background_execution"]["status"] == "deferred"  # type: ignore[index]
