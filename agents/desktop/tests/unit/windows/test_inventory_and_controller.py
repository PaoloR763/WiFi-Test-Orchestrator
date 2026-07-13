from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.platforms.windows.inventory import WindowsInventoryCollector
from wto_desktop_agent.platforms.windows.native_wifi.errors import NativeWifiError
from wto_desktop_agent.platforms.windows.network_controller import WindowsNetworkController
from wto_desktop_agent.ports.platform import ProcessResult
from wto_desktop_agent.ports.plugins import CancellationToken

GUID = "11111111-1111-4111-8111-111111111111"
POWERSHELL_EMPTY = (
    b'{"schema_version":"1.0.0","powershell_edition":"Desktop",'
    b'"powershell_version":"5.1.0","adapters":[]}'
)


class FakeRunner:
    def __init__(self) -> None:
        self.commands: list[str] = []

    async def run(self, request: object, cancellation: object) -> ProcessResult:
        del cancellation
        command_id = request.command_id  # type: ignore[attr-defined]
        self.commands.append(command_id)
        if command_id == "windows.powershell.network_inventory":
            return ProcessResult(0, POWERSHELL_EMPTY, b"")
        return ProcessResult(0, b"", b"")


class EmptyIpHelper:
    def interfaces(self) -> list[dict[str, object]]:
        return []


class PrivacyDeniedNative:
    def interfaces(self) -> list[dict[str, object]]:
        return [{"guid": GUID, "description": "Wi-Fi", "state": 1}]

    def connection(self, guid: str) -> dict[str, object]:
        del guid
        raise NativeWifiError("WlanQueryInterface", 5, "access_denied")

    def interface_capability(self, guid: str) -> dict[str, object]:
        del guid
        return {"phy_types": [7]}


@pytest.mark.asyncio
async def test_privacy_denial_does_not_invoke_netsh() -> None:
    runner = FakeRunner()
    collector = WindowsInventoryCollector(
        PrivacyDeniedNative(), EmptyIpHelper(), runner  # type: ignore[arg-type]
    )
    snapshot = await collector.collect_inventory()
    assert "windows.netsh.wlan_show_interfaces" not in runner.commands
    wifi = snapshot.interfaces[0].fields
    assert wifi["wifi.bssid"].value is None
    assert wifi["wifi.bssid"].reason is not None
    assert wifi["wifi.bssid"].reason.code == "permission_denied"
    scan = await collector.scan(GUID, CancellationToken())
    assert scan.reason is not None
    assert scan.reason.code == "permission_denied"


class FakeScanNative:
    def __init__(self, state: int = 4) -> None:
        self.state = state
        self.scan_calls = 0

    def interface_state(self, guid: str) -> int:
        assert guid == GUID
        return self.state

    def scan(self, guid: str, timeout_seconds: float) -> None:
        assert guid == GUID
        assert timeout_seconds > 0
        self.scan_calls += 1

    def bss_entries(self, guid: str) -> list[dict[str, object]]:
        assert guid == GUID
        return [
            {
                "ssid_bytes": b"lab",
                "ssid_display": "lab",
                "bssid": "00:11:22:33:44:55",
                "phy_type": 11,
                "rssi_dbm": -70,
                "signal_quality": 50,
                "frequency_khz": 5_955_000,
            },
            {
                "ssid_bytes": b"lab",
                "ssid_display": "lab",
                "bssid": "00:11:22:33:44:55",
                "phy_type": 11,
                "rssi_dbm": -40,
                "signal_quality": 80,
                "frequency_khz": 5_955_000,
            },
            {
                "ssid_bytes": b"",
                "ssid_display": None,
                "bssid": "00:11:22:33:44:66",
                "phy_type": 7,
                "rssi_dbm": -60,
                "signal_quality": 60,
                "frequency_khz": 2_412_000,
            },
        ]


@pytest.mark.asyncio
async def test_scan_deduplicates_bssid_preserves_hidden_and_enforces_cooldown() -> None:
    native = FakeScanNative()
    collector = WindowsInventoryCollector(
        native, EmptyIpHelper(), FakeRunner(), scan_cooldown_seconds=60
    )
    result = await collector.scan(GUID, CancellationToken())
    assert len(result.entries) == 2
    visible = next(item for item in result.entries if item.bssid.endswith("55"))
    assert visible.fields["wifi.rssi_measured"].value == -40
    assert visible.fields["wifi.band"].value == "6GHz"
    hidden = next(item for item in result.entries if item.bssid.endswith("66"))
    assert hidden.fields["wifi.ssid"].value is None
    assert hidden.fields["wifi.ssid"].reason is not None
    repeated = await collector.scan(GUID, CancellationToken())
    assert repeated.reason is not None
    assert "cooldown" in (repeated.reason.detail or "")
    assert native.scan_calls == 1


@pytest.mark.asyncio
async def test_disabled_adapter_does_not_start_scan() -> None:
    native = FakeScanNative(state=0)
    collector = WindowsInventoryCollector(native, EmptyIpHelper(), FakeRunner())
    result = await collector.scan(GUID, CancellationToken())
    assert result.reason is not None
    assert "disabled" in (result.reason.detail or "")
    assert native.scan_calls == 0


@pytest.mark.asyncio
async def test_only_one_concurrent_scan_runs_per_guid() -> None:
    gate = asyncio.Event()

    class BlockingNative(FakeScanNative):
        def scan(self, guid: str, timeout_seconds: float) -> None:
            super().scan(guid, timeout_seconds)
            import time

            time.sleep(0.1)

    native = BlockingNative()
    collector = WindowsInventoryCollector(native, EmptyIpHelper(), FakeRunner())
    first = asyncio.create_task(collector.scan(GUID, CancellationToken()))
    await asyncio.sleep(0.02)
    second = await collector.scan(GUID, CancellationToken())
    gate.set()
    await first
    assert second.reason is not None
    assert "already active" in (second.reason.detail or "")
    assert native.scan_calls == 1


class FakeNativeControl:
    def __init__(self) -> None:
        self.current: str | None = "OldProfile"
        self.calls: list[tuple[str, str | None]] = []

    def profiles(self, guid: str) -> list[str]:
        assert guid == GUID
        return ["OldProfile", "AllowedProfile", "NotAllowed"]

    def connection(self, guid: str) -> dict[str, object]:
        assert guid == GUID
        if self.current is None:
            raise NativeWifiError("WlanQueryInterface", 5023, "invalid_state")
        return {"profile_name": self.current}

    def connect(self, guid: str, profile: str) -> None:
        assert guid == GUID
        self.calls.append(("connect", profile))
        self.current = profile

    def disconnect(self, guid: str) -> None:
        assert guid == GUID
        self.calls.append(("disconnect", None))
        self.current = None


@pytest.mark.asyncio
async def test_network_controller_journals_before_effect_and_is_idempotent(
    tmp_path: Path,
) -> None:
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    store.initialize()
    native = FakeNativeControl()
    controller = WindowsNetworkController(
        native,
        object(),
        store,
        allowed_interface_guids=[GUID],
        allowed_profiles=["OldProfile", "AllowedProfile"],
        enabled=True,
        administrator_check=lambda: True,
    )
    key = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    result = await controller.connect(
        interface_guid=GUID,
        profile_name="AllowedProfile",
        idempotency_key=key,
        confirmed=True,
        timeout_seconds=1.0,
        cancellation=CancellationToken(),
    )
    assert result["state"] == "completed"
    assert store.rows("windows_network_operations")[0]["previous_profile"] == "OldProfile"
    repeated = await controller.connect(
        interface_guid=GUID,
        profile_name="AllowedProfile",
        idempotency_key=key,
        confirmed=True,
        timeout_seconds=1.0,
        cancellation=CancellationToken(),
    )
    assert repeated["state"] == "completed"
    assert native.calls == [("connect", "AllowedProfile")]


@pytest.mark.asyncio
async def test_network_controller_requires_allowlist_and_confirmation(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    store.initialize()
    controller = WindowsNetworkController(
        FakeNativeControl(),
        object(),
        store,
        allowed_interface_guids=[GUID],
        allowed_profiles=["AllowedProfile"],
        enabled=True,
        administrator_check=lambda: True,
    )
    with pytest.raises(PermissionError, match="confirmation"):
        controller.list_profiles(GUID, confirmed=False)
    assert controller.list_profiles(GUID, confirmed=True) == ["AllowedProfile"]
    with pytest.raises(PermissionError, match="confirmation"):
        await controller.disconnect(
            interface_guid=GUID,
            idempotency_key="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            confirmed=False,
            timeout_seconds=1.0,
            cancellation=CancellationToken(),
        )
