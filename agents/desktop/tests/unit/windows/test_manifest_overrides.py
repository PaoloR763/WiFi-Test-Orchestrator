from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from wto_desktop_agent.application.capabilities import CapabilityRegistry
from wto_desktop_agent.infrastructure.contracts import validate_contract
from wto_desktop_agent.platforms.windows.capability_manifest import (
    background_continuous_override,
)
from wto_desktop_agent.platforms.windows.npcap import NpcapDetector, NpcapStatus

CANONICAL_CAPABILITY_IDS = {
    "wifi.connection.read",
    "wifi.scan",
    "wifi.rssi.read",
    "network.icmp.ping",
    "network.tcp.probe",
    "network.http.probe",
    "traffic.tcp.throughput",
    "traffic.udp.throughput",
    "traffic.http.download",
    "traffic.http.upload",
    "traffic.latency_under_load",
    "capture.ip",
    "capture.ieee80211.monitor",
    "traffic.pcap.replay",
    "execution.background.continuous",
}
CAPABILITY_DIMENSIONS = {
    "technical_support",
    "implementation_status",
    "permission_requirement",
    "user_interaction",
    "background_execution",
    "provider",
    "limitations",
}


class _WindowsOverrides:
    platform_id = "windows"

    def __init__(self, capture_status: NpcapStatus, service_state: str) -> None:
        self._capture_detector = _detector(capture_status)
        self._service_state = service_state

    def capability_overrides(self) -> dict[str, dict[str, object]]:
        result = self._capture_detector.capability_overrides()
        result["execution.background.continuous"] = background_continuous_override(
            self._service_state
        )
        return result


def _detector(status: NpcapStatus) -> NpcapDetector:
    detector = object.__new__(NpcapDetector)
    detector.status = status
    return detector


def _entries(*, capture_status: NpcapStatus, service_state: str) -> list[dict[str, object]]:
    platform = _WindowsOverrides(capture_status, service_state)
    return CapabilityRegistry(platform).entries()  # type: ignore[arg-type]


def _entry(entries: list[dict[str, object]], capability_id: str) -> dict[str, Any]:
    return next(item for item in entries if item["id"] == capability_id)  # type: ignore[return-value]


def _assert_contract_valid(entries: list[dict[str, object]]) -> None:
    payload = {
        "schema_version": "1.0.0",
        "manifest_id": "00000000-0000-4000-8000-000000000001",
        "manifest_sequence": 0,
        "agent_id": "00000000-0000-4000-8000-000000000002",
        "agent_version": "0.1.0",
        "platform": "windows",
        "platform_version": "10.0.26100",
        "protocol_version": "1.0.0",
        "capability_catalog_version": "1.0.0",
        "generated_at": "2026-07-12T12:00:00Z",
        "capabilities": entries,
    }
    validate_contract("capability-manifest.schema.json", payload)


@pytest.fixture
def unavailable_capture() -> NpcapStatus:
    return NpcapStatus(
        installed=False,
        service_status="not_installed",
        admin_only=None,
        dot11_support=None,
        version=None,
        dumpcap_path=None,
        dumpcap_version=None,
    )


@pytest.fixture
def detected_capture() -> NpcapStatus:
    return NpcapStatus(
        installed=True,
        service_status="running",
        admin_only=False,
        dot11_support=False,
        version="1.83.0.0",
        dumpcap_path=Path("dumpcap.exe"),
        dumpcap_version="4.6.0.0",
    )


@pytest.mark.parametrize("service_state", ["not_installed", "stopped", "running"])
def test_final_windows_manifest_has_canonical_shape_and_validates_contract(
    unavailable_capture: NpcapStatus,
    service_state: str,
) -> None:
    entries = _entries(capture_status=unavailable_capture, service_state=service_state)

    assert len(entries) == 15
    assert {str(item["id"]) for item in entries} == CANONICAL_CAPABILITY_IDS
    for item in entries:
        assert set(item) == {"id", "version", *CAPABILITY_DIMENSIONS}
    assert "availability_reason" not in json.dumps(entries)
    _assert_contract_valid(entries)


@pytest.mark.parametrize("provider_detected", [False, True])
def test_capture_ip_remains_planned_after_detector_override(
    unavailable_capture: NpcapStatus,
    detected_capture: NpcapStatus,
    provider_detected: bool,
) -> None:
    status = detected_capture if provider_detected else unavailable_capture
    entries = _entries(capture_status=status, service_state="not_installed")
    capture = _entry(entries, "capture.ip")

    assert capture["implementation_status"]["status"] == "planned"
    assert capture["implementation_status"]["status"] != "implemented"
    assert capture["technical_support"]["status"] == (
        "conditional" if provider_detected else "unknown"
    )
    assert capture["provider"]["status"] == ("available" if provider_detected else "unavailable")
    _assert_contract_valid(entries)


@pytest.mark.parametrize("provider_detected", [False, True])
def test_monitor_capture_cannot_be_promoted_by_runtime_detector(
    unavailable_capture: NpcapStatus,
    detected_capture: NpcapStatus,
    provider_detected: bool,
) -> None:
    status = detected_capture if provider_detected else unavailable_capture
    entries = _entries(capture_status=status, service_state="running")
    monitor = _entry(entries, "capture.ieee80211.monitor")

    if not provider_detected:
        assert monitor["technical_support"]["status"] == "unknown"
    assert monitor["implementation_status"]["status"] == "excluded"
    assert monitor["implementation_status"]["status"] not in {"implemented", "partial"}
    assert monitor["provider"]["status"] == "not_applicable"
    assert monitor["provider"]["implementations"] == []
    _assert_contract_valid(entries)


@pytest.mark.parametrize(
    ("service_state", "provider_status", "background_status", "has_runtime"),
    [
        ("not_installed", "unavailable", "deferred", False),
        ("stopped", "available", "deferred", True),
        ("running", "available", "continuous", True),
    ],
)
def test_background_service_final_states_are_coherent(
    unavailable_capture: NpcapStatus,
    service_state: str,
    provider_status: str,
    background_status: str,
    has_runtime: bool,
) -> None:
    entries = _entries(capture_status=unavailable_capture, service_state=service_state)
    background = _entry(entries, "execution.background.continuous")

    assert background["implementation_status"] == {"status": "implemented", "reason": None}
    assert background["provider"]["status"] == provider_status
    assert bool(background["provider"]["implementations"]) is has_runtime
    assert background["background_execution"]["status"] == background_status
    assert (background["background_execution"]["reason"] is None) is (
        background_status == "continuous"
    )
    assert background["permission_requirement"]["status"] == "required"
    assert background["permission_requirement"]["permissions"] == ["service.install"]
    assert (background["permission_requirement"]["reason"] is None) is has_runtime
    assert background["user_interaction"]["status"] == "conditional"
    assert (background["user_interaction"]["reason"] is None) is has_runtime
    _assert_contract_valid(entries)
