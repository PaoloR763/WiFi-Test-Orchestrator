from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from wto_desktop_agent.application.capabilities import CapabilityRegistry
from wto_desktop_agent.config import AgentSettings
from wto_desktop_agent.domain.errors import SecureStoreUnavailableError
from wto_desktop_agent.infrastructure.contracts import contract_root, validate_contract
from wto_desktop_agent.platforms.linux.capability_manifest import (
    linux_capability_overrides,
)
from wto_desktop_agent.platforms.linux.capture import (
    CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE,
    MONITOR_CAPTURE_CAPABILITY,
    PCAP_REPLAY_CAPABILITY,
    PrivilegedAuthorizationDecision,
    UnavailableControlPlaneAuthorization,
)
from wto_desktop_agent.platforms.linux.secret_store import (
    LinuxEncryptedFileSecretStore,
)
from wto_desktop_agent.platforms.linux.tooling import (
    ToolStatus,
    parse_file_capabilities,
)

AGENT_ID = "40000000-0000-4000-8000-000000000001"


class StaticCapabilityGrant:
    def authorize(
        self, *, agent_id: str | None, capability_id: str
    ) -> PrivilegedAuthorizationDecision:
        allowed = agent_id == AGENT_ID and capability_id in {
            MONITOR_CAPTURE_CAPABILITY,
            PCAP_REPLAY_CAPABILITY,
        }
        return PrivilegedAuthorizationDecision(
            allowed,
            None if allowed else CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE,
        )


def _tool(name: str, ready: bool) -> ToolStatus:
    return ToolStatus(
        name=name,
        path=Path(f"/usr/bin/{name}") if ready else None,
        installed=ready,
        self_check=ready,
        access="allowed" if ready else "missing",
        secure=ready,
        version="1.0.0" if ready else None,
    )


def _settings(tmp_path: Path, **overrides: object) -> AgentSettings:
    values: dict[str, object] = {
        "environment": "test",
        "server_url": "http://testserver",
        "state_dir": tmp_path,
    }
    values.update(overrides)
    return AgentSettings.model_validate(values)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode semantics")
def test_encrypted_file_secret_store_round_trip_and_no_plaintext(
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)

    store.put("active.credential", "sensitive-value")

    assert store.get("active.credential") == "sensitive-value"
    files = list((tmp_path / "secrets").iterdir())
    assert all(path.stat().st_mode & 0o077 == 0 for path in files)
    assert all(b"sensitive-value" not in path.read_bytes() for path in files)
    store.delete("active.credential")
    assert store.get("active.credential") is None


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode semantics")
def test_secret_store_rejects_world_readable_or_group_writable_paths(
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    store = LinuxEncryptedFileSecretStore(tmp_path)
    store.put("active", "value")
    secret = next(
        path for path in (tmp_path / "secrets").iterdir() if path.name.startswith("secret-")
    )
    os.chmod(secret, 0o640)

    with pytest.raises(SecureStoreUnavailableError):
        store.get("active")

    os.chmod(tmp_path / "secrets", 0o720)
    assert store.doctor().status == "BLOCKED"


def test_endpoint_never_promotes_monitor_or_replay(tmp_path: Path) -> None:
    settings = _settings(tmp_path, node_role="endpoint")
    overrides = linux_capability_overrides(
        settings,
        service_state="active",
        dumpcap=_tool("dumpcap", True),
        flent=_tool("flent", True),
        netperf=_tool("netperf", True),
        tcpreplay=_tool("tcpreplay", True),
        monitor_interfaces=frozenset({"wlan1"}),
        effective_capabilities=frozenset({"cap_net_admin", "cap_net_raw"}),
        tree_containment_ready=True,
        agent_id=AGENT_ID,
        authorization=StaticCapabilityGrant(),
    )

    assert overrides["capture.ieee80211.monitor"]["provider"]["status"] == "unavailable"  # type: ignore[index]
    assert overrides["traffic.pcap.replay"]["implementation_status"]["status"] == "excluded"  # type: ignore[index]


def test_dumpcap_file_capability_parser_is_fail_closed() -> None:
    assert parse_file_capabilities("/usr/bin/dumpcap cap_net_admin,cap_net_raw=eip") == frozenset(
        {"cap_net_admin", "cap_net_raw"}
    )
    assert parse_file_capabilities("") == frozenset()
    with pytest.raises(ValueError):
        parse_file_capabilities("/usr/bin/dumpcap unexpected-output")


def test_capture_flent_and_replay_require_role_policy_permissions_and_self_check(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "approved"
    settings = _settings(
        tmp_path,
        node_role="capture_node",
        capture_enabled=True,
        allowed_capture_interfaces=["wlan1"],
        allowed_capture_channels=[36],
        allowed_capture_frequencies_mhz=[5180],
        flent_enabled=True,
        flent_allowed_servers=["flent.lab.example"],
        tcpreplay_enabled=True,
        allowed_replay_interfaces=["lab0"],
        allowed_replay_scenarios=["lab.scenario"],
        replay_namespace="wto-lab",
        approved_replay_artifacts_dir=artifact,
        approved_replay_artifacts={"approved.pcap": "a" * 64},
    )
    overrides = linux_capability_overrides(
        settings,
        service_state="active",
        dumpcap=_tool("dumpcap", True),
        flent=_tool("flent", True),
        netperf=_tool("netperf", True),
        tcpreplay=_tool("tcpreplay", True),
        monitor_interfaces=frozenset({"wlan1"}),
        effective_capabilities=frozenset({"cap_net_admin", "cap_net_raw"}),
        tree_containment_ready=True,
        agent_id=AGENT_ID,
        authorization=StaticCapabilityGrant(),
    )

    assert overrides["capture.ip"]["provider"]["status"] == "unavailable"  # type: ignore[index]
    assert overrides["capture.ieee80211.monitor"]["provider"]["status"] == "available"  # type: ignore[index]
    assert overrides["traffic.latency_under_load"]["provider"]["status"] == "available"  # type: ignore[index]
    assert overrides["traffic.pcap.replay"]["provider"]["status"] == "available"  # type: ignore[index]

    without_containment = linux_capability_overrides(
        settings,
        service_state="active",
        dumpcap=_tool("dumpcap", True),
        flent=_tool("flent", True),
        netperf=_tool("netperf", True),
        tcpreplay=_tool("tcpreplay", True),
        monitor_interfaces=frozenset({"wlan1"}),
        effective_capabilities=frozenset({"cap_net_admin", "cap_net_raw"}),
        tree_containment_ready=False,
        agent_id=AGENT_ID,
        authorization=StaticCapabilityGrant(),
    )
    for capability_id in (
        "capture.ieee80211.monitor",
        "traffic.latency_under_load",
        "traffic.pcap.replay",
        "execution.background.continuous",
    ):
        assert without_containment[capability_id]["provider"]["status"] == "unavailable"  # type: ignore[index]

    denied = linux_capability_overrides(
        settings,
        service_state="inactive",
        dumpcap=_tool("dumpcap", False),
        flent=_tool("flent", False),
        netperf=_tool("netperf", False),
        tcpreplay=_tool("tcpreplay", False),
        monitor_interfaces=frozenset(),
        effective_capabilities=frozenset(),
        tree_containment_ready=True,
        agent_id=AGENT_ID,
        authorization=StaticCapabilityGrant(),
    )
    assert denied["capture.ip"]["provider"]["status"] == "unavailable"  # type: ignore[index]
    assert denied["capture.ieee80211.monitor"]["permission_requirement"]["status"] == "denied"  # type: ignore[index]
    assert denied["traffic.latency_under_load"]["provider"]["status"] == "unavailable"  # type: ignore[index]

    class LinuxManifestPlatform:
        platform_id = "linux"

        def capability_overrides(self) -> dict[str, dict[str, object]]:
            return overrides

    manifest = json.loads(
        (contract_root() / "examples" / "valid" / "capability-manifest-desktop.json").read_text(
            encoding="utf-8"
        )
    )
    manifest["platform"] = "linux"
    manifest["capabilities"] = CapabilityRegistry(
        LinuxManifestPlatform()  # type: ignore[arg-type]
    ).entries()
    validate_contract("capability-manifest.schema.json", manifest)


def test_local_role_dumpcap_and_capabilities_cannot_replace_control_plane_grant(
    tmp_path: Path,
) -> None:
    settings = _settings(
        tmp_path,
        node_role="capture_node",
        capture_enabled=True,
        allowed_capture_interfaces=["wlan1"],
        allowed_capture_channels=[36],
        allowed_capture_frequencies_mhz=[5180],
    )
    overrides = linux_capability_overrides(
        settings,
        service_state="active",
        dumpcap=_tool("dumpcap", True),
        flent=_tool("flent", False),
        netperf=_tool("netperf", False),
        tcpreplay=_tool("tcpreplay", True),
        monitor_interfaces=frozenset({"wlan1"}),
        effective_capabilities=frozenset({"cap_net_admin", "cap_net_raw"}),
        tree_containment_ready=True,
        agent_id=AGENT_ID,
        authorization=UnavailableControlPlaneAuthorization(),
    )

    monitor = overrides["capture.ieee80211.monitor"]
    assert monitor["provider"]["status"] == "unavailable"  # type: ignore[index]
    assert (
        monitor["technical_support"]["reason"]["detail"]  # type: ignore[index]
        == CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE
    )
    assert overrides["capture.ip"]["provider"]["status"] == "unavailable"  # type: ignore[index]


@pytest.mark.parametrize(
    "overrides",
    [
        {
            "node_role": "endpoint",
            "capture_enabled": True,
            "allowed_capture_interfaces": ["wlan1"],
        },
        {
            "node_role": "capture_node",
            "capture_enabled": True,
            "allowed_capture_interfaces": ["wlan1"],
            "protected_capture_interfaces": ["wlan1"],
        },
        {"node_role": "endpoint", "tcpreplay_enabled": True},
        {"flent_enabled": True},
    ],
)
def test_invalid_specialized_configuration_fails_closed(
    tmp_path: Path, overrides: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        _settings(tmp_path, **overrides)
