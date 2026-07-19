from __future__ import annotations

from wto_desktop_agent.config import AgentSettings
from wto_desktop_agent.platforms.linux.capture import (
    MONITOR_CAPTURE_CAPABILITY,
    PCAP_REPLAY_CAPABILITY,
    ControlPlaneAuthorization,
    privileged_capability_decision,
)
from wto_desktop_agent.platforms.linux.tooling import ToolStatus


def _reason(reason: str) -> dict[str, str]:
    if reason == "permission_denied":
        return {"code": "permission_denied"}
    if reason in {"provider_unavailable", "technical_self_check_failed"}:
        return {"code": "provider_unavailable", "detail": reason}
    return {"code": "policy_denied", "detail": reason}


def _unavailable(reason: str = "provider_unavailable") -> dict[str, object]:
    reason_value = _reason(reason)
    return {
        "technical_support": {"status": "conditional", "reason": reason_value},
        "implementation_status": {"status": "implemented", "reason": None},
        "permission_requirement": {
            "status": "required",
            "permissions": ["packet.capture"],
            "reason": {"code": "permission_missing"},
        },
        "user_interaction": {"status": "conditional", "reason": None},
        "background_execution": {"status": "bounded", "reason": None},
        "provider": {
            "status": "unavailable",
            "implementations": [],
            "reason": reason_value,
        },
        "limitations": {"status": "unknown", "reason": {"code": "unknown"}},
    }


def linux_capability_overrides(
    settings: AgentSettings,
    *,
    service_state: str,
    dumpcap: ToolStatus,
    flent: ToolStatus,
    netperf: ToolStatus,
    tcpreplay: ToolStatus,
    monitor_interfaces: frozenset[str],
    effective_capabilities: frozenset[str],
    tree_containment_ready: bool = False,
    agent_id: str | None,
    authorization: ControlPlaneAuthorization,
) -> dict[str, dict[str, object]]:
    specialized = settings.node_role in {"capture_node", "lab_node"}
    monitor_permissions = {"cap_net_admin", "cap_net_raw"}.issubset(effective_capabilities)
    capture = _unavailable("provider_unavailable")
    capture["implementation_status"] = {
        "status": "not_implemented",
        "reason": {"code": "not_implemented"},
    }
    capture["limitations"] = {
        "status": "known",
        "max_duration_seconds": settings.capture_max_duration_seconds,
        "max_payload_bytes": settings.capture_max_size_bytes,
        "max_concurrency": 1,
        "reason": None,
    }
    capture["provider"]["reason"] = {  # type: ignore[index]
        "code": "provider_unavailable",
        "detail": "monitor_radiotap_provider_does_not_implement_capture.ip",
    }
    monitor_decision = privileged_capability_decision(
        agent_id=agent_id,
        capability_id=MONITOR_CAPTURE_CAPABILITY,
        authorization=authorization,
        role_allowed=specialized,
        policy_enabled=settings.capture_enabled,
        provider_ready=dumpcap.ready,
        permissions_ready=monitor_permissions,
        allowlists_ready=bool(
            settings.allowed_capture_interfaces
            and settings.allowed_capture_channels
            and settings.allowed_capture_frequencies_mhz
            and settings.allowed_capture_widths_mhz
        ),
        technical_ready=bool(monitor_interfaces) and tree_containment_ready,
    )
    monitor = _unavailable(monitor_decision.reason or "policy_denied")
    if not specialized:
        monitor["implementation_status"] = {
            "status": "excluded",
            "reason": {"code": "not_applicable"},
        }
    monitor["limitations"] = capture["limitations"]
    if monitor_decision.allowed:
        monitor.update(
            {
                "technical_support": {"status": "supported", "reason": None},
                "permission_requirement": {
                    "status": "required",
                    "permissions": ["network.monitor", "network.channel_control"],
                    "reason": None,
                },
                "provider": {
                    "status": "available",
                    "implementations": [
                        {
                            "provider_id": "linux-dumpcap",
                            "provider_version": "1.0.0",
                            "method": "radiotap-frequency-lock",
                        }
                    ],
                    "reason": None,
                },
            }
        )
    elif monitor_decision.reason == "permission_denied":
        monitor["permission_requirement"] = {
            "status": "denied",
            "permissions": ["network.monitor", "network.channel_control"],
            "reason": {"code": "permission_denied"},
        }

    flent_ready = (
        settings.flent_enabled
        and bool(settings.flent_allowed_servers)
        and flent.ready
        and netperf.ready
        and tree_containment_ready
    )
    latency = {
        "technical_support": {
            "status": "supported" if flent_ready else "conditional",
            "reason": None if flent_ready else {"code": "provider_unavailable"},
        },
        "implementation_status": {
            "status": "partial" if flent_ready else "not_implemented",
            "reason": {"code": "not_implemented"},
        },
        "permission_requirement": {
            "status": "none" if flent_ready else "restricted",
            "permissions": [],
            "reason": None if flent_ready else {"code": "policy_denied"},
        },
        "user_interaction": {"status": "none", "reason": None},
        "background_execution": {"status": "bounded", "reason": None},
        "provider": {
            "status": "available" if flent_ready else "unavailable",
            "implementations": (
                [
                    {
                        "provider_id": "linux-flent",
                        "provider_version": "1.0.0",
                        "method": "rrul",
                    }
                ]
                if flent_ready
                else []
            ),
            "reason": None if flent_ready else {"code": "provider_unavailable"},
        },
        "limitations": {
            "status": "known",
            "max_duration_seconds": 300,
            "max_concurrency": 1,
            "reason": {
                "code": "unknown",
                "detail": "Server allowlist remains mandatory",
            },
        },
    }

    replay_decision = privileged_capability_decision(
        agent_id=agent_id,
        capability_id=PCAP_REPLAY_CAPABILITY,
        authorization=authorization,
        role_allowed=specialized,
        policy_enabled=settings.tcpreplay_enabled,
        provider_ready=tcpreplay.ready,
        permissions_ready=True,
        allowlists_ready=bool(
            settings.allowed_replay_interfaces
            and settings.allowed_replay_scenarios
            and settings.approved_replay_artifacts
        ),
        technical_ready=(
            tree_containment_ready
            and settings.replay_namespace is not None
            and settings.approved_replay_artifacts_dir is not None
        ),
    )
    replay_ready = replay_decision.allowed
    replay = _unavailable(replay_decision.reason or "policy_denied")
    replay["permission_requirement"] = {
        "status": "required",
        "permissions": ["traffic.replay", "network.namespace"],
        "reason": None if replay_ready else {"code": "policy_denied"},
    }
    replay["implementation_status"] = {
        "status": (
            "partial" if replay_ready else "excluded" if not specialized else "not_implemented"
        ),
        "reason": {"code": "not_implemented" if specialized else "not_applicable"},
    }
    replay["limitations"] = {
        "status": "known",
        "max_duration_seconds": settings.replay_max_duration_seconds,
        "max_throughput_bps": settings.replay_max_rate_mbps * 1_000_000,
        "max_payload_bytes": settings.replay_max_size_bytes,
        "max_concurrency": 1,
        "reason": {
            "code": "unknown",
            "detail": "Validation/simulation only in Phase 07",
        },
    }
    if replay_ready:
        replay["provider"] = {
            "status": "available",
            "implementations": [
                {
                    "provider_id": "linux-tcpreplay",
                    "provider_version": "1.0.0",
                    "method": "validated-simulation",
                }
            ],
            "reason": None,
        }

    unit_installed = service_state in {
        "active",
        "inactive",
        "failed",
        "activating",
        "deactivating",
    }
    installed = unit_installed and tree_containment_ready
    running = service_state == "active" and tree_containment_ready
    background = {
        "technical_support": {"status": "supported", "reason": None},
        "implementation_status": {"status": "implemented", "reason": None},
        "permission_requirement": {
            "status": "required",
            "permissions": ["service.install"],
            "reason": (
                None
                if installed
                else {
                    "code": (
                        "provider_unavailable"
                        if service_state in {"unknown", "unavailable"} or not tree_containment_ready
                        else "permission_missing"
                    )
                }
            ),
        },
        "user_interaction": {
            "status": "conditional",
            "reason": None if installed else {"code": "user_interaction_required"},
        },
        "background_execution": {
            "status": "continuous" if running else "deferred",
            "reason": None if running else {"code": "blocked", "detail": service_state},
        },
        "provider": {
            "status": "available" if installed else "unavailable",
            "implementations": (
                [
                    {
                        "provider_id": "linux-systemd",
                        "provider_version": "1.0.0",
                        "method": "system-service",
                    }
                ]
                if installed
                else []
            ),
            "reason": (
                None
                if installed
                else {
                    "code": "provider_unavailable",
                    "detail": (
                        "tree_containment_unavailable"
                        if not tree_containment_ready
                        else service_state
                    ),
                }
            ),
        },
        "limitations": {
            "status": "known",
            "max_concurrency": 1,
            "reason": {"code": "unknown", "detail": "One service instance per role"},
        },
    }
    return {
        "capture.ip": capture,
        "capture.ieee80211.monitor": monitor,
        "traffic.latency_under_load": latency,
        "traffic.pcap.replay": replay,
        "execution.background.continuous": background,
    }
