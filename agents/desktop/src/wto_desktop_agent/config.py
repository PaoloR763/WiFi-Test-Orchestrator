from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, model_validator

from wto_desktop_agent.domain.capture_policy import SUPPORTED_CAPTURE_WIDTHS_MHZ


class AgentSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    environment: Literal["production", "development", "test"] = "production"
    server_url: str
    state_dir: Path
    artifacts_dir: Path | None = None
    artifact_staging_timeout_seconds: float = Field(default=300.0, ge=1.0, le=3600.0)
    artifact_reconciliation_timeout_seconds: float = Field(default=30.0, ge=1.0, le=300.0)
    artifact_reconciliation_grace_seconds: float = Field(default=5.0, ge=0.1, le=30.0)
    artifact_retention_max_age_seconds: int = Field(default=2_592_000, ge=0)
    artifact_retention_count: int = Field(default=1_000, ge=0, le=1_000_000)
    artifact_retention_bytes: int = Field(default=10_737_418_240, ge=0)
    artifact_prune_batch_limit: int = Field(default=100, ge=1, le=10_000)
    ca_bundle: Path | None = None
    request_timeout_seconds: float = Field(default=15.0, ge=1.0, le=120.0)
    heartbeat_interval_seconds: float = Field(default=30.0, ge=15.0, le=900.0)
    polling_interval_seconds: float = Field(default=5.0, ge=0.1, le=900.0)
    max_concurrency: int = Field(default=1, ge=1, le=32)
    shutdown_grace_seconds: float = Field(default=15.0, ge=0.1, le=300.0)
    backoff_initial_seconds: float = Field(default=1.0, ge=0.1, le=60.0)
    backoff_max_seconds: float = Field(default=60.0, ge=1.0, le=900.0)
    backoff_multiplier: float = Field(default=2.0, ge=1.0, le=10.0)
    backoff_jitter_ratio: float = Field(default=0.2, ge=0.0, le=1.0)
    allowed_plugins: frozenset[str] = frozenset({"protocol.contract_check"})
    allowed_interface_guids: frozenset[str] = frozenset()
    allowed_wifi_profiles: frozenset[str] = frozenset()
    windows_inventory_timeout_seconds: float = Field(default=30.0, ge=10.0, le=120.0)
    wifi_scan_cooldown_seconds: float = Field(default=60.0, ge=10.0, le=3600.0)
    wifi_scan_timeout_seconds: float = Field(default=8.0, ge=4.0, le=60.0)
    allow_local_wifi_control: bool = False
    allow_in_memory_secret_store: bool = False
    node_role: Literal["endpoint", "capture_node", "lab_node"] = "endpoint"
    linux_secret_backend: Literal["auto", "secret_service", "encrypted_file"] = (
        "secret_service"  # noqa: S105
    )
    linux_secret_service_total_timeout_seconds: float = Field(default=5.0, ge=0.25, le=30.0)
    linux_secret_service_operation_timeout_seconds: float = Field(default=2.0, ge=0.1, le=10.0)
    linux_inventory_timeout_seconds: float = Field(default=10.0, ge=2.0, le=60.0)
    capture_enabled: bool = False
    allowed_capture_interfaces: frozenset[str] = frozenset()
    protected_capture_interfaces: frozenset[str] = frozenset()
    allowed_capture_channels: frozenset[int] = frozenset()
    allowed_capture_frequencies_mhz: frozenset[int] = frozenset()
    allowed_capture_widths_mhz: frozenset[int] = frozenset({20})
    capture_max_duration_seconds: int = Field(default=300, ge=1, le=3600)
    capture_max_size_bytes: int = Field(default=104_857_600, ge=1024, le=1_073_741_824)
    flent_enabled: bool = False
    flent_allowed_servers: frozenset[str] = frozenset()
    tcpreplay_enabled: bool = False
    allowed_replay_interfaces: frozenset[str] = frozenset()
    allowed_replay_scenarios: frozenset[str] = frozenset()
    replay_namespace: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    approved_replay_artifacts_dir: Path | None = None
    approved_replay_artifacts: dict[str, str] = Field(default_factory=dict)
    replay_max_duration_seconds: int = Field(default=60, ge=1, le=600)
    replay_max_rate_mbps: int = Field(default=100, ge=1, le=10_000)
    replay_max_loops: int = Field(default=1, ge=1, le=100)
    replay_max_size_bytes: int = Field(default=104_857_600, ge=64, le=1_073_741_824)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @model_validator(mode="after")
    def validate_security(self) -> AgentSettings:
        parsed = urlparse(self.server_url)
        local_dev = self.environment in {"development", "test"} and parsed.hostname in {
            "localhost",
            "127.0.0.1",
            "testserver",
        }
        if parsed.scheme != "https" and not (parsed.scheme == "http" and local_dev):
            raise ValueError("server_url must use HTTPS outside explicit local development/test")
        if self.allow_in_memory_secret_store and self.environment not in {
            "development",
            "test",
        }:
            raise ValueError("InMemorySecretStore is forbidden outside development/test")
        if self.backoff_max_seconds < self.backoff_initial_seconds:
            raise ValueError("backoff_max_seconds must be >= backoff_initial_seconds")
        if (
            self.linux_secret_service_operation_timeout_seconds
            > self.linux_secret_service_total_timeout_seconds
        ):
            raise ValueError(
                "linux_secret_service_operation_timeout_seconds must be <= "
                "linux_secret_service_total_timeout_seconds"
            )
        if self.capture_enabled:
            if self.node_role not in {"capture_node", "lab_node"}:
                raise ValueError("capture_enabled requires capture_node or lab_node role")
            if not self.allowed_capture_interfaces:
                raise ValueError("capture_enabled requires an explicit interface allowlist")
            if not self.allowed_capture_channels or not self.allowed_capture_frequencies_mhz:
                raise ValueError("capture_enabled requires channel and frequency allowlists")
        if self.allowed_capture_interfaces & self.protected_capture_interfaces:
            raise ValueError("capture interfaces cannot also be protected connectivity interfaces")
        if any(channel < 1 or channel > 233 for channel in self.allowed_capture_channels):
            raise ValueError("allowed_capture_channels contains an invalid channel")
        if any(
            frequency < 2_400 or frequency > 71_000
            for frequency in self.allowed_capture_frequencies_mhz
        ):
            raise ValueError("allowed_capture_frequencies_mhz contains an invalid frequency")
        if not self.allowed_capture_widths_mhz.issubset(SUPPORTED_CAPTURE_WIDTHS_MHZ):
            raise ValueError("allowed_capture_widths_mhz contains an unsupported width")
        if self.flent_enabled and not self.flent_allowed_servers:
            raise ValueError("flent_enabled requires an explicit server allowlist")
        if self.tcpreplay_enabled:
            if self.node_role not in {"capture_node", "lab_node"}:
                raise ValueError("tcpreplay_enabled requires capture_node or lab_node role")
            if not self.allowed_replay_interfaces or not self.allowed_replay_scenarios:
                raise ValueError("tcpreplay requires explicit interface and scenario allowlists")
            if self.replay_namespace is None or self.approved_replay_artifacts_dir is None:
                raise ValueError("tcpreplay requires an isolated namespace and artifact root")
            if not self.approved_replay_artifacts:
                raise ValueError("tcpreplay requires approved artifact hashes")
            if any(
                not re.fullmatch(r"[0-9a-f]{64}", value)
                for value in self.approved_replay_artifacts.values()
            ):
                raise ValueError("approved replay artifact hashes must be lowercase SHA-256")
        return self

    @property
    def database_path(self) -> Path:
        return self.state_dir / "agent.sqlite3"

    @property
    def effective_artifacts_dir(self) -> Path:
        return self.artifacts_dir or self.state_dir / "artifacts"


_ENV_NAMES = {
    "WTO_AGENT_ENVIRONMENT": "environment",
    "WTO_AGENT_SERVER_URL": "server_url",
    "WTO_AGENT_STATE_DIR": "state_dir",
    "WTO_AGENT_ARTIFACTS_DIR": "artifacts_dir",
    "WTO_AGENT_CA_BUNDLE": "ca_bundle",
    "WTO_AGENT_REQUEST_TIMEOUT_SECONDS": "request_timeout_seconds",
    "WTO_AGENT_HEARTBEAT_INTERVAL_SECONDS": "heartbeat_interval_seconds",
    "WTO_AGENT_POLLING_INTERVAL_SECONDS": "polling_interval_seconds",
    "WTO_AGENT_MAX_CONCURRENCY": "max_concurrency",
    "WTO_AGENT_SHUTDOWN_GRACE_SECONDS": "shutdown_grace_seconds",
    "WTO_AGENT_WINDOWS_INVENTORY_TIMEOUT_SECONDS": "windows_inventory_timeout_seconds",
    "WTO_AGENT_LINUX_INVENTORY_TIMEOUT_SECONDS": "linux_inventory_timeout_seconds",
    "WTO_AGENT_LINUX_SECRET_BACKEND": "linux_secret_backend",
    "WTO_AGENT_LINUX_SECRET_SERVICE_TOTAL_TIMEOUT_SECONDS": (
        "linux_secret_service_total_timeout_seconds"
    ),
    "WTO_AGENT_LINUX_SECRET_SERVICE_OPERATION_TIMEOUT_SECONDS": (
        "linux_secret_service_operation_timeout_seconds"
    ),
    "WTO_AGENT_NODE_ROLE": "node_role",
    "WTO_AGENT_LOG_LEVEL": "log_level",
}


def load_settings(path: Path, overrides: dict[str, object] | None = None) -> AgentSettings:
    document = tomllib.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    unknown_sections = set(document) - {"agent"}
    if unknown_sections:
        raise ValueError(f"unknown TOML sections: {sorted(unknown_sections)}")
    data: dict[str, Any] = dict(document.get("agent", {}))
    for environment_name, field_name in _ENV_NAMES.items():
        value = os.environ.get(environment_name)
        if value is not None:
            data[field_name] = value
    if overrides:
        data.update({key: value for key, value in overrides.items() if value is not None})
    return AgentSettings.model_validate(data)
