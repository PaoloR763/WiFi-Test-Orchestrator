from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AgentSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    environment: Literal["production", "development", "test"] = "production"
    server_url: str
    state_dir: Path
    artifacts_dir: Path | None = None
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
    wifi_scan_cooldown_seconds: float = Field(default=60.0, ge=10.0, le=3600.0)
    wifi_scan_timeout_seconds: float = Field(default=8.0, ge=4.0, le=60.0)
    allow_local_wifi_control: bool = False
    allow_in_memory_secret_store: bool = False
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
