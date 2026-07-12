from __future__ import annotations

from functools import lru_cache
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path
from typing import Literal
from urllib.parse import quote_plus

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Validated runtime configuration sourced only from the environment."""

    model_config = SettingsConfigDict(extra="ignore", env_prefix="WTO_")

    environment: Literal["development", "demo", "test", "production"] = "production"
    service_name: str = "backend"
    log_level: str = "INFO"
    demo_agent_ttl_seconds: int = Field(default=45, ge=10, le=300)
    postgres_host: str
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    postgres_db: str
    postgres_user: str
    postgres_password: str = Field(min_length=1)
    postgres_migration_user: str
    postgres_migration_password: str = Field(min_length=1)
    postgres_runtime_role: str = "wto_runtime"
    redis_host: str
    redis_port: int = Field(default=6379, ge=1, le=65535)
    redis_db: int = Field(default=0, ge=0, le=15)
    artifact_root: Path = Path("/var/lib/wto/artifacts")
    jwt_signing_key: SecretStr
    rate_limit_hmac_key: SecretStr
    audit_subject_hmac_key: SecretStr
    enrollment_token_hmac_key: SecretStr
    agent_credential_hmac_key: SecretStr
    secret_replay_encryption_key: SecretStr
    jwt_issuer: str = "wifi-test-orchestrator"
    jwt_audience: str = "wifi-test-orchestrator-api"
    access_token_minutes: int = Field(default=10, ge=1, le=30)
    refresh_absolute_days: int = Field(default=30, ge=1, le=90)
    refresh_inactivity_days: int = Field(default=7, ge=1, le=30)
    allowed_origin: str
    trusted_proxy_cidrs: str = "127.0.0.1/32"
    argon2_memory_cost: int = Field(default=65536, ge=65536, le=1048576)
    argon2_time_cost: int = Field(default=3, ge=3, le=10)
    argon2_parallelism: int = Field(default=1, ge=1, le=8)
    login_ip_limit: int = Field(default=20, ge=1, le=1000)
    login_identifier_limit: int = Field(default=5, ge=1, le=100)
    login_rate_window_seconds: int = Field(default=900, ge=60, le=86400)
    enrollment_token_minutes: int = Field(default=15, ge=1, le=1440)
    agent_credential_days: int = Field(default=90, ge=1, le=180)
    agent_clock_skew_seconds: int = Field(default=300, ge=30, le=300)
    agent_nonce_ttl_seconds: int = Field(default=600, ge=600, le=600)
    agent_request_limit: int = Field(default=120, ge=1, le=10000)

    @field_validator(
        "service_name",
        "postgres_host",
        "postgres_db",
        "postgres_user",
        "postgres_migration_user",
        "postgres_runtime_role",
        "redis_host",
        "jwt_issuer",
        "jwt_audience",
    )
    @classmethod
    def reject_empty_values(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("configuration values must not be blank")
        return value

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("unsupported log level")
        return normalized

    @field_validator("postgres_runtime_role")
    @classmethod
    def validate_role_name(cls, value: str) -> str:
        if not value.replace("_", "a").isalnum() or len(value) > 63:
            raise ValueError("invalid PostgreSQL runtime role")
        return value

    @field_validator("allowed_origin")
    @classmethod
    def validate_allowed_origin(cls, value: str) -> str:
        normalized = value.rstrip("/")
        if not normalized.startswith(("http://", "https://")):
            raise ValueError("allowed origin must be an HTTP(S) origin")
        if "/" in normalized.split("://", 1)[1]:
            raise ValueError("allowed origin must not contain a path")
        return normalized

    @model_validator(mode="after")
    def validate_secrets(self) -> Settings:
        values = [
            self.jwt_signing_key.get_secret_value(),
            self.rate_limit_hmac_key.get_secret_value(),
            self.audit_subject_hmac_key.get_secret_value(),
            self.enrollment_token_hmac_key.get_secret_value(),
            self.agent_credential_hmac_key.get_secret_value(),
            self.secret_replay_encryption_key.get_secret_value(),
        ]
        placeholders = {"change-me", "changeme", "placeholder", "development", "secret"}
        for value in values:
            if len(value.encode("utf-8")) < 32 or value.lower() in placeholders:
                raise ValueError(
                    "security keys must contain at least 256 bits of non-placeholder data"
                )
        if len(set(values)) != len(values):
            raise ValueError("security keys must be independent")
        return self

    @property
    def demo_enabled(self) -> bool:
        return self.environment in {"development", "demo"}

    @property
    def database_url(self) -> str:
        user = quote_plus(self.postgres_user)
        password = quote_plus(self.postgres_password)
        database = quote_plus(self.postgres_db)
        return (
            f"postgresql+psycopg://{user}:{password}@{self.postgres_host}:"
            f"{self.postgres_port}/{database}"
        )

    @property
    def migration_database_url(self) -> str:
        user = quote_plus(self.postgres_migration_user)
        password = quote_plus(self.postgres_migration_password)
        database = quote_plus(self.postgres_db)
        return (
            f"postgresql+psycopg://{user}:{password}@{self.postgres_host}:"
            f"{self.postgres_port}/{database}"
        )

    @property
    def trusted_proxy_networks(self) -> tuple[IPv4Network | IPv6Network, ...]:
        return tuple(
            ip_network(item.strip(), strict=False) for item in self.trusted_proxy_cidrs.split(",")
        )

    @property
    def celery_broker_url(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
