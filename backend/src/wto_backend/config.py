from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import quote_plus

from pydantic import Field, field_validator
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
    redis_host: str
    redis_port: int = Field(default=6379, ge=1, le=65535)
    redis_db: int = Field(default=0, ge=0, le=15)
    artifact_root: Path = Path("/var/lib/wto/artifacts")

    @field_validator("service_name", "postgres_host", "postgres_db", "postgres_user", "redis_host")
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
    def celery_broker_url(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
