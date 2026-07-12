from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from wto_backend.config import Settings


@pytest.fixture
def settings_factory(tmp_path: Path) -> Callable[..., Settings]:
    def factory(**overrides: object) -> Settings:
        values: dict[str, object] = {
            "environment": "test",
            "service_name": "backend-test",
            "log_level": "INFO",
            "demo_agent_ttl_seconds": 45,
            "postgres_host": "postgres.invalid",
            "postgres_port": 5432,
            "postgres_db": "wto_test",
            "postgres_user": "wto_test",
            "postgres_password": "test-only-placeholder",
            "redis_host": "redis.invalid",
            "redis_port": 6379,
            "redis_db": 0,
            "artifact_root": tmp_path,
        }
        values.update(overrides)
        return Settings(**values)  # type: ignore[arg-type]

    return factory
