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
            "postgres_migration_user": "wto_test_owner",
            "postgres_migration_password": "test-owner-placeholder",
            "postgres_runtime_role": "wto_runtime",
            "redis_host": "redis.invalid",
            "redis_port": 6379,
            "redis_db": 0,
            "artifact_root": tmp_path,
            "jwt_signing_key": "j" * 48,
            "rate_limit_hmac_key": "r" * 48,
            "audit_subject_hmac_key": "a" * 48,
            "allowed_origin": "https://testserver",
            "trusted_proxy_cidrs": "127.0.0.1/32",
        }
        values.update(overrides)
        return Settings(**values)  # type: ignore[arg-type]

    return factory
