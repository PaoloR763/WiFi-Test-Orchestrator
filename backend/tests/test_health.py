from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from wto_backend.config import Settings
from wto_backend.health import HealthService
from wto_backend.main import create_app


class StubCheck:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls = 0

    def check(self) -> None:
        self.calls += 1
        if self.error is not None:
            raise self.error


@pytest.fixture
def checks() -> dict[str, StubCheck]:
    return {
        "postgresql": StubCheck(),
        "redis": StubCheck(),
        "artifact_store": StubCheck(),
    }


def client_for(settings: Settings, checks: dict[str, StubCheck]) -> TestClient:
    return TestClient(create_app(settings, health_service=HealthService(checks)))


def test_liveness_is_independent_of_dependencies(
    settings_factory: Callable[..., Settings], checks: dict[str, StubCheck]
) -> None:
    for check in checks.values():
        check.error = RuntimeError("dependency must not be called")
    response = client_for(settings_factory(), checks).get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "alive"}
    assert all(check.calls == 0 for check in checks.values())


def test_readiness_is_healthy(
    settings_factory: Callable[..., Settings], checks: dict[str, StubCheck]
) -> None:
    response = client_for(settings_factory(), checks).get("/health/ready")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "checks": {
            "postgresql": {"status": "ready"},
            "redis": {"status": "ready"},
            "artifact_store": {"status": "ready"},
        },
    }


@pytest.mark.parametrize("failed_dependency", ["postgresql", "redis", "artifact_store"])
def test_readiness_is_degraded_without_leaking_details(
    failed_dependency: str,
    settings_factory: Callable[..., Settings],
    checks: dict[str, StubCheck],
) -> None:
    checks[failed_dependency].error = RuntimeError(
        "postgresql://user:secret@private-host/internal-path"
    )
    response = client_for(settings_factory(), checks).get("/health/ready")
    body = response.json()
    assert response.status_code == 503
    assert body["status"] == "unavailable"
    assert body["checks"][failed_dependency] == {"status": "unavailable"}
    serialized = response.text
    assert "secret" not in serialized
    assert "private-host" not in serialized
    assert "internal-path" not in serialized
