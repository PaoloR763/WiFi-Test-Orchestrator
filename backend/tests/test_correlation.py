from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from wto_backend.config import Settings
from wto_backend.health import HealthService
from wto_backend.main import create_app


class HealthyCheck:
    def check(self) -> None:
        return None


def make_client(settings: Settings) -> TestClient:
    checks = {name: HealthyCheck() for name in ("postgresql", "redis", "artifact_store")}
    return TestClient(create_app(settings, health_service=HealthService(checks)))


def test_generates_correlation_id(settings_factory: Callable[..., Settings]) -> None:
    response = make_client(settings_factory()).get("/health/live")
    UUID(response.headers["X-Correlation-ID"])


def test_propagates_valid_correlation_id(settings_factory: Callable[..., Settings]) -> None:
    correlation_id = "client.request-123_example"
    response = make_client(settings_factory()).get(
        "/health/live", headers={"X-Correlation-ID": correlation_id}
    )
    assert response.status_code == 200
    assert response.headers["X-Correlation-ID"] == correlation_id


def test_accepts_correlation_id_at_maximum_length(
    settings_factory: Callable[..., Settings],
) -> None:
    correlation_id = "a" * 128
    response = make_client(settings_factory()).get(
        "/health/live", headers={"X-Correlation-ID": correlation_id}
    )
    assert response.status_code == 200
    assert response.headers["X-Correlation-ID"] == correlation_id


@pytest.mark.parametrize(
    "invalid_value",
    [" leading-space", "contains space", "a" * 129, "slash/not-allowed"],
)
def test_rejects_invalid_correlation_id(
    invalid_value: str, settings_factory: Callable[..., Settings]
) -> None:
    response = make_client(settings_factory()).get(
        "/health/live", headers={"X-Correlation-ID": invalid_value}
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_correlation_id"
    UUID(response.headers["X-Correlation-ID"])
    assert invalid_value not in response.text


def test_pattern_rejects_non_ascii() -> None:
    from wto_backend.correlation import CORRELATION_ID_PATTERN

    assert CORRELATION_ID_PATTERN.fullmatch("é") is None
