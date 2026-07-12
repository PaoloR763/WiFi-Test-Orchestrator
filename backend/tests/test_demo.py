from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

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


def heartbeat_payload() -> dict[str, str]:
    now = datetime.now(UTC).isoformat()
    return {
        "agent_id": "simulated-test-agent",
        "display_name": "Test simulated agent",
        "platform": "simulated",
        "process_started_at": now,
        "sent_at": now,
    }


def test_demo_endpoints_available_in_development(
    settings_factory: Callable[..., Settings],
) -> None:
    client = make_client(settings_factory(environment="development"))
    assert client.post("/demo/agents/heartbeat", json=heartbeat_payload()).status_code == 204
    response = client.get("/demo/agents")
    assert response.status_code == 200
    assert response.json()["agents"][0]["agent_id"] == "simulated-test-agent"


def test_demo_endpoints_available_in_demo(
    settings_factory: Callable[..., Settings],
) -> None:
    client = make_client(settings_factory(environment="demo"))
    assert client.get("/demo/agents").status_code == 200


def test_demo_endpoints_are_404_outside_demo_environments(
    settings_factory: Callable[..., Settings],
) -> None:
    client = make_client(settings_factory(environment="production"))
    assert client.get("/demo/agents").status_code == 404
    assert client.post("/demo/agents/heartbeat", json=heartbeat_payload()).status_code == 404


def test_demo_endpoints_are_excluded_from_openapi(
    settings_factory: Callable[..., Settings],
) -> None:
    client = make_client(settings_factory(environment="development"))
    paths = client.get("/openapi.json").json()["paths"]
    assert "/demo/agents" not in paths
    assert "/demo/agents/heartbeat" not in paths


def test_canonical_openapi_has_agent_security_schemes(
    settings_factory: Callable[..., Settings],
) -> None:
    client = make_client(settings_factory(environment="production"))
    document = client.get("/openapi.json").json()
    assert document["openapi"] == "3.1.0"
    schemes = document["components"]["securitySchemes"]
    assert {
        "UserBearerAuth",
        "AgentBearerAuth",
        "AgentPendingCredentialAuth",
    } <= schemes.keys()
