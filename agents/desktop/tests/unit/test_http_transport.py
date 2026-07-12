from __future__ import annotations

import inspect

import httpx
import pytest

from wto_desktop_agent.domain.errors import TransportError
from wto_desktop_agent.infrastructure.http_transport import HttpAgentTransport


def test_productive_transport_has_no_task_progress_result_or_artifact_api() -> None:
    source = inspect.getsource(HttpAgentTransport)
    for forbidden in ("task-fetch", "/progress", "/results", "artifact-manifests"):
        assert forbidden not in source
    for method in (
        "enroll",
        "create_rotation",
        "activate_rotation",
        "publish_manifest",
        "heartbeat",
    ):
        assert hasattr(HttpAgentTransport, method)
    assert not hasattr(HttpAgentTransport, "fetch_local_task")


@pytest.mark.asyncio
async def test_http_transport_only_calls_public_enrollment_path() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(503, json={"schema_version": "1.0.0", "error": {}})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    transport = HttpAgentTransport("https://server.example", timeout_seconds=1, client=client)
    from uuid import uuid4

    key = uuid4()
    with pytest.raises(TransportError):
        await transport.enroll(
            {
                "schema_version": "1.0.0",
                "idempotency_key": str(key),
                "enrollment_token": "wto_enr_1." + str(uuid4()) + "." + "A" * 43,
                "installation_id": str(uuid4()),
                "display_name": "test",
                "platform": "linux",
                "platform_version": "1",
                "agent_version": "0.1.0",
                "protocol_min_version": "1.0.0",
                "protocol_max_version": "1.0.0",
                "agent_reported_at": "2026-07-12T12:00:00Z",
            },
            key,
        )
    assert paths == ["/api/v1/agent-enrollments"]
    await client.aclose()


@pytest.mark.asyncio
async def test_unreachable_server_returns_structured_transport_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("synthetic offline server", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    transport = HttpAgentTransport("https://server.example", timeout_seconds=1, client=client)
    from uuid import uuid4

    key = uuid4()
    with pytest.raises(TransportError, match="HTTPS request failed"):
        await transport.enroll(
            {
                "schema_version": "1.0.0",
                "idempotency_key": str(key),
                "enrollment_token": "wto_enr_1." + str(uuid4()) + "." + "A" * 43,
                "installation_id": str(uuid4()),
                "display_name": "test",
                "platform": "linux",
                "platform_version": "1",
                "agent_version": "0.1.0",
                "protocol_min_version": "1.0.0",
                "protocol_max_version": "1.0.0",
                "agent_reported_at": "2026-07-12T12:00:00Z",
            },
            key,
        )
    await client.aclose()
