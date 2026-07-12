from __future__ import annotations

import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field

from wto_desktop_agent.domain.errors import TransportError
from wto_desktop_agent.infrastructure.contracts import validate_contract


class AgentAuthenticationFailed(TransportError):
    pass


class StrictResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RotationCredential(StrictResponse):
    schema_version: str
    credential_id: UUID
    credential_version: int
    credential: str
    issued_at: datetime
    expires_at: datetime
    state: str


class RotationCreateResponse(StrictResponse):
    schema_version: str
    rotation_id: UUID
    expires_at: datetime
    pending_credential: RotationCredential


class RotationActivateResponse(StrictResponse):
    schema_version: str
    rotation_id: UUID
    credential_id: UUID
    credential_version: int
    activated_at: datetime


class PresenceResponse(StrictResponse):
    schema_version: str
    accepted_sequence: int
    server_received_at: datetime
    presence_expires_at: datetime
    poll_after_seconds: int = Field(ge=15, le=900)


class ManifestResponse(StrictResponse):
    schema_version: str
    manifest_id: UUID
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    server_received_at: datetime


class HttpAgentTransport:
    """Phase 04 public API client. It intentionally has no task/outbox methods."""

    def __init__(
        self,
        server_url: str,
        *,
        timeout_seconds: float,
        ca_bundle: Path | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._server_url = server_url.rstrip("/")
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=timeout_seconds,
            verify=str(ca_bundle) if ca_bundle else True,
            follow_redirects=False,
        )

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(UTC).isoformat().replace("+00:00", "Z")

    def _agent_headers(
        self, credential: str, *, idempotency_key: UUID | None = None
    ) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {credential}",
            "X-WTO-Agent-Timestamp": self._timestamp(),
            "X-WTO-Agent-Nonce": secrets.token_urlsafe(16),
            "X-WTO-Agent-Protocol": "1.0.0",
            "X-Correlation-ID": str(uuid4()),
        }
        if idempotency_key:
            headers["Idempotency-Key"] = str(idempotency_key)
        return headers

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = await self._client.request(method, self._server_url + path, **kwargs)
        except httpx.HTTPError as error:
            raise TransportError("HTTPS request failed") from error
        if response.status_code == 401:
            code = ""
            try:
                code = str(response.json().get("error", {}).get("code", ""))
            except ValueError:
                pass
            if code == "agent_authentication_failed":
                raise AgentAuthenticationFailed("agent credential was rejected")
        if response.is_error:
            raise TransportError(f"server rejected request with status {response.status_code}")
        if response.status_code == 204:
            return {}
        try:
            body = response.json()
        except ValueError as error:
            raise TransportError("server returned invalid JSON") from error
        if not isinstance(body, dict):
            raise TransportError("server returned an invalid response shape")
        return body

    async def enroll(self, payload: dict[str, Any], idempotency_key: UUID) -> dict[str, Any]:
        validate_contract("agent-registration-request.schema.json", payload)
        body = await self._request(
            "POST",
            "/api/v1/agent-enrollments",
            json=payload,
            headers={
                "Idempotency-Key": str(idempotency_key),
                "X-Correlation-ID": str(uuid4()),
            },
        )
        validate_contract("agent-registration-response.schema.json", body)
        return body

    async def create_rotation(
        self, credential: str, payload: dict[str, Any], idempotency_key: UUID
    ) -> dict[str, Any]:
        body = await self._request(
            "POST",
            "/api/v1/agents/self/credential-rotations",
            json=payload,
            headers=self._agent_headers(credential, idempotency_key=idempotency_key),
        )
        return RotationCreateResponse.model_validate(body).model_dump(mode="json")

    async def activate_rotation(
        self,
        credential: str,
        rotation_id: UUID,
        payload: dict[str, Any],
        idempotency_key: UUID,
    ) -> dict[str, Any]:
        body = await self._request(
            "POST",
            f"/api/v1/agents/self/credential-rotations/{rotation_id}/activate",
            json=payload,
            headers=self._agent_headers(credential, idempotency_key=idempotency_key),
        )
        return RotationActivateResponse.model_validate(body).model_dump(mode="json")

    async def publish_manifest(self, credential: str, payload: dict[str, Any]) -> dict[str, Any]:
        validate_contract("capability-manifest.schema.json", payload)
        body = await self._request(
            "PUT",
            "/api/v1/agents/self/capability-manifest",
            json=payload,
            headers=self._agent_headers(credential),
        )
        return ManifestResponse.model_validate(body).model_dump(mode="json")

    async def heartbeat(self, credential: str, payload: dict[str, Any]) -> dict[str, Any]:
        validate_contract("desktop-heartbeat.schema.json", payload)
        body = await self._request(
            "POST",
            "/api/v1/agents/self/heartbeats",
            json=payload,
            headers=self._agent_headers(credential),
        )
        return PresenceResponse.model_validate(body).model_dump(mode="json")
