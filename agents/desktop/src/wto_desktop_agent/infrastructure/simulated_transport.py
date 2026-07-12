from __future__ import annotations

from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class SimulatedAgentTransport:
    """Explicit test/development transport for public calls and local task delivery."""

    def __init__(self) -> None:
        self.tasks: deque[dict[str, Any]] = deque()
        self.progress: list[dict[str, Any]] = []
        self.results: list[dict[str, Any]] = []
        self.uploads: list[dict[str, Any]] = []
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._agent_id = uuid4()
        self._device_id = uuid4()
        self._active = "wto_ac_1." + str(uuid4()) + "." + "A" * 43
        self._pending: str | None = None
        self._rotation_response: dict[str, Any] | None = None
        self._activation_response: dict[str, Any] | None = None

    async def enroll(self, payload: dict[str, Any], idempotency_key: UUID) -> dict[str, Any]:
        import hashlib

        safe_payload = dict(payload)
        supplied = str(safe_payload.pop("enrollment_token"))
        safe_payload["enrollment_token_fingerprint"] = hashlib.sha256(
            supplied.encode("utf-8")
        ).hexdigest()
        self.calls.append(("enroll", safe_payload))
        return {
            "schema_version": "1.0.0",
            "device_id": str(self._device_id),
            "agent_id": str(self._agent_id),
            "protocol_version": "1.0.0",
            "server_received_at": _now(),
            "credential": {
                "schema_version": "1.0.0",
                "credential_id": self._active.split(".")[1],
                "credential_version": 1,
                "credential": self._active,
                "issued_at": _now(),
                "expires_at": (datetime.now(UTC) + timedelta(days=30))
                .isoformat()
                .replace("+00:00", "Z"),
                "state": "active",
            },
        }

    async def create_rotation(
        self, credential: str, payload: dict[str, Any], idempotency_key: UUID
    ) -> dict[str, Any]:
        self.calls.append(("create_rotation", payload))
        if self._rotation_response is not None:
            return self._rotation_response
        if self._pending is None:
            self._pending = "wto_ac_1." + str(uuid4()) + "." + "B" * 43
        self._rotation_response = {
            "schema_version": "1.0.0",
            "rotation_id": str(uuid4()),
            "expires_at": (datetime.now(UTC) + timedelta(minutes=15))
            .isoformat()
            .replace("+00:00", "Z"),
            "pending_credential": {
                "schema_version": "1.0.0",
                "credential_id": self._pending.split(".")[1],
                "credential_version": 2,
                "credential": self._pending,
                "issued_at": _now(),
                "expires_at": (datetime.now(UTC) + timedelta(days=30))
                .isoformat()
                .replace("+00:00", "Z"),
                "state": "pending",
            },
        }
        return self._rotation_response

    async def activate_rotation(
        self,
        credential: str,
        rotation_id: UUID,
        payload: dict[str, Any],
        idempotency_key: UUID,
    ) -> dict[str, Any]:
        self.calls.append(("activate_rotation", payload))
        if self._activation_response is not None:
            return self._activation_response
        assert self._pending is not None
        self._active = self._pending
        self._activation_response = {
            "schema_version": "1.0.0",
            "rotation_id": str(rotation_id),
            "credential_id": self._active.split(".")[1],
            "credential_version": 2,
            "activated_at": _now(),
        }
        return self._activation_response

    async def publish_manifest(self, credential: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("publish_manifest", payload))
        import hashlib
        import json

        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return {
            "schema_version": "1.0.0",
            "manifest_id": payload["manifest_id"],
            "manifest_digest": hashlib.sha256(encoded).hexdigest(),
            "server_received_at": _now(),
        }

    async def heartbeat(self, credential: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("heartbeat", payload))
        return {
            "schema_version": "1.0.0",
            "accepted_sequence": payload["sequence"],
            "server_received_at": _now(),
            "presence_expires_at": (datetime.now(UTC) + timedelta(seconds=90))
            .isoformat()
            .replace("+00:00", "Z"),
            "poll_after_seconds": 30,
        }

    async def fetch_local_task(self) -> dict[str, Any] | None:
        return self.tasks.popleft() if self.tasks else None

    async def publish_progress(self, payload: dict[str, Any]) -> None:
        self.progress.append(payload)

    async def publish_result(self, payload: dict[str, Any]) -> None:
        self.results.append(payload)

    async def publish_upload(self, payload: dict[str, Any]) -> None:
        self.uploads.append(payload)
