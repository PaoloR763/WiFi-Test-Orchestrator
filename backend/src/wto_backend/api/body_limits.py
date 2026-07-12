from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from starlette.types import ASGIApp, Message, Receive, Scope, Send


def limit_for_path(path: str) -> int | None:
    if "agent-enrollments" in path or "credential-rotations" in path:
        return 32 * 1024
    if any(item in path for item in ("heartbeats", "presence", "progress")):
        return 64 * 1024
    if "capability-manifest" in path or "task-fetch" in path:
        return 256 * 1024
    if "artifact-manifests" in path:
        return 64 * 1024
    if path.endswith("/results"):
        return 1024 * 1024
    return None


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = limit_for_path(str(scope.get("path", "")))
        if limit is None:
            await self.app(scope, receive, send)
            return
        body = bytearray()
        more = True
        while more:
            message = await receive()
            if message["type"] != "http.request":
                continue
            body.extend(message.get("body", b""))
            more = bool(message.get("more_body", False))
            if len(body) > limit:
                await self._reject(scope, send)
                return
        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if delivered:
                return {"type": "http.request", "body": b"", "more_body": False}
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay, send)

    @staticmethod
    async def _reject(scope: Scope, send: Send) -> None:
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        supplied = headers.get(b"x-correlation-id", b"").decode("ascii", errors="ignore")
        correlation_id = supplied if 1 <= len(supplied) <= 128 else str(uuid4())
        payload: dict[str, Any] = {
            "schema_version": "1.0.0",
            "error": {
                "code": "payload_too_large",
                "message": "The request body exceeds the allowed size.",
                "details": None,
                "correlation_id": correlation_id,
            },
        }
        rendered = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(rendered)).encode("ascii")),
                    (b"x-correlation-id", correlation_id.encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": rendered})
