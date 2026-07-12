from __future__ import annotations

import json
import logging
import os
import re
import secrets
import signal
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from uuid import UUID, uuid4

import httpx

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HEALTH_FILE = Path("/tmp/simulated-agent-heartbeat")
_MANIFEST_FILE = Path("/app/capability-manifest.json")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "service": "simulated-agent",
                "environment": os.environ.get("WTO_ENVIRONMENT", "production"),
            },
            separators=(",", ":"),
        )


@dataclass(frozen=True)
class Settings:
    backend_url: str
    agent_id: str
    display_name: str
    heartbeat_interval: float
    request_timeout: float
    enrollment_token: str | None

    @classmethod
    def from_environment(cls) -> Settings:
        backend_url = os.environ["SIM_BACKEND_URL"].rstrip("/")
        agent_id = os.environ["SIM_AGENT_ID"]
        display_name = os.environ["SIM_AGENT_DISPLAY_NAME"].strip()
        heartbeat_interval = float(os.environ["SIM_HEARTBEAT_INTERVAL_SECONDS"])
        request_timeout = float(os.environ["SIM_REQUEST_TIMEOUT_SECONDS"])
        enrollment_token = os.environ.get("SIM_ENROLLMENT_TOKEN", "").strip() or None
        if not backend_url.startswith(("http://", "https://")):
            raise ValueError("SIM_BACKEND_URL must be HTTP or HTTPS")
        if _ID_PATTERN.fullmatch(agent_id) is None:
            raise ValueError("SIM_AGENT_ID has an invalid format")
        if not display_name or len(display_name) > 128:
            raise ValueError("SIM_AGENT_DISPLAY_NAME must contain 1 to 128 characters")
        if not 1 <= heartbeat_interval <= 300:
            raise ValueError("heartbeat interval must be between 1 and 300 seconds")
        if not 1 <= request_timeout <= 30:
            raise ValueError("request timeout must be between 1 and 30 seconds")
        return cls(
            backend_url=backend_url,
            agent_id=agent_id,
            display_name=display_name,
            heartbeat_interval=heartbeat_interval,
            request_timeout=request_timeout,
            enrollment_token=enrollment_token,
        )


def configure_logging() -> logging.Logger:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("wto.simulated_agent")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(os.environ.get("WTO_LOG_LEVEL", "INFO").upper())
    logger.propagate = False
    return logger


def timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def agent_headers(credential: str, *, idempotency_key: UUID | None = None) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {credential}",
        "X-WTO-Agent-Timestamp": timestamp(),
        "X-WTO-Agent-Nonce": secrets.token_urlsafe(16),
        "X-WTO-Agent-Protocol": "1.0.0",
        "X-Correlation-ID": str(uuid4()),
    }
    if idempotency_key is not None:
        headers["Idempotency-Key"] = str(idempotency_key)
    return headers


def enroll(client: httpx.Client, settings: Settings) -> tuple[str, str, str, str]:
    assert settings.enrollment_token is not None
    idempotency_key = uuid4()
    payload = {
        "schema_version": "1.0.0",
        "idempotency_key": str(idempotency_key),
        "enrollment_token": settings.enrollment_token,
        "installation_id": str(uuid4()),
        "display_name": settings.display_name,
        "platform": "simulated",
        "platform_version": "1",
        "agent_version": "0.1.0",
        "protocol_min_version": "1.0.0",
        "protocol_max_version": "1.0.0",
        "agent_reported_at": timestamp(),
    }
    response = client.post(
        f"{settings.backend_url}/api/v1/agent-enrollments",
        json=payload,
        headers={"Idempotency-Key": str(idempotency_key), "X-Correlation-ID": str(uuid4())},
    )
    response.raise_for_status()
    body = response.json()
    return (
        str(body["agent_id"]),
        str(body["credential"]["credential"]),
        str(body["credential"]["credential_id"]),
        str(body["device_id"]),
    )


def publish_manifest(
    client: httpx.Client, settings: Settings, agent_id: str, credential: str
) -> tuple[str, str]:
    manifest = json.loads(_MANIFEST_FILE.read_text(encoding="utf-8"))
    manifest["agent_id"] = agent_id
    manifest["manifest_id"] = str(uuid4())
    manifest["platform"] = "simulated"
    manifest["platform_version"] = "1"
    manifest["generated_at"] = timestamp()
    response = client.put(
        f"{settings.backend_url}/api/v1/agents/self/capability-manifest",
        json=manifest,
        headers=agent_headers(credential),
    )
    response.raise_for_status()
    body = response.json()
    return str(body["manifest_id"]), str(body["manifest_digest"])


def rotate(client: httpx.Client, settings: Settings, credential: str) -> str:
    rotation_key = uuid4()
    response = client.post(
        f"{settings.backend_url}/api/v1/agents/self/credential-rotations",
        json={"schema_version": "1.0.0", "idempotency_key": str(rotation_key)},
        headers=agent_headers(credential, idempotency_key=rotation_key),
    )
    response.raise_for_status()
    body = response.json()
    pending = str(body["pending_credential"]["credential"])
    activation_key = uuid4()
    activation = client.post(
        f"{settings.backend_url}/api/v1/agents/self/credential-rotations/{body['rotation_id']}/activate",
        json={"schema_version": "1.0.0", "idempotency_key": str(activation_key)},
        headers=agent_headers(pending, idempotency_key=activation_key),
    )
    activation.raise_for_status()
    return pending


def run_demo(client: httpx.Client, settings: Settings, started_at: datetime) -> None:
    payload = {
        "agent_id": settings.agent_id,
        "display_name": settings.display_name,
        "platform": "simulated",
        "process_started_at": started_at.isoformat(),
        "sent_at": timestamp(),
    }
    response = client.post(
        f"{settings.backend_url}/demo/agents/heartbeat",
        json=payload,
        headers={"X-Correlation-ID": str(uuid4())},
    )
    response.raise_for_status()


def main() -> None:
    settings = Settings.from_environment()
    logger = configure_logging()
    started_at = datetime.now(UTC)
    stopping = False

    def stop(_: int, __: FrameType | None) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    agent_id: str | None = None
    credential: str | None = None
    manifest_id: str | None = None
    manifest_digest: str | None = None
    boot_id = str(uuid4())
    sequence = 0

    with httpx.Client(timeout=settings.request_timeout) as client:
        if settings.enrollment_token is not None:
            try:
                agent_id, credential, _, _ = enroll(client, settings)
                manifest_id, manifest_digest = publish_manifest(
                    client, settings, agent_id, credential
                )
                credential = rotate(client, settings, credential)
                logger.info("Normative enrollment and credential rotation completed")
            except httpx.HTTPError:
                logger.error("Normative enrollment failed")
        while not stopping:
            try:
                if all((agent_id, credential, manifest_id, manifest_digest)):
                    sequence += 1
                    payload = {
                        "schema_version": "1.0.0",
                        "agent_id": agent_id,
                        "boot_id": boot_id,
                        "sequence": sequence,
                        "agent_version": "0.1.0",
                        "protocol_version": "1.0.0",
                        "agent_reported_at": timestamp(),
                        "readiness": "ready",
                        "reason": None,
                        "manifest_id": manifest_id,
                        "manifest_digest": manifest_digest,
                    }
                    response = client.post(
                        f"{settings.backend_url}/api/v1/agents/self/heartbeats",
                        json=payload,
                        headers=agent_headers(str(credential)),
                    )
                    response.raise_for_status()
                    logger.info("Normative presence heartbeat accepted")
                else:
                    run_demo(client, settings, started_at)
                    logger.info("Demo presence heartbeat accepted")
                _HEALTH_FILE.touch()
            except httpx.HTTPError:
                logger.warning("Presence heartbeat failed")
            deadline = time.monotonic() + settings.heartbeat_interval
            while not stopping and time.monotonic() < deadline:
                time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))


if __name__ == "__main__":
    main()
