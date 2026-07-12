from __future__ import annotations

import json
import logging
import os
import re
import signal
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from uuid import uuid4

import httpx

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HEALTH_FILE = Path("/tmp/simulated-agent-heartbeat")


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

    @classmethod
    def from_environment(cls) -> Settings:
        backend_url = os.environ["SIM_BACKEND_URL"].rstrip("/")
        agent_id = os.environ["SIM_AGENT_ID"]
        display_name = os.environ["SIM_AGENT_DISPLAY_NAME"].strip()
        heartbeat_interval = float(os.environ["SIM_HEARTBEAT_INTERVAL_SECONDS"])
        request_timeout = float(os.environ["SIM_REQUEST_TIMEOUT_SECONDS"])
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

    with httpx.Client(timeout=settings.request_timeout) as client:
        while not stopping:
            sent_at = datetime.now(UTC)
            payload = {
                "agent_id": settings.agent_id,
                "display_name": settings.display_name,
                "platform": "simulated",
                "process_started_at": started_at.isoformat(),
                "sent_at": sent_at.isoformat(),
            }
            try:
                response = client.post(
                    f"{settings.backend_url}/demo/agents/heartbeat",
                    json=payload,
                    headers={"X-Correlation-ID": str(uuid4())},
                )
                response.raise_for_status()
                _HEALTH_FILE.touch()
                logger.info("Demo presence heartbeat accepted")
            except httpx.HTTPError:
                logger.warning("Demo presence heartbeat failed")
            deadline = time.monotonic() + settings.heartbeat_interval
            while not stopping and time.monotonic() < deadline:
                time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))


if __name__ == "__main__":
    main()
