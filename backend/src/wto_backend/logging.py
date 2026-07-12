from __future__ import annotations

import contextvars
import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import TextIO

correlation_id_context: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id", default=None
)

_SECRET_PATTERN = re.compile(
    r"(?i)\b(password(?:_hash)?|passwd|(?:refresh_)?token(?:_digest)?|cookie|secret|"
    r"authorization|dsn|signing_key|hmac_key)\b\s*[:=]\s*([^\s,;]+)"
)


def redact_secrets(value: str) -> str:
    return _SECRET_PATTERN.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str, environment: str) -> None:
        super().__init__()
        self._service = service
        self._environment = environment

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, str] = {
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_secrets(record.getMessage()),
            "service": self._service,
            "environment": self._environment,
        }
        correlation_id = correlation_id_context.get()
        if correlation_id is not None:
            payload["correlation_id"] = correlation_id
        if record.exc_info is not None:
            exception_type = record.exc_info[0]
            if exception_type is not None:
                payload["exception"] = exception_type.__name__
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_logging(
    *, service: str, environment: str, level: str, stream: TextIO | None = None
) -> None:
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(JsonFormatter(service=service, environment=environment))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        framework_logger = logging.getLogger(logger_name)
        framework_logger.handlers.clear()
        framework_logger.propagate = True
