from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any, TextIO

_MACHINE_SECRET = re.compile(r"wto_(?:enr|ac)_1\.[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}")
_BEARER = re.compile(r"(?i)Bearer\s+[A-Za-z0-9._-]+")
_NAMED_SECRET = re.compile(
    r"(?i)\b(authorization|cookie|nonce|password|secret|token|credential|"
    r"[a-z0-9_]*(?:hmac|signing|encryption)_key)\b\s*[:=]\s*([^\s,;]+)"
)
_SECRET_KEYS = re.compile(
    r"(?i)(authorization|cookie|nonce|password|secret|token|credential|hmac|signing|encryption)"
)


def redact_text(value: str) -> str:
    value = _MACHINE_SECRET.sub("[REDACTED]", value)
    value = _BEARER.sub("Bearer [REDACTED]", value)
    return _NAMED_SECRET.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)


def redact_value(value: object, key: str = "") -> object:
    if key and _SECRET_KEYS.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
            "service": "wto-desktop-agent",
        }
        for name in ("correlation_id", "task_id", "execution_id", "event"):
            if hasattr(record, name):
                payload[name] = redact_value(getattr(record, name), name)
        if record.exc_info and record.exc_info[0]:
            payload["exception"] = record.exc_info[0].__name__
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_logging(level: str, stream: TextIO | None = None) -> None:
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
