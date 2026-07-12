from __future__ import annotations

import io
import json
import logging

from wto_backend.logging import configure_logging, correlation_id_context


def test_logs_are_structured_utc_and_include_correlation_id() -> None:
    stream = io.StringIO()
    configure_logging(service="backend-test", environment="test", level="INFO", stream=stream)
    token = correlation_id_context.set("test-correlation-1")
    try:
        logging.getLogger("test.logger").info("readiness completed")
    finally:
        correlation_id_context.reset(token)

    payload = json.loads(stream.getvalue())
    assert payload["timestamp"].endswith("Z")
    assert payload["level"] == "INFO"
    assert payload["logger"] == "test.logger"
    assert payload["message"] == "readiness completed"
    assert payload["correlation_id"] == "test-correlation-1"
    assert payload["service"] == "backend-test"
    assert payload["environment"] == "test"


def test_logs_redact_secrets() -> None:
    stream = io.StringIO()
    configure_logging(service="backend-test", environment="test", level="INFO", stream=stream)
    logging.getLogger("test.logger").warning(
        "password=do-not-log token:also-secret authorization=Bearer-value"
    )
    rendered = stream.getvalue()
    assert "do-not-log" not in rendered
    assert "also-secret" not in rendered
    assert "Bearer-value" not in rendered
    assert rendered.count("[REDACTED]") == 3
