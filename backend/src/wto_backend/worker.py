from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from celery import Celery

from wto_backend.config import get_settings
from wto_backend.logging import configure_logging

settings = get_settings()
configure_logging(
    service=settings.service_name,
    environment=settings.environment,
    level=settings.log_level,
)

celery_app = Celery("wto_phase02", broker=settings.celery_broker_url)
celery_app.conf.update(
    task_ignore_result=True,
    task_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    worker_hijack_root_logger=False,
)


@celery_app.task(name="phase02.healthcheck")  # type: ignore[misc]
def phase02_healthcheck(payload: dict[str, Any] | None = None) -> dict[str, str]:
    """Internal bootstrap operation; not a public task contract."""

    del payload
    return {"status": "ok", "timestamp": datetime.now(UTC).isoformat()}
