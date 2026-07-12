from __future__ import annotations

from typing import Any, Protocol

from celery import Celery


class ExecutionBackend(Protocol):
    """Phase 02 worker boundary; definitive task semantics remain deferred."""

    def submit_internal(self, operation: str, payload: dict[str, Any]) -> str: ...


class CeleryExecutionBackend:
    def __init__(self, celery_app: Celery) -> None:
        self._celery_app = celery_app

    def submit_internal(self, operation: str, payload: dict[str, Any]) -> str:
        result = self._celery_app.send_task(operation, kwargs={"payload": payload})
        return str(result.id)
