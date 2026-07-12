from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from wto_backend.dependencies import ReadinessCheck

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


class HealthService:
    def __init__(self, checks: Mapping[str, ReadinessCheck]) -> None:
        self._checks = checks

    def readiness(self) -> tuple[bool, dict[str, dict[str, str]]]:
        healthy = True
        results: dict[str, dict[str, str]] = {}
        for name, check in self._checks.items():
            try:
                check.check()
                results[name] = {"status": "ready"}
            except Exception:
                healthy = False
                results[name] = {"status": "unavailable"}
                logger.warning("Readiness dependency unavailable: %s", name)
        return healthy, results


@router.get("/health/live")
async def live() -> dict[str, str]:
    return {"status": "alive"}


@router.get("/health/ready")
async def ready(request: Request) -> JSONResponse:
    service: HealthService = request.app.state.health_service
    healthy, checks = await asyncio.to_thread(service.readiness)
    status_code = 200 if healthy else 503
    return JSONResponse(
        status_code=status_code,
        content={"status": "ready" if healthy else "unavailable", "checks": checks},
    )
