from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from wto_backend.config import Settings, get_settings
from wto_backend.correlation import CorrelationIdMiddleware
from wto_backend.demo import DemoAgentStore
from wto_backend.demo import router as demo_router
from wto_backend.dependencies import RuntimeDependencies
from wto_backend.health import HealthService
from wto_backend.health import router as health_router
from wto_backend.logging import configure_logging


def create_app(
    settings: Settings | None = None,
    *,
    health_service: HealthService | None = None,
    demo_agent_store: DemoAgentStore | None = None,
) -> FastAPI:
    resolved_settings = settings or get_settings()
    configure_logging(
        service=resolved_settings.service_name,
        environment=resolved_settings.environment,
        level=resolved_settings.log_level,
    )
    runtime_dependencies: RuntimeDependencies | None = None
    if health_service is None:
        runtime_dependencies = RuntimeDependencies(resolved_settings)
        health_service = HealthService(runtime_dependencies.checks())

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        if runtime_dependencies is not None:
            runtime_dependencies.close()

    app = FastAPI(
        title="WiFi Test Orchestrator Bootstrap API",
        version="0.1.0",
        description=(
            "Phase 02 operational API only. Demo inventory is intentionally excluded "
            "from OpenAPI and will be replaced in Phases 03 and 04."
        ),
        lifespan=lifespan,
    )
    app.state.health_service = health_service
    app.add_middleware(CorrelationIdMiddleware)
    app.include_router(health_router)

    if resolved_settings.demo_enabled:
        app.state.demo_agent_store = demo_agent_store or DemoAgentStore(
            resolved_settings.demo_agent_ttl_seconds
        )
        app.include_router(demo_router)

    return app


app = create_app()
