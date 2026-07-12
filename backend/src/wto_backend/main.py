from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from wto_backend.api.errors import install_error_handlers
from wto_backend.api.routers.admin import router as admin_router
from wto_backend.api.routers.audit import router as audit_router
from wto_backend.api.routers.auth import router as auth_router
from wto_backend.api.routers.rbac import router as rbac_router
from wto_backend.config import Settings, get_settings
from wto_backend.correlation import CorrelationIdMiddleware
from wto_backend.demo import DemoAgentStore
from wto_backend.demo import router as demo_router
from wto_backend.dependencies import RuntimeDependencies
from wto_backend.health import HealthService
from wto_backend.health import router as health_router
from wto_backend.logging import configure_logging
from wto_backend.security.passwords import PasswordManager
from wto_backend.security.rate_limit import LoginRateLimiter
from wto_backend.security.tokens import TokenManager
from wto_backend.services.auth import AuthService


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
    runtime_dependencies = RuntimeDependencies(resolved_settings)
    if health_service is None:
        health_service = HealthService(runtime_dependencies.checks())

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        if runtime_dependencies is not None:
            runtime_dependencies.close()

    app = FastAPI(
        title="WiFi Test Orchestrator Internal API",
        version="0.1.0",
        description=(
            "Phase 03 internal and provisional API. Demo inventory remains excluded "
            "from OpenAPI and will be replaced in Phase 04."
        ),
        lifespan=lifespan,
    )
    app.state.health_service = health_service
    app.state.settings = resolved_settings
    app.state.database = runtime_dependencies.database
    password_manager = PasswordManager(
        memory_cost=resolved_settings.argon2_memory_cost,
        time_cost=resolved_settings.argon2_time_cost,
        parallelism=resolved_settings.argon2_parallelism,
    )
    token_manager = TokenManager(
        signing_key=resolved_settings.jwt_signing_key.get_secret_value(),
        issuer=resolved_settings.jwt_issuer,
        audience=resolved_settings.jwt_audience,
        ttl_minutes=resolved_settings.access_token_minutes,
    )
    app.state.password_manager = password_manager
    app.state.auth_service_factory = lambda session: AuthService(
        session,
        passwords=password_manager,
        tokens=token_manager,
        audit_hmac_key=resolved_settings.audit_subject_hmac_key.get_secret_value(),
        absolute_days=resolved_settings.refresh_absolute_days,
        inactivity_days=resolved_settings.refresh_inactivity_days,
    )
    app.state.login_rate_limiter = LoginRateLimiter(
        runtime_dependencies.redis_client,
        ip_limit=resolved_settings.login_ip_limit,
        identifier_limit=resolved_settings.login_identifier_limit,
        window_seconds=resolved_settings.login_rate_window_seconds,
    )
    app.add_middleware(CorrelationIdMiddleware)
    install_error_handlers(app)
    app.include_router(health_router)
    internal_prefix = "/api/internal/v1"
    app.include_router(auth_router, prefix=internal_prefix)
    app.include_router(admin_router, prefix=internal_prefix)
    app.include_router(rbac_router, prefix=internal_prefix)
    app.include_router(audit_router, prefix=internal_prefix)

    if resolved_settings.demo_enabled:
        app.state.demo_agent_store = demo_agent_store or DemoAgentStore(
            resolved_settings.demo_agent_ttl_seconds
        )
        app.include_router(demo_router)

    return app


app = create_app()
