from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Request, Response, status

from wto_backend.api.dependencies import (
    current_principal,
    effective_client_ip,
    get_auth_service,
    get_settings_from_app,
    require_cookie_origin,
)
from wto_backend.api.schemas import LoginRequest, PasswordChangeRequest, TokenResponse, UserView
from wto_backend.config import Settings
from wto_backend.domain.models import User
from wto_backend.logging import correlation_id_context
from wto_backend.security.fingerprints import hmac_fingerprint
from wto_backend.security.rate_limit import RateLimitUnavailableError
from wto_backend.security.tokens import AccessClaims
from wto_backend.services.auth import AuthService
from wto_backend.services.errors import (
    DependencyUnavailableError,
    InvalidSessionError,
    RateLimitedError,
)

router = APIRouter(prefix="/auth", tags=["internal-auth"])
REFRESH_COOKIE = "wto_refresh"


def user_view(user: User) -> UserView:
    return UserView(
        id=user.id,
        username=user.username,
        email=user.email,
        is_active=user.is_active,
        must_change_password=user.must_change_password,
        auth_version=user.auth_version,
        roles=sorted(role.key for role in user.roles),
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


def set_refresh_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        REFRESH_COOKIE,
        token,
        httponly=True,
        secure=settings.environment != "development",
        samesite="strict",
        path="/api/internal/v1/auth",
        max_age=settings.refresh_absolute_days * 86400,
    )


def clear_refresh_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        REFRESH_COOKIE,
        httponly=True,
        secure=settings.environment != "development",
        samesite="strict",
        path="/api/internal/v1/auth",
    )


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    auth: Annotated[AuthService, Depends(get_auth_service)],
    settings: Annotated[Settings, Depends(get_settings_from_app)],
) -> TokenResponse:
    normalized = payload.username.strip().lower()
    client_ip = effective_client_ip(request, settings)
    rate_identifier = hmac_fingerprint(settings.rate_limit_hmac_key.get_secret_value(), normalized)
    rate_ip = hmac_fingerprint(settings.rate_limit_hmac_key.get_secret_value(), client_ip)
    try:
        decision = request.app.state.login_rate_limiter.check(
            ip_fingerprint=rate_ip, identifier_fingerprint=rate_identifier
        )
    except RateLimitUnavailableError as error:
        raise DependencyUnavailableError from error
    if not decision.allowed:
        raise RateLimitedError
    audit_identifier = hmac_fingerprint(
        settings.audit_subject_hmac_key.get_secret_value(), normalized
    )
    audit_ip = hmac_fingerprint(settings.audit_subject_hmac_key.get_secret_value(), client_ip)
    access, refresh, user = auth.login(
        username=normalized,
        password=payload.password,
        correlation_id=correlation_id_context.get() or "unavailable",
        identifier_fingerprint=audit_identifier,
        ip_fingerprint=audit_ip,
        client_metadata={"ip_fingerprint": audit_ip},
    )
    set_refresh_cookie(response, refresh, settings)
    return TokenResponse(
        access_token=access,
        expires_in=settings.access_token_minutes * 60,
        must_change_password=user.must_change_password,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    request: Request,
    response: Response,
    auth: Annotated[AuthService, Depends(get_auth_service)],
    settings: Annotated[Settings, Depends(get_settings_from_app)],
    refresh_token: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
) -> TokenResponse:
    require_cookie_origin(request, settings)
    if refresh_token is None:
        clear_refresh_cookie(response, settings)
        raise InvalidSessionError
    try:
        access, replacement, user = auth.refresh(
            token=refresh_token, correlation_id=correlation_id_context.get() or "unavailable"
        )
    except InvalidSessionError:
        clear_refresh_cookie(response, settings)
        raise
    set_refresh_cookie(response, replacement, settings)
    return TokenResponse(
        access_token=access,
        expires_in=settings.access_token_minutes * 60,
        must_change_password=user.must_change_password,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    principal: Annotated[tuple[User, AccessClaims], Depends(current_principal)],
    auth: Annotated[AuthService, Depends(get_auth_service)],
    settings: Annotated[Settings, Depends(get_settings_from_app)],
) -> Response:
    require_cookie_origin(request, settings)
    user, claims = principal
    auth.logout(
        user=user,
        session_id=claims.session_id,
        correlation_id=correlation_id_context.get() or "unavailable",
    )
    clear_refresh_cookie(response, settings)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
def logout_all(
    request: Request,
    response: Response,
    principal: Annotated[tuple[User, AccessClaims], Depends(current_principal)],
    auth: Annotated[AuthService, Depends(get_auth_service)],
    settings: Annotated[Settings, Depends(get_settings_from_app)],
) -> Response:
    require_cookie_origin(request, settings)
    user, _ = principal
    auth.logout_all(user=user, correlation_id=correlation_id_context.get() or "unavailable")
    clear_refresh_cookie(response, settings)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=UserView)
def me(principal: Annotated[tuple[User, AccessClaims], Depends(current_principal)]) -> UserView:
    return user_view(principal[0])


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    response: Response,
    principal: Annotated[tuple[User, AccessClaims], Depends(current_principal)],
    auth: Annotated[AuthService, Depends(get_auth_service)],
    settings: Annotated[Settings, Depends(get_settings_from_app)],
) -> Response:
    require_cookie_origin(request, settings)
    auth.change_password(
        user=principal[0],
        current=payload.current_password,
        new=payload.new_password,
        correlation_id=correlation_id_context.get() or "unavailable",
    )
    clear_refresh_cookie(response, settings)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
