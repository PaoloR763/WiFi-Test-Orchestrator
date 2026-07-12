from __future__ import annotations

from collections.abc import Callable, Iterator
from ipaddress import ip_address
from typing import Annotated, cast

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from wto_backend.config import Settings
from wto_backend.domain.models import User
from wto_backend.security.tokens import AccessClaims, InvalidAccessTokenError
from wto_backend.services.auth import AuthService, permission_keys
from wto_backend.services.errors import InvalidSessionError, PermissionDeniedError

bearer = HTTPBearer(auto_error=False)


def get_settings_from_app(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def get_session(request: Request) -> Iterator[Session]:
    with request.app.state.database.session_factory() as session:
        session.info["password_manager"] = request.app.state.password_manager
        yield session


def get_auth_service(
    request: Request, session: Annotated[Session, Depends(get_session)]
) -> AuthService:
    factory = cast(Callable[[Session], AuthService], request.app.state.auth_service_factory)
    return factory(session)


def effective_client_ip(request: Request, settings: Settings) -> str:
    peer = request.client.host if request.client is not None else "127.0.0.1"
    try:
        peer_address = ip_address(peer)
    except ValueError:
        return "127.0.0.1"
    if any(peer_address in network for network in settings.trusted_proxy_networks):
        supplied = request.headers.get("X-Real-IP")
        if supplied is not None:
            try:
                return str(ip_address(supplied.strip()))
            except ValueError:
                return str(peer_address)
    return str(peer_address)


def require_cookie_origin(request: Request, settings: Settings) -> None:
    origin = request.headers.get("Origin")
    if origin is None:
        referer = request.headers.get("Referer")
        origin = "/".join(referer.split("/", 3)[:3]) if referer else None
    if origin is None or origin.rstrip("/") != settings.allowed_origin:
        raise PermissionDeniedError


def current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    auth: Annotated[AuthService, Depends(get_auth_service)],
) -> tuple[User, AccessClaims]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise InvalidSessionError
    try:
        claims = auth.tokens.decode_access(credentials.credentials)
    except InvalidAccessTokenError as error:
        raise InvalidSessionError from error
    return auth.authenticate_access(claims), claims


def require_permissions(
    *required: str,
) -> Callable[[tuple[User, AccessClaims]], tuple[User, AccessClaims]]:
    def dependency(
        principal: Annotated[tuple[User, AccessClaims], Depends(current_principal)],
    ) -> tuple[User, AccessClaims]:
        user, _ = principal
        if not set(required).issubset(permission_keys(user)):
            raise PermissionDeniedError
        return principal

    return dependency
