from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import jwt


class InvalidAccessTokenError(Exception):
    pass


@dataclass(frozen=True)
class AccessClaims:
    user_id: UUID
    session_id: UUID
    auth_version: int
    jti: UUID


class TokenManager:
    algorithm = "HS256"

    def __init__(self, *, signing_key: str, issuer: str, audience: str, ttl_minutes: int) -> None:
        self._signing_key = signing_key
        self._issuer = issuer
        self._audience = audience
        self._ttl = timedelta(minutes=ttl_minutes)

    def issue_access(self, *, user_id: UUID, session_id: UUID, auth_version: int) -> str:
        now = datetime.now(UTC)
        payload: dict[str, Any] = {
            "iss": self._issuer,
            "aud": self._audience,
            "sub": str(user_id),
            "iat": now,
            "nbf": now,
            "exp": now + self._ttl,
            "jti": str(uuid4()),
            "token_type": "access",
            "sid": str(session_id),
            "auth_version": auth_version,
        }
        return jwt.encode(
            payload,
            self._signing_key,
            algorithm=self.algorithm,
            headers={"typ": "at+jwt"},
        )

    def decode_access(self, token: str) -> AccessClaims:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != self.algorithm or header.get("typ") != "at+jwt":
                raise InvalidAccessTokenError
            payload = jwt.decode(
                token,
                self._signing_key,
                algorithms=[self.algorithm],
                issuer=self._issuer,
                audience=self._audience,
                options={
                    "require": [
                        "iss",
                        "aud",
                        "sub",
                        "iat",
                        "nbf",
                        "exp",
                        "jti",
                        "token_type",
                        "sid",
                        "auth_version",
                    ]
                },
            )
            if payload["token_type"] != "access" or not isinstance(  # noqa: S105
                payload["auth_version"], int
            ):
                raise InvalidAccessTokenError
            return AccessClaims(
                user_id=UUID(payload["sub"]),
                session_id=UUID(payload["sid"]),
                auth_version=payload["auth_version"],
                jti=UUID(payload["jti"]),
            )
        except (jwt.PyJWTError, KeyError, TypeError, ValueError) as error:
            raise InvalidAccessTokenError from error

    @staticmethod
    def new_refresh_token() -> tuple[str, bytes]:
        token = secrets.token_urlsafe(32)
        return token, hashlib.sha256(token.encode("ascii")).digest()

    @staticmethod
    def refresh_digest(token: str) -> bytes:
        return hashlib.sha256(token.encode("utf-8")).digest()
