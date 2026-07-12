from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from redis import Redis

from wto_backend.security.passwords import PasswordManager
from wto_backend.security.rate_limit import LoginRateLimiter, RateLimitUnavailableError
from wto_backend.security.tokens import InvalidAccessTokenError, TokenManager


def password_manager(**overrides: int) -> PasswordManager:
    values = {"memory_cost": 65536, "time_cost": 3, "parallelism": 1}
    values.update(overrides)
    return PasswordManager(**values)


def test_argon2id_hash_verify_and_salt() -> None:
    manager = password_manager()
    first = manager.hash("a-valid-password-1")
    second = manager.hash("a-valid-password-1")
    assert first.startswith("$argon2id$v=19$m=65536,t=3,p=1$")
    assert first != second
    assert manager.verify("a-valid-password-1", first) == (True, None)
    assert manager.verify("wrong-password", first) == (False, None)


def test_argon2_rehash_when_parameters_change() -> None:
    original = password_manager().hash("a-valid-password-2")
    valid, replacement = password_manager(time_cost=4).verify("a-valid-password-2", original)
    assert valid is True
    assert replacement is not None
    assert "$m=65536,t=4,p=1$" in replacement


def token_manager() -> TokenManager:
    return TokenManager(signing_key="k" * 48, issuer="issuer", audience="audience", ttl_minutes=10)


def test_access_token_round_trip_has_required_identity() -> None:
    manager = token_manager()
    user_id, session_id = uuid4(), uuid4()
    token = manager.issue_access(user_id=user_id, session_id=session_id, auth_version=7)
    assert jwt.get_unverified_header(token) == {"alg": "HS256", "typ": "at+jwt"}
    claims = manager.decode_access(token)
    assert claims.user_id == user_id
    assert claims.session_id == session_id
    assert claims.auth_version == 7


@pytest.mark.parametrize(
    ("change", "value"),
    [("iss", "wrong"), ("aud", "wrong"), ("token_type", "refresh")],
)
def test_access_token_rejects_invalid_claims(change: str, value: str) -> None:
    manager = token_manager()
    now = datetime.now(UTC)
    payload = {
        "iss": "issuer",
        "aud": "audience",
        "sub": str(uuid4()),
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=1),
        "jti": str(uuid4()),
        "token_type": "access",
        "sid": str(uuid4()),
        "auth_version": 1,
    }
    payload[change] = value
    token = jwt.encode(payload, "k" * 48, algorithm="HS256", headers={"typ": "at+jwt"})
    with pytest.raises(InvalidAccessTokenError):
        manager.decode_access(token)


def test_access_token_rejects_expired_bad_signature_and_algorithm() -> None:
    manager = token_manager()
    now = datetime.now(UTC)
    base = {
        "iss": "issuer",
        "aud": "audience",
        "sub": str(uuid4()),
        "iat": now - timedelta(minutes=2),
        "nbf": now - timedelta(minutes=2),
        "exp": now - timedelta(minutes=1),
        "jti": str(uuid4()),
        "token_type": "access",
        "sid": str(uuid4()),
        "auth_version": 1,
    }
    expired = jwt.encode(base, "k" * 48, algorithm="HS256", headers={"typ": "at+jwt"})
    bad_signature = jwt.encode(
        {**base, "exp": now + timedelta(minutes=1)},
        "x" * 48,
        algorithm="HS256",
        headers={"typ": "at+jwt"},
    )
    wrong_algorithm = jwt.encode(
        {**base, "exp": now + timedelta(minutes=1)},
        "k" * 48,
        algorithm="HS384",
        headers={"typ": "at+jwt"},
    )
    for token in (expired, bad_signature, wrong_algorithm):
        with pytest.raises(InvalidAccessTokenError):
            manager.decode_access(token)


def test_login_rate_limiter_fails_closed_when_redis_is_unavailable() -> None:
    limiter = LoginRateLimiter(
        Redis(host="127.0.0.1", port=1, socket_timeout=0.01),
        ip_limit=5,
        identifier_limit=5,
        window_seconds=60,
    )
    with pytest.raises(RateLimitUnavailableError):
        limiter.check(ip_fingerprint="ip", identifier_fingerprint="identifier")
