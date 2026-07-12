from __future__ import annotations

from dataclasses import dataclass

from redis import Redis
from redis.exceptions import RedisError

_INCREMENT_SCRIPT = """
local ip_count = redis.call('INCR', KEYS[1])
if ip_count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
local identifier_count = redis.call('INCR', KEYS[2])
if identifier_count == 1 then redis.call('EXPIRE', KEYS[2], ARGV[1]) end
return {ip_count, identifier_count}
"""


class RateLimitUnavailableError(Exception):
    pass


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after: int


class LoginRateLimiter:
    def __init__(
        self,
        client: Redis[bytes],
        *,
        ip_limit: int,
        identifier_limit: int,
        window_seconds: int,
    ) -> None:
        self._client = client
        self._ip_limit = ip_limit
        self._identifier_limit = identifier_limit
        self._window = window_seconds

    def check(self, *, ip_fingerprint: str, identifier_fingerprint: str) -> RateLimitDecision:
        try:
            result = self._client.eval(  # type: ignore[no-untyped-call]
                _INCREMENT_SCRIPT,
                2,
                f"wto:login:ip:{ip_fingerprint}",
                f"wto:login:id:{identifier_fingerprint}",
                self._window,
            )
            if not isinstance(result, list) or len(result) != 2:
                raise ValueError("unexpected Redis rate-limit response")
            ip_count, identifier_count = (int(value) for value in result)
        except (RedisError, OSError, ValueError) as error:
            raise RateLimitUnavailableError from error
        allowed = ip_count <= self._ip_limit and identifier_count <= self._identifier_limit
        return RateLimitDecision(allowed=allowed, retry_after=self._window)
