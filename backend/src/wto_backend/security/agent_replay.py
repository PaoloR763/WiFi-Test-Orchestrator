from __future__ import annotations

from redis import Redis
from redis.exceptions import RedisError

_RESERVE_SCRIPT = """
local nonce_ok = redis.call('SET', KEYS[1], '1', 'EX', ARGV[1], 'NX')
if not nonce_ok then return {0, 0} end
local count = redis.call('INCR', KEYS[2])
if count == 1 then redis.call('EXPIRE', KEYS[2], ARGV[2]) end
return {1, count}
"""


class AgentReplayUnavailableError(Exception):
    pass


class AgentNonceReusedError(Exception):
    pass


class AgentRateLimitedError(Exception):
    pass


class AgentReplayGuard:
    def __init__(self, client: Redis[bytes], *, nonce_ttl: int, request_limit: int) -> None:
        self._client = client
        self._nonce_ttl = nonce_ttl
        self._request_limit = request_limit

    def reserve(self, *, credential_id: str, nonce: str) -> None:
        try:
            result = self._client.eval(  # type: ignore[no-untyped-call]
                _RESERVE_SCRIPT,
                2,
                f"wto:agent:nonce:{credential_id}:{nonce}",
                f"wto:agent:rate:{credential_id}",
                self._nonce_ttl,
                60,
            )
            if not isinstance(result, list) or len(result) != 2:
                raise ValueError("unexpected Redis agent replay response")
            reserved, count = (int(item) for item in result)
        except (RedisError, OSError, ValueError) as error:
            raise AgentReplayUnavailableError from error
        if reserved != 1:
            raise AgentNonceReusedError
        if count > self._request_limit:
            raise AgentRateLimitedError
