from __future__ import annotations

from collections.abc import Callable

from fastapi import Request
from starlette.datastructures import Headers

from wto_backend.api.dependencies import effective_client_ip
from wto_backend.config import Settings


def request_for(peer: str, headers: dict[str, str]) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": Headers(headers).raw,
        "client": (peer, 1234),
    }
    return Request(scope)


def test_untrusted_peer_cannot_spoof_forwarded_ip(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(trusted_proxy_cidrs="10.0.0.10/32")
    request = request_for("198.51.100.8", {"X-Real-IP": "203.0.113.9"})
    assert effective_client_ip(request, settings) == "198.51.100.8"


def test_trusted_proxy_can_supply_effective_ip(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(trusted_proxy_cidrs="10.0.0.10/32")
    request = request_for("10.0.0.10", {"X-Real-IP": "203.0.113.9"})
    assert effective_client_ip(request, settings) == "203.0.113.9"
