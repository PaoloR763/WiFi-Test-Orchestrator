from __future__ import annotations

from typing import Literal

LinuxFailureKind = Literal[
    "unavailable",
    "unsupported",
    "permission_denied",
    "command_missing",
    "interface_disconnected",
    "transient_failure",
    "invalid_output",
]


class LinuxProviderError(RuntimeError):
    def __init__(self, provider: str, kind: LinuxFailureKind, detail: str) -> None:
        super().__init__(f"{provider}: {kind}")
        self.provider = provider
        self.kind = kind
        self.detail = detail
