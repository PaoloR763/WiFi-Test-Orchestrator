from __future__ import annotations

from typing import Literal


class NativeWifiError(RuntimeError):
    def __init__(
        self,
        operation: str,
        code: int,
        category: Literal[
            "access_denied",
            "invalid_state",
            "service_stopped",
            "timeout",
            "not_found",
            "unsupported",
            "failed",
        ] = "failed",
    ) -> None:
        self.operation = operation
        self.code = code
        self.category = category
        super().__init__(f"{operation} failed with Win32 code {code} ({category})")


def raise_for_code(operation: str, code: int) -> None:
    if code == 0:
        return
    categories = {
        5: "access_denied",
        50: "unsupported",
        1062: "service_stopped",
        1168: "not_found",
        1460: "timeout",
        5023: "invalid_state",
    }
    raise NativeWifiError(operation, code, categories.get(code, "failed"))  # type: ignore[arg-type]
