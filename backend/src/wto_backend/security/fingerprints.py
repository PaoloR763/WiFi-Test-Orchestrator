from __future__ import annotations

import hashlib
import hmac


def hmac_fingerprint(key: str, value: str) -> str:
    return hmac.new(key.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
