from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecretReplayCipher:
    key_version = 1

    def __init__(self, key_material: str) -> None:
        self._cipher = AESGCM(hashlib.sha256(key_material.encode("utf-8")).digest())

    def encrypt(self, payload: dict[str, Any], *, associated_data: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return self._cipher.encrypt(nonce, plaintext, associated_data), nonce

    def decrypt(self, ciphertext: bytes, nonce: bytes, *, associated_data: bytes) -> dict[str, Any]:
        plaintext = self._cipher.decrypt(nonce, ciphertext, associated_data)
        value = json.loads(plaintext)
        if not isinstance(value, dict):
            raise ValueError("secret replay payload is not an object")
        return value
