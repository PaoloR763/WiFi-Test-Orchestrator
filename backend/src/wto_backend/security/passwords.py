from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type


class PasswordManager:
    def __init__(self, *, memory_cost: int, time_cost: int, parallelism: int) -> None:
        self._hasher = PasswordHasher(
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        self._dummy_hash = self._hasher.hash("dummy-password-never-authenticates")

    def hash(self, password: str) -> str:
        self.validate_password(password)
        return self._hasher.hash(password)

    def verify(self, password: str, encoded_hash: str) -> tuple[bool, str | None]:
        try:
            self._hasher.verify(encoded_hash, password)
        except (VerificationError, InvalidHashError):
            return False, None
        replacement = (
            self._hasher.hash(password) if self._hasher.check_needs_rehash(encoded_hash) else None
        )
        return True, replacement

    def dummy_verify(self, password: str) -> None:
        self.verify(password, self._dummy_hash)

    @staticmethod
    def validate_password(password: str) -> None:
        encoded_length = len(password.encode("utf-8"))
        if len(password) < 12 or encoded_length > 1024:
            raise ValueError(
                "password must contain at least 12 characters and at most 1024 UTF-8 bytes"
            )
