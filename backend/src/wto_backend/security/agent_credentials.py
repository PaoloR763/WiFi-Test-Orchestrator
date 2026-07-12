from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from uuid import UUID


class InvalidMachineSecretError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedMachineSecret:
    locator: UUID
    secret: str


def _new_secret(prefix: str, locator: UUID) -> tuple[str, str]:
    secret = secrets.token_urlsafe(32)
    return f"{prefix}.{locator}.{secret}", secret


def new_enrollment_token(locator: UUID) -> tuple[str, str]:
    return _new_secret("wto_enr_1", locator)


def new_agent_credential(locator: UUID) -> tuple[str, str]:
    return _new_secret("wto_ac_1", locator)


def parse_machine_secret(value: str, *, prefix: str) -> ParsedMachineSecret:
    parts = value.split(".")
    if len(parts) != 3 or parts[0] != prefix or len(parts[2]) != 43:
        raise InvalidMachineSecretError
    try:
        locator = UUID(parts[1])
    except ValueError as error:
        raise InvalidMachineSecretError from error
    if str(locator) != parts[1] or not all(
        character.isalnum() or character in "-_" for character in parts[2]
    ):
        raise InvalidMachineSecretError
    return ParsedMachineSecret(locator=locator, secret=parts[2])


def secret_digest(key: str, secret: str) -> bytes:
    return hmac.new(key.encode("utf-8"), secret.encode("ascii"), hashlib.sha256).digest()


def verify_secret(key: str, secret: str, expected: bytes) -> bool:
    return hmac.compare_digest(secret_digest(key, secret), expected)
