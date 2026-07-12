from __future__ import annotations

import argparse
import os
import re
import secrets
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / ".env"
PHASE04_SECRET_KEYS = (
    "WTO_ENROLLMENT_TOKEN_HMAC_KEY",
    "WTO_AGENT_CREDENTIAL_HMAC_KEY",
    "WTO_SECRET_REPLAY_ENCRYPTION_KEY",
)
ENV_KEY_PATTERN = re.compile(r"^(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=", re.MULTILINE)


def secret() -> str:
    return secrets.token_urlsafe(48)


def add_missing_phase04_secrets(target: Path) -> int:
    if not target.exists():
        raise SystemExit(".env does not exist; generate it first without --add-missing")

    original = target.read_bytes()
    try:
        text = original.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(".env must be valid UTF-8") from exc

    existing_keys = set(ENV_KEY_PATTERN.findall(text))
    missing_keys = [key for key in PHASE04_SECRET_KEYS if key not in existing_keys]
    if not missing_keys:
        print("No Phase 04 secrets were missing from .env.")
        return 0

    newline = b"\r\n" if b"\r\n" in original else b"\n"
    separator = b"" if not original or original.endswith((b"\n", b"\r")) else newline
    additions = newline.join(f"{key}={secret()}".encode() for key in missing_keys)
    with target.open("ab") as env_file:
        env_file.write(separator + additions + newline)
        env_file.flush()
        os.fsync(env_file.fileno())

    print(f"Added {len(missing_keys)} missing Phase 04 secret variable(s) to .env.")
    return len(missing_keys)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--force", action="store_true")
    operation.add_argument("--add-missing", action="store_true")
    args = parser.parse_args(argv)
    if args.add_missing:
        add_missing_phase04_secrets(TARGET)
        return
    if TARGET.exists() and not args.force:
        raise SystemExit(
            ".env already exists; use --force only to rotate local development secrets"
        )
    owner_password = secret()
    runtime_password = secret()
    values = {
        "WTO_ENVIRONMENT": "development",
        "WTO_LOG_LEVEL": "INFO",
        "WTO_DEMO_AGENT_TTL_SECONDS": "45",
        "WTO_ALLOWED_ORIGIN": "http://localhost:8080",
        "WTO_TRUSTED_PROXY_CIDRS": "172.31.0.10/32",
        "WTO_JWT_SIGNING_KEY": secret(),
        "WTO_RATE_LIMIT_HMAC_KEY": secret(),
        "WTO_AUDIT_SUBJECT_HMAC_KEY": secret(),
        "WTO_ENROLLMENT_TOKEN_HMAC_KEY": secret(),
        "WTO_AGENT_CREDENTIAL_HMAC_KEY": secret(),
        "WTO_SECRET_REPLAY_ENCRYPTION_KEY": secret(),
        "WTO_ENROLLMENT_TOKEN_MINUTES": "15",
        "WTO_AGENT_CREDENTIAL_DAYS": "90",
        "WTO_AGENT_CLOCK_SKEW_SECONDS": "300",
        "WTO_AGENT_NONCE_TTL_SECONDS": "600",
        "WTO_AGENT_REQUEST_LIMIT": "120",
        "POSTGRES_DB": "wifi_test_orchestrator",
        "POSTGRES_USER": "wto_owner",
        "POSTGRES_PASSWORD": owner_password,
        "POSTGRES_RUNTIME_USER": "wto_runtime",
        "POSTGRES_RUNTIME_PASSWORD": runtime_password,
        "WTO_POSTGRES_DB": "wifi_test_orchestrator",
        "WTO_POSTGRES_USER": "wto_runtime",
        "WTO_POSTGRES_PASSWORD": runtime_password,
        "WTO_POSTGRES_MIGRATION_USER": "wto_owner",
        "WTO_POSTGRES_MIGRATION_PASSWORD": owner_password,
        "WTO_POSTGRES_RUNTIME_ROLE": "wto_runtime",
        "WTO_POSTGRES_PORT": "5432",
        "WTO_REDIS_PORT": "6379",
        "WTO_REDIS_DB": "0",
        "SIM_AGENT_ID": "simulated-agent-01",
        "SIM_AGENT_DISPLAY_NAME": "Local simulated agent",
        "SIM_HEARTBEAT_INTERVAL_SECONDS": "10",
        "SIM_REQUEST_TIMEOUT_SECONDS": "5",
        "SIM_ENROLLMENT_TOKEN": "",
    }
    TARGET.write_text(
        "".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8"
    )
    print("Generated .env with independent local-development secrets.")


if __name__ == "__main__":
    main()
