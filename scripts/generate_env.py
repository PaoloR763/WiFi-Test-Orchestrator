from __future__ import annotations

import argparse
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / ".env"


def secret() -> str:
    return secrets.token_urlsafe(48)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    if TARGET.exists() and not args.force:
        raise SystemExit(".env already exists; use --force only to rotate local development secrets")
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
    }
    TARGET.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
    print("Generated .env with independent local-development secrets.")


if __name__ == "__main__":
    main()
