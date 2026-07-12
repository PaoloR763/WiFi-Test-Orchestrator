from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REQUIRED_SERVICES = {
    "reverse-proxy",
    "frontend",
    "backend",
    "worker",
    "postgres",
    "redis",
    "artifact-store",
    "simulated-agent",
}
REQUIRED_VOLUMES = {"postgres_data", "redis_data", "artifact_data"}


def compose_config() -> dict[str, Any]:
    process = subprocess.run(
        ["docker", "compose", "config", "--format", "json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(process.stdout)


def fail(message: str) -> None:
    print(f"compose policy violation: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    config = compose_config()
    services: dict[str, dict[str, Any]] = config["services"]
    missing = REQUIRED_SERVICES - services.keys()
    if missing:
        fail(f"missing default services: {sorted(missing)}")

    published = {name for name, service in services.items() if service.get("ports")}
    if published != {"reverse-proxy"}:
        fail(f"only reverse-proxy may publish ports, found: {sorted(published)}")

    for name in ("postgres", "redis", "backend", "frontend", "worker", "simulated-agent"):
        if services[name].get("ports"):
            fail(f"{name} must not publish host ports")

    for name in REQUIRED_SERVICES:
        if "healthcheck" not in services[name]:
            fail(f"{name} must define a healthcheck")

    networks = config.get("networks", {})
    internal_network = next(
        (value for key, value in networks.items() if key.endswith("internal")), None
    )
    if internal_network is None or internal_network.get("internal") is not True:
        fail("the data network must be marked internal")

    declared_volumes = set(config.get("volumes", {}).keys())
    for suffix in REQUIRED_VOLUMES:
        if not any(name.endswith(suffix) for name in declared_volumes):
            fail(f"missing named volume: {suffix}")

    for service_name, service in services.items():
        for mount in service.get("volumes", []):
            if mount.get("type") == "bind":
                fail(f"bind mount is not portable: {service_name}")

    for name, service in services.items():
        image = service.get("image")
        if isinstance(image, str) and image.endswith(":latest"):
            fail(f"floating latest image tag is forbidden: {name}")

    print("Compose policy validation passed.")


if __name__ == "__main__":
    main()
