from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from wto_desktop_agent.application.capabilities import (
    CapabilityRegistry,
    ManifestService,
)
from wto_desktop_agent.application.doctor import DoctorService
from wto_desktop_agent.application.heartbeat import HeartbeatService
from wto_desktop_agent.application.identity import IdentityManager
from wto_desktop_agent.application.runtime import AgentRuntime
from wto_desktop_agent.config import AgentSettings, load_settings
from wto_desktop_agent.infrastructure.backoff import BackoffPolicy
from wto_desktop_agent.infrastructure.http_transport import HttpAgentTransport
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.logging import configure_logging
from wto_desktop_agent.platforms.factory import create_platform_adapter
from wto_desktop_agent.ports.platform import PlatformAdapter
from wto_desktop_agent.ports.time import SystemClock, SystemRandomSource


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="wto-agent")
    result.add_argument(
        "--config",
        type=Path,
        default=Path("wto-agent.toml"),
        help="Strict TOML configuration",
    )
    commands = result.add_subparsers(dest="command", required=True)
    enroll = commands.add_parser("enroll")
    enroll.add_argument("--display-name", required=True)
    source = enroll.add_mutually_exclusive_group()
    source.add_argument("--token-stdin", action="store_true")
    source.add_argument(
        "--token-env",
        metavar="NAME",
        help="Read the one-use token from the named environment variable",
    )
    run = commands.add_parser("run")
    run.add_argument("--once", action="store_true")
    commands.add_parser("status")
    doctor = commands.add_parser("doctor")
    doctor.add_argument("--json", action="store_true", dest="as_json")
    capabilities = commands.add_parser("capabilities")
    capabilities.add_argument("--json", action="store_true", dest="as_json")
    return result


def _token(args: argparse.Namespace) -> str:
    if args.token_stdin:
        value = sys.stdin.readline().strip()
    elif args.token_env:
        value = os.environ.get(str(args.token_env), "").strip()
    else:
        value = getpass.getpass("Enrollment bootstrap value > ").strip()
    if not value:
        raise ValueError("an enrollment token is required")
    return value


def _components(
    config_path: Path,
) -> tuple[AgentSettings, PlatformAdapter, SQLiteStore, HttpAgentTransport, IdentityManager]:
    preliminary = load_settings(config_path)
    platform = create_platform_adapter(in_memory=preliminary.allow_in_memory_secret_store)
    settings = preliminary
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    settings.effective_artifacts_dir.mkdir(parents=True, exist_ok=True)
    store = SQLiteStore(settings.database_path)
    transport = HttpAgentTransport(
        settings.server_url,
        timeout_seconds=settings.request_timeout_seconds,
        ca_bundle=settings.ca_bundle,
    )
    identity = IdentityManager(
        store,
        platform,
        transport,
        SystemClock(),
        allow_insecure_development_store=settings.allow_in_memory_secret_store,
    )
    return settings, platform, store, transport, identity


async def _run(args: argparse.Namespace) -> int:
    settings, platform, store, transport, identity = _components(args.config)
    configure_logging(settings.log_level)
    try:
        if args.command == "enroll":
            store.initialize()
            token = _token(args)
            try:
                enrolled = await identity.enroll(token=token, display_name=args.display_name)
            finally:
                del token
            print(json.dumps({"agent_id": enrolled["agent_id"], "status": "enrolled"}))
            return 0
        if args.command == "status":
            store.initialize()
            current = store.identity()
            safe = {
                "enrolled": bool(current and current.get("agent_id")),
                "agent_id": current.get("agent_id") if current else None,
                "platform": platform.platform_id,
                "rotation_state": current.get("rotation_state") if current else None,
                "schema_version": 1,
            }
            print(json.dumps(safe, sort_keys=True))
            return 0
        if args.command == "doctor":
            checks = DoctorService(settings, store, platform).run()
            if args.as_json:
                print(json.dumps([check.model_dump() for check in checks], sort_keys=True))
            else:
                for check in checks:
                    print(f"{check.status:8} {check.name}: {check.detail}")
            return 1 if any(check.status == "BLOCKED" for check in checks) else 0
        registry = CapabilityRegistry(platform)
        if args.command == "capabilities":
            entries = registry.entries()
            if args.as_json:
                print(json.dumps(entries, sort_keys=True))
            else:
                for entry in entries:
                    implementation = entry["implementation_status"]
                    print(f"{entry['id']}: {implementation['status']}")  # type: ignore[index]
            return 0
        if args.command == "run":
            runtime = AgentRuntime(
                store,
                identity,
                ManifestService(store, registry, transport, platform, SystemClock()),
                HeartbeatService(store, transport, SystemClock()),
                SystemClock(),
                heartbeat_interval_seconds=settings.heartbeat_interval_seconds,
                backoff=BackoffPolicy(
                    settings.backoff_initial_seconds,
                    settings.backoff_max_seconds,
                    settings.backoff_multiplier,
                    settings.backoff_jitter_ratio,
                ),
                random_source=SystemRandomSource(),
            )
            await runtime.run(once=bool(args.once))
            return 0
        raise RuntimeError("unknown command")
    finally:
        await transport.close()


def main(argv: Sequence[str] | None = None) -> None:
    args = parser().parse_args(argv)
    try:
        raise SystemExit(asyncio.run(_run(args)))
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except Exception as error:
        print(f"wto-agent failed: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(1) from None
