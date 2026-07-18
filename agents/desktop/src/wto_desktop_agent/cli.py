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
from wto_desktop_agent.ports.plugins import CancellationToken
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
    commands.add_parser("inventory")
    wifi = commands.add_parser("wifi")
    wifi_commands = wifi.add_subparsers(dest="wifi_command", required=True)
    profiles = wifi_commands.add_parser("profiles")
    profiles.add_argument("--interface-guid", required=True)
    profiles.add_argument("--confirm", action="store_true")
    connect = wifi_commands.add_parser("connect")
    connect.add_argument("--interface-guid", required=True)
    connect.add_argument("--profile", required=True)
    connect.add_argument("--idempotency-key", required=True)
    connect.add_argument("--confirm", action="store_true")
    disconnect = wifi_commands.add_parser("disconnect")
    disconnect.add_argument("--interface-guid", required=True)
    disconnect.add_argument("--idempotency-key", required=True)
    disconnect.add_argument("--confirm", action="store_true")
    scan = wifi_commands.add_parser("scan")
    scan.add_argument("--interface-guid", required=True)
    scan.add_argument("--idempotency-key", required=True)
    scan.add_argument("--confirm", action="store_true")
    service = commands.add_parser("service")
    service_commands = service.add_subparsers(dest="service_command", required=True)
    service_commands.add_parser("run")
    install = service_commands.add_parser("install")
    install.add_argument("--executable", type=Path, default=Path(sys.executable))
    for action in ("uninstall", "start", "stop", "pause", "resume", "status"):
        service_commands.add_parser(action)
    purge = service_commands.add_parser("purge-identity")
    purge.add_argument("--confirm", action="store_true")
    service_enroll = service_commands.add_parser("enroll")
    service_enroll.add_argument("--display-name", required=True)
    service_enroll.add_argument("--token-stdin", action="store_true")
    maintenance = commands.add_parser("maintenance")
    maintenance_commands = maintenance.add_subparsers(dest="maintenance_command", required=True)
    backup = maintenance_commands.add_parser("backup")
    backup.add_argument("--destination", type=Path, required=True)
    restore = maintenance_commands.add_parser("restore")
    restore.add_argument("--source", type=Path, required=True)
    restore.add_argument("--confirm", action="store_true")
    prune = maintenance_commands.add_parser("prune-artifacts")
    prune.add_argument("--confirm", action="store_true")
    return result


def _token(args: argparse.Namespace) -> str:
    if args.token_stdin:
        value = sys.stdin.readline().strip()
    elif getattr(args, "token_env", None):
        value = os.environ.get(str(args.token_env), "").strip()
    else:
        value = getpass.getpass("Enrollment bootstrap value > ").strip()
    if not value:
        raise ValueError("an enrollment token is required")
    return value


def _components(
    config_path: Path,
) -> tuple[AgentSettings, PlatformAdapter, SQLiteStore, HttpAgentTransport, IdentityManager]:
    settings = _load_prepared_settings(config_path)
    store = SQLiteStore(settings.database_path)
    # Platform construction performs filesystem/SQLite reconciliation on
    # Linux, so the existing schema must be open before adapters are built.
    store.initialize()
    platform, transport, identity = _compose_components(settings, store)
    return settings, platform, store, transport, identity


def _compose_components(
    settings: AgentSettings,
    store: SQLiteStore,
) -> tuple[PlatformAdapter, HttpAgentTransport, IdentityManager]:
    platform = create_platform_adapter(
        in_memory=settings.allow_in_memory_secret_store,
        settings=settings,
        store=store,
    )
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
    return platform, transport, identity


def _prepare_state_directory(settings: AgentSettings) -> None:
    if sys.platform.startswith("linux"):
        from wto_desktop_agent.platforms.linux.state_directory import (
            prepare_linux_state_directory,
        )

        prepare_linux_state_directory(settings.state_dir)
        artifacts_dir = settings.effective_artifacts_dir
        if artifacts_dir != settings.state_dir:
            # Artifact staging has always required an owned 0700 root. Prepare
            # that independently so it may be a sibling or another filesystem.
            prepare_linux_state_directory(artifacts_dir)
        return
    settings.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    settings.effective_artifacts_dir.mkdir(parents=True, exist_ok=True, mode=0o700)


def _load_prepared_settings(config_path: Path) -> AgentSettings:
    settings = load_settings(config_path)
    _prepare_state_directory(settings)
    return settings


async def _run(args: argparse.Namespace) -> int:
    if args.command == "service" and args.service_command == "run":
        from wto_desktop_agent.platforms.windows.service_host import (
            run_service_dispatcher,
        )

        run_service_dispatcher(args.config)
        return 0
    if args.command == "maintenance":
        settings = _load_prepared_settings(args.config)
        store = SQLiteStore(settings.database_path)
        if args.maintenance_command == "backup":
            destination = args.destination.absolute()
            store.create_verified_backup(destination)
            print(json.dumps({"status": "verified", "destination": str(destination)}))
            return 0
        if args.maintenance_command == "prune-artifacts":
            if not args.confirm:
                raise PermissionError("artifact pruning requires explicit confirmation")
            if os.name != "posix":
                raise RuntimeError("descriptor-anchored artifact pruning requires Linux")
            from wto_desktop_agent.application.artifacts import SQLiteArtifactStager

            store.initialize()
            stager = SQLiteArtifactStager(
                store,
                settings.effective_artifacts_dir,
                trusted_root=settings.effective_artifacts_dir,
                staging_timeout_seconds=settings.artifact_staging_timeout_seconds,
                reconciliation_timeout_seconds=(settings.artifact_reconciliation_timeout_seconds),
                reconciliation_cleanup_timeout_seconds=(
                    settings.artifact_reconciliation_grace_seconds
                ),
            )
            report = await stager.prune_confirmed(
                maximum_age_seconds=settings.artifact_retention_max_age_seconds,
                retain_count=settings.artifact_retention_count,
                retain_bytes=settings.artifact_retention_bytes,
                batch_limit=settings.artifact_prune_batch_limit,
            )
            print(
                json.dumps(
                    {
                        "status": "completed",
                        "selected": report.selected,
                        "files_deleted": report.files_deleted,
                        "rows_deleted": report.rows_deleted,
                        "bytes_deleted": report.bytes_deleted,
                        "issues": report.issues,
                    },
                    sort_keys=True,
                )
            )
            return 0
        if not args.confirm:
            raise PermissionError("SQLite restore requires explicit confirmation")
        version = store.restore_verified_backup(args.source)
        print(json.dumps({"status": "restored", "schema_version": version}))
        return 0
    if args.command == "doctor":
        # Doctor is intentionally not routed through runtime directory
        # preparation: missing state is diagnostic evidence, not bootstrap work.
        settings = load_settings(args.config)
        store = SQLiteStore(settings.database_path)
        doctor_platform: PlatformAdapter | None = None
        platform_error: Exception | None = None
        diagnostic_checks = None
        if sys.platform.startswith("linux"):
            from wto_desktop_agent.platforms.linux.doctor import LinuxReadOnlyDoctor

            diagnostic_checks = await asyncio.to_thread(LinuxReadOnlyDoctor(settings).run)
        else:
            try:
                store.inspect_health()
            except Exception as error:
                platform_error = error
            else:
                try:
                    doctor_platform = create_platform_adapter(
                        in_memory=settings.allow_in_memory_secret_store,
                        settings=settings,
                        store=store,
                    )
                except Exception as error:
                    platform_error = error
        configure_logging(settings.log_level)
        checks = await asyncio.to_thread(
            DoctorService(
                settings,
                store,
                doctor_platform,
                platform_error=platform_error,
                diagnostic_checks=diagnostic_checks,
            ).run
        )
        if args.as_json:
            print(json.dumps([check.model_dump() for check in checks], sort_keys=True))
        else:
            for check in checks:
                print(f"{check.status:8} {check.name}: {check.detail}")
        return 1 if any(check.status == "BLOCKED" for check in checks) else 0
    if sys.platform.startswith("linux"):
        settings, platform, store, transport, identity = await asyncio.to_thread(
            _components, args.config
        )
    else:
        settings, platform, store, transport, identity = _components(args.config)
    configure_logging(settings.log_level)
    try:
        if args.command == "enroll":
            if platform.platform_id == "windows":
                raise PermissionError(
                    "Windows enrollment must use the service-owned administrative named pipe"
                )
            token = _token(args)
            try:
                enrolled = await identity.enroll(token=token, display_name=args.display_name)
            finally:
                del token
            print(json.dumps({"agent_id": enrolled["agent_id"], "status": "enrolled"}))
            return 0
        if args.command == "status":
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
        if args.command == "inventory":
            snapshot = await platform.wifi_collector.collect_inventory()
            print(snapshot.model_dump_json())
            return 0
        if args.command == "wifi":
            if args.wifi_command == "profiles":
                profiles = platform.network_controller.list_profiles(
                    args.interface_guid, confirmed=bool(args.confirm)
                )
                print(json.dumps({"profiles": profiles}, ensure_ascii=False, sort_keys=True))
                return 0
            common = {
                "interface_guid": args.interface_guid,
                "idempotency_key": args.idempotency_key,
                "confirmed": bool(args.confirm),
                "cancellation": CancellationToken(),
            }
            if args.wifi_command == "connect":
                connect_result = await platform.network_controller.connect(
                    **common,
                    profile_name=args.profile,
                    timeout_seconds=settings.request_timeout_seconds,
                )
                print(json.dumps(connect_result, sort_keys=True))
                return 0
            if args.wifi_command == "disconnect":
                disconnect_result = await platform.network_controller.disconnect(
                    **common,
                    timeout_seconds=settings.request_timeout_seconds,
                )
                print(json.dumps(disconnect_result, sort_keys=True))
                return 0
            if args.wifi_command == "scan":
                scan_result = await platform.network_controller.request_scan(**common)
                print(scan_result.model_dump_json())
                return 0
        if args.command == "service":
            if args.service_command == "enroll":
                if platform.platform_id != "windows":
                    raise RuntimeError("service enrollment IPC is Windows-only")
                from wto_desktop_agent.platforms.windows.enrollment_ipc import (
                    EnrollmentIpcRequest,
                    send_enrollment_request,
                )

                token = _token(args)
                try:
                    response = await asyncio.to_thread(
                        send_enrollment_request,
                        EnrollmentIpcRequest(
                            schema_version="1.0.0",
                            operation="enroll",
                            display_name=args.display_name,
                            enrollment_token=token,
                        ),
                    )
                finally:
                    del token
                print(response.model_dump_json(exclude_none=True))
                return 0 if response.status == "enrolled" else 1
            if args.service_command == "install":
                await asyncio.to_thread(
                    platform.service_manager.install, args.executable, args.config
                )
                return 0
            if args.service_command == "uninstall":
                await asyncio.to_thread(platform.service_manager.uninstall)
                return 0
            if args.service_command == "purge-identity":
                await asyncio.to_thread(
                    platform.service_manager.purge_identity,
                    confirmed=bool(args.confirm),
                )
                return 0
            if args.service_command == "status":
                status = await asyncio.to_thread(platform.service_manager.status)
                print(json.dumps({"status": status}))
                return 0
            if args.service_command in {"start", "stop", "pause", "resume"}:
                await asyncio.to_thread(platform.service_manager.control, args.service_command)
                return 0
        registry = CapabilityRegistry(platform)
        if args.command == "capabilities":
            entries = await registry.entries_async()
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
