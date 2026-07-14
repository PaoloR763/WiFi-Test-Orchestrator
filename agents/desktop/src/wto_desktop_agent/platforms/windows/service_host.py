from __future__ import annotations

import asyncio
import json
import logging
import threading
from pathlib import Path
from typing import ClassVar

import servicemanager
import win32service
import win32serviceutil

from wto_desktop_agent.application.capabilities import CapabilityRegistry, ManifestService
from wto_desktop_agent.application.heartbeat import HeartbeatService
from wto_desktop_agent.application.runtime import AgentRuntime
from wto_desktop_agent.infrastructure.backoff import BackoffPolicy
from wto_desktop_agent.logging import configure_logging
from wto_desktop_agent.platforms.windows.acl import SERVICE_NAME, lookup_service_sid
from wto_desktop_agent.platforms.windows.enrollment_ipc import (
    EnrollmentIpcRequest,
    EnrollmentIpcResponse,
    EnrollmentPipeServer,
)
from wto_desktop_agent.ports.time import SystemClock, SystemRandomSource

LOGGER = logging.getLogger(__name__)
PURGE_CONTROL_CODE = 128


class WtoAgentService(win32serviceutil.ServiceFramework):  # type: ignore[misc]
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = "WiFi Test Orchestrator Agent"
    config_path: ClassVar[Path | None] = None

    def __init__(self, args: list[str]) -> None:
        super().__init__(args)
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.power_event = threading.Event()
        self.purge_event = threading.Event()

    def GetAcceptedControls(self) -> int:  # noqa: N802
        return int(
            int(super().GetAcceptedControls())
            | int(win32service.SERVICE_ACCEPT_PAUSE_CONTINUE)
            | int(win32service.SERVICE_ACCEPT_SHUTDOWN)
            | int(win32service.SERVICE_ACCEPT_POWEREVENT)
        )

    def SvcStop(self) -> None:  # noqa: N802
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.stop_event.set()

    def SvcShutdown(self) -> None:  # noqa: N802
        self.stop_event.set()

    def SvcPause(self) -> None:  # noqa: N802
        self.pause_event.set()
        self.ReportServiceStatus(win32service.SERVICE_PAUSED)

    def SvcContinue(self) -> None:  # noqa: N802
        self.pause_event.clear()
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)

    def SvcOtherEx(self, control: int, event_type: int, data: object) -> None:  # noqa: N802
        del event_type, data
        if control == win32service.SERVICE_CONTROL_POWEREVENT:
            self.power_event.set()
        elif control == PURGE_CONTROL_CODE:
            self.purge_event.set()

    def SvcDoRun(self) -> None:  # noqa: N802
        if self.config_path is None:
            raise RuntimeError("service configuration path was not provided")
        asyncio.run(
            run_service(
                self.config_path,
                stop_event=self.stop_event,
                pause_event=self.pause_event,
                power_event=self.power_event,
                purge_event=self.purge_event,
            )
        )


async def _enroll_service(
    config_path: Path, request: EnrollmentIpcRequest
) -> EnrollmentIpcResponse:
    from wto_desktop_agent.cli import _components

    _, _, store, transport, identity = _components(config_path)
    try:
        store.initialize()
        result = await identity.enroll(
            token=request.enrollment_token, display_name=request.display_name
        )
        return EnrollmentIpcResponse(status="enrolled", agent_id=str(result["agent_id"]))
    except Exception as error:
        return EnrollmentIpcResponse(status="failed", error_code=type(error).__name__)
    finally:
        await transport.close()


async def run_service(
    config_path: Path,
    *,
    stop_event: threading.Event,
    pause_event: threading.Event,
    power_event: threading.Event,
    purge_event: threading.Event,
) -> None:
    from wto_desktop_agent.cli import _components

    settings, platform, store, transport, identity = _components(config_path)
    configure_logging(
        settings.log_level,
        log_path=settings.state_dir.parent / "logs" / "agent.jsonl",
    )
    store.initialize()
    while not stop_event.is_set() and not (store.identity() or {}).get("agent_id"):
        server = EnrollmentPipeServer(
            lambda request: _enroll_service(config_path, request), lookup_service_sid()
        )
        try:
            await asyncio.to_thread(server.serve_once, 5.0)
        except TimeoutError:
            continue
    if stop_event.is_set():
        await transport.close()
        return
    await transport.close()
    settings, platform, store, transport, identity = _components(config_path)

    reconcile = getattr(platform.network_controller, "reconcile_incomplete", None)
    if reconcile is not None:
        await reconcile()
    registry = CapabilityRegistry(platform)
    clock = SystemClock()
    runtime = AgentRuntime(
        store,
        identity,
        ManifestService(store, registry, transport, platform, clock),
        HeartbeatService(store, transport, clock),
        clock,
        heartbeat_interval_seconds=settings.heartbeat_interval_seconds,
        backoff=BackoffPolicy(
            settings.backoff_initial_seconds,
            settings.backoff_max_seconds,
            settings.backoff_multiplier,
            settings.backoff_jitter_ratio,
        ),
        random_source=SystemRandomSource(),
    )
    await runtime.start()
    try:
        while not stop_event.is_set():
            if pause_event.is_set():
                await asyncio.sleep(0.2)
                continue
            if power_event.is_set():
                power_event.clear()
                invalidate = getattr(platform.wifi_collector, "invalidate_runtime_state", None)
                if invalidate is not None:
                    invalidate()
                LOGGER.info(
                    "power resume invalidated Windows observations",
                    extra={"event": "power_resume"},
                )
            if purge_event.is_set():
                purge_event.clear()
                status_path = settings.state_dir / "purge-status.json"
                payload = {"schema_version": "1.0.0", "status": "failed"}
                try:
                    identity.purge_local_identity()
                    payload["status"] = "purged"
                except Exception:
                    LOGGER.error(
                        "service-owned identity purge failed",
                        extra={"event": "identity_purge"},
                    )
                temporary = status_path.with_suffix(".tmp")
                temporary.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
                temporary.replace(status_path)
            try:
                await runtime.cycle()
            except Exception as error:
                LOGGER.warning(
                    "service cycle failed",
                    extra={"event": "service_cycle", "exception_type": type(error).__name__},
                )
            await _wait_interruptible(stop_event, settings.heartbeat_interval_seconds)
    finally:
        await runtime.shutdown()
        await transport.close()


async def _wait_interruptible(event: threading.Event, seconds: float) -> None:
    elapsed = 0.0
    while not event.is_set() and elapsed < seconds:
        interval = min(0.25, seconds - elapsed)
        await asyncio.sleep(interval)
        elapsed += interval


def run_service_dispatcher(config_path: Path) -> None:
    WtoAgentService.config_path = config_path.resolve(strict=True)
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(WtoAgentService)
    servicemanager.StartServiceCtrlDispatcher()
