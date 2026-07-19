from __future__ import annotations

import asyncio
import os
import platform
from pathlib import Path
from typing import NoReturn, cast

from pydantic import BaseModel, ConfigDict, Field

from wto_desktop_agent.application.artifacts import SQLiteArtifactStager
from wto_desktop_agent.config import AgentSettings
from wto_desktop_agent.domain.errors import (
    MutationCommitIndeterminateError,
    SecureStoreUnavailableError,
)
from wto_desktop_agent.domain.models import DoctorCheck
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.platforms.common import (
    CommandSpec,
    LinuxCleanupScope,
    LinuxProcessRunner,
    UnsupportedNetworkController,
)
from wto_desktop_agent.platforms.linux.capability_manifest import (
    linux_capability_overrides,
)
from wto_desktop_agent.platforms.linux.capture import (
    CaptureCoordinator,
    CaptureLiveDependencies,
    CaptureWorkspace,
    DeferredCaptureCoordinator,
    FileCaptureJournal,
    UnavailableControlPlaneAuthorization,
)
from wto_desktop_agent.platforms.linux.capture_backend import (
    LinuxCommandCaptureBackend,
    build_capture_execution_plan,
)
from wto_desktop_agent.platforms.linux.capture_commands import capture_command_specs
from wto_desktop_agent.platforms.linux.capture_recovery import CaptureRecoveryStore
from wto_desktop_agent.platforms.linux.cgroup import CgroupV2Manager
from wto_desktop_agent.platforms.linux.inventory import (
    LinuxInventoryCollector,
    ProviderReadiness,
    ReadinessState,
)
from wto_desktop_agent.platforms.linux.network_manager import NetworkManagerDbusProvider
from wto_desktop_agent.platforms.linux.parsers import validate_interface_name
from wto_desktop_agent.platforms.linux.replay import TcpreplayValidator
from wto_desktop_agent.platforms.linux.secret_store import (
    LinuxEncryptedFileSecretStore,
    LinuxSecretServiceStore,
)
from wto_desktop_agent.platforms.linux.service_manager import LinuxServiceManager
from wto_desktop_agent.platforms.linux.tooling import (
    ToolStatus,
    effective_capabilities,
    inspect_tool,
    monitor_capable_interfaces,
    probe_dumpcap,
    probe_tool,
)
from wto_desktop_agent.ports.platform import SecretStore


class _NoArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _InterfaceArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")
    interface: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$")


class UnavailableLinuxSecretStore:
    def __init__(self, error: SecureStoreUnavailableError | None = None) -> None:
        self._commit_indeterminate = isinstance(error, MutationCommitIndeterminateError)
        self._reason = str(error) if error is not None else "Linux secure storage is unavailable"

    @property
    def secure(self) -> bool:
        return self._commit_indeterminate

    def _raise_unavailable(self) -> NoReturn:
        if self._commit_indeterminate:
            raise MutationCommitIndeterminateError()
        raise SecureStoreUnavailableError(self._reason)

    def put(self, key: str, value: str) -> None:
        del key, value
        self._raise_unavailable()

    def get(self, key: str) -> str | None:
        del key
        self._raise_unavailable()

    def delete(self, key: str) -> None:
        del key
        self._raise_unavailable()

    def doctor(self) -> DoctorCheck:
        if self._commit_indeterminate:
            return DoctorCheck(
                name="secret_store",
                status="BLOCKED",
                detail="BLOCKED_MUTATION_COMMIT_INDETERMINATE",
            )
        return DoctorCheck(
            name="secret_store",
            status="BLOCKED",
            detail="The explicitly selected Linux secret backend is unavailable",
        )


def _trusted_environment() -> dict[str, str]:
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    }


def _commands(
    settings: AgentSettings,
) -> tuple[
    dict[str, CommandSpec],
    dict[str, bool],
    dict[str, ProviderReadiness],
    dict[str, ToolStatus],
]:
    root = Path("/").resolve()
    environment = _trusted_environment()
    commands: dict[str, CommandSpec] = {}
    inspected_tools = {
        name: inspect_tool(name)
        for name in (
            "ip",
            "iw",
            "ethtool",
            "nmcli",
            "dumpcap",
            "flent",
            "netperf",
            "tcpreplay",
            "getcap",
        )
    }
    paths = {
        name: status.path if status.secure and status.access == "allowed" else None
        for name, status in inspected_tools.items()
    }
    identities = {name: status.identity for name, status in inspected_tools.items()}
    ip = paths["ip"]
    if ip is not None:
        commands["linux.ip.address-json"] = CommandSpec(
            command_id="linux.ip.address-json",
            executable=ip,
            argument_model=_NoArguments,
            build_argv=lambda _: [
                "-details",
                "-statistics",
                "-json",
                "address",
                "show",
            ],
            cwd=root,
            environment=environment,
            max_output_bytes=4_194_304,
            linux_cleanup_scope=LinuxCleanupScope.LEADER_ONLY,
            executable_identity=identities["ip"],
        )
        commands["linux.ip.route-json"] = CommandSpec(
            command_id="linux.ip.route-json",
            executable=ip,
            argument_model=_NoArguments,
            build_argv=lambda _: ["-json", "route", "show", "table", "all"],
            cwd=root,
            environment=environment,
            max_output_bytes=2_097_152,
            linux_cleanup_scope=LinuxCleanupScope.LEADER_ONLY,
            executable_identity=identities["ip"],
        )
        commands["linux.ip.route6-json"] = CommandSpec(
            command_id="linux.ip.route6-json",
            executable=ip,
            argument_model=_NoArguments,
            build_argv=lambda _: ["-6", "-json", "route", "show", "table", "all"],
            cwd=root,
            environment=environment,
            max_output_bytes=2_097_152,
            linux_cleanup_scope=LinuxCleanupScope.LEADER_ONLY,
            executable_identity=identities["ip"],
        )
    iw = paths["iw"]
    if iw is not None:
        commands["linux.iw.dev"] = CommandSpec(
            command_id="linux.iw.dev",
            executable=iw,
            argument_model=_NoArguments,
            build_argv=lambda _: ["dev"],
            cwd=root,
            environment=environment,
            linux_cleanup_scope=LinuxCleanupScope.LEADER_ONLY,
            executable_identity=identities["iw"],
        )
        commands["linux.iw.link"] = CommandSpec(
            command_id="linux.iw.link",
            executable=iw,
            argument_model=_InterfaceArguments,
            build_argv=lambda value: [
                "dev",
                validate_interface_name(value.interface),
                "link",
            ],
            cwd=root,
            environment=environment,
            linux_cleanup_scope=LinuxCleanupScope.LEADER_ONLY,
            executable_identity=identities["iw"],
        )
        commands["linux.iw.info"] = CommandSpec(
            command_id="linux.iw.info",
            executable=iw,
            argument_model=_InterfaceArguments,
            build_argv=lambda value: [
                "dev",
                validate_interface_name(value.interface),
                "info",
            ],
            cwd=root,
            environment=environment,
            linux_cleanup_scope=LinuxCleanupScope.LEADER_ONLY,
            executable_identity=identities["iw"],
        )
    ethtool = paths["ethtool"]
    if ethtool is not None:
        commands["linux.ethtool.driver"] = CommandSpec(
            command_id="linux.ethtool.driver",
            executable=ethtool,
            argument_model=_InterfaceArguments,
            build_argv=lambda value: ["-i", validate_interface_name(value.interface)],
            cwd=root,
            environment=environment,
            linux_cleanup_scope=LinuxCleanupScope.LEADER_ONLY,
            executable_identity=identities["ethtool"],
        )
    tools = {name: status.installed for name, status in inspected_tools.items()}
    readiness: dict[str, ProviderReadiness] = {}
    for name, status in inspected_tools.items():
        state: ReadinessState
        if not status.installed:
            state = "command_missing"
        elif status.access != "allowed":
            state = "permission_denied"
        elif not status.secure:
            state = "provider_failed"
        else:
            state = "installed"
        readiness[name] = ProviderReadiness(status.installed, state, status.reason)
    commands.update(
        capture_command_specs(
            paths=paths,
            identities=identities,
            artifact_root=settings.effective_artifacts_dir,
            environment=environment,
        )
    )
    return commands, tools, readiness, inspected_tools


class LinuxPlatformAdapter:
    def __init__(self, settings: AgentSettings, store: SQLiteStore) -> None:
        self._settings = settings
        self._store = store
        self._control_plane_authorization = UnavailableControlPlaneAuthorization()
        self._network = UnsupportedNetworkController()
        self._secrets: SecretStore | None = None
        self._live_initialized = False
        self._cgroups: CgroupV2Manager | None = None
        self._process: LinuxProcessRunner | None = None
        self._services: LinuxServiceManager | None = None
        self._wifi: LinuxInventoryCollector | None = None
        self._capture_live: CaptureCoordinator | None = None
        self._replay: TcpreplayValidator | None = None
        self._dumpcap: ToolStatus | None = None
        self._flent: ToolStatus | None = None
        self._netperf: ToolStatus | None = None
        self._tcpreplay: ToolStatus | None = None
        self._monitor_interfaces: frozenset[str] = frozenset()
        self._effective_capabilities: frozenset[str] = frozenset()
        self._capture = DeferredCaptureCoordinator(
            state_dir=settings.state_dir,
            artifact_root=settings.effective_artifacts_dir,
            capture_plan_builder=build_capture_execution_plan,
            live_factory=self._live_capture_provider,
            role=settings.node_role,
            enabled=settings.capture_enabled,
            agent_id_provider=self._agent_id,
            authorization=self._control_plane_authorization,
            allowed_interfaces=settings.allowed_capture_interfaces,
            protected_interfaces=settings.protected_capture_interfaces,
            allowed_channels=settings.allowed_capture_channels,
            allowed_frequencies_mhz=settings.allowed_capture_frequencies_mhz,
            allowed_widths_mhz=settings.allowed_capture_widths_mhz,
            max_duration_seconds=settings.capture_max_duration_seconds,
            max_size_bytes=settings.capture_max_size_bytes,
        )

    def _initialize_live(self) -> None:
        if self._live_initialized:
            return
        settings = self._settings
        commands, tools, tool_readiness, inspected_tools = _commands(settings)
        self._cgroups = CgroupV2Manager()
        self._process = LinuxProcessRunner(commands, cgroup_manager=self._cgroups)
        self._services = LinuxServiceManager(settings.node_role, settings.state_dir)
        network_manager_installed = bool(
            tool_readiness["nmcli"].installed or Path("/usr/sbin/NetworkManager").is_file()
        )
        self._wifi = LinuxInventoryCollector(
            NetworkManagerDbusProvider(
                total_timeout_seconds=settings.linux_inventory_timeout_seconds
            ),
            self._process,
            commands=frozenset(commands),
            tools=tools,
            network_manager_installed=network_manager_installed,
            systemd_available=self._services.provider_available,
            inventory_timeout_seconds=settings.linux_inventory_timeout_seconds,
            tool_readiness=tool_readiness,
        )
        self._dumpcap = probe_dumpcap(
            dumpcap=inspected_tools["dumpcap"],
            getcap=inspected_tools["getcap"],
        )
        self._flent = probe_tool("flent", ["--version"], inspected=inspected_tools["flent"])
        self._netperf = probe_tool("netperf", ["-V"], inspected=inspected_tools["netperf"])
        self._tcpreplay = probe_tool(
            "tcpreplay", ["--version"], inspected=inspected_tools["tcpreplay"]
        )
        self._monitor_interfaces = monitor_capable_interfaces(
            settings.allowed_capture_interfaces,
            iw=inspected_tools["iw"],
        )
        process_capabilities = effective_capabilities()
        self._effective_capabilities = process_capabilities
        self._capture_live = CaptureCoordinator(
            LinuxCommandCaptureBackend(self._process, commands),
            None,
            None,
            role=settings.node_role,
            enabled=settings.capture_enabled,
            agent_id_provider=self._agent_id,
            authorization=self._control_plane_authorization,
            provider_ready=self._dumpcap.ready,
            privileged_ready={"cap_net_admin", "cap_net_raw"}.issubset(process_capabilities),
            technical_ready=bool(self._monitor_interfaces),
            tree_containment_ready=self._tree_containment_ready,
            allowed_interfaces=settings.allowed_capture_interfaces,
            protected_interfaces=settings.protected_capture_interfaces,
            allowed_channels=settings.allowed_capture_channels,
            allowed_frequencies_mhz=settings.allowed_capture_frequencies_mhz,
            allowed_widths_mhz=settings.allowed_capture_widths_mhz,
            max_duration_seconds=settings.capture_max_duration_seconds,
            max_size_bytes=settings.capture_max_size_bytes,
            provider_version=self._dumpcap.version,
            live_dependencies_factory=self._capture_live_dependencies,
        )
        self._replay = TcpreplayValidator(
            role=settings.node_role,
            policy_enabled=settings.tcpreplay_enabled,
            agent_id_provider=self._agent_id,
            authorization=self._control_plane_authorization,
            tool_ready=self._tcpreplay.ready,
            tree_containment_ready=self._tree_containment_ready,
            artifact_root=settings.approved_replay_artifacts_dir,
            approved_artifacts=settings.approved_replay_artifacts,
            allowed_interfaces=settings.allowed_replay_interfaces,
            allowed_scenarios=settings.allowed_replay_scenarios,
            namespace=settings.replay_namespace,
            max_duration_seconds=settings.replay_max_duration_seconds,
            max_rate_mbps=settings.replay_max_rate_mbps,
            max_loops=settings.replay_max_loops,
            max_size_bytes=settings.replay_max_size_bytes,
        )
        self._live_initialized = True

    def _capture_live_dependencies(self) -> CaptureLiveDependencies:
        settings = self._settings
        stager = SQLiteArtifactStager(
            self._store,
            settings.effective_artifacts_dir,
            trusted_root=settings.effective_artifacts_dir,
            staging_timeout_seconds=settings.artifact_staging_timeout_seconds,
            reconciliation_timeout_seconds=settings.artifact_reconciliation_timeout_seconds,
            reconciliation_cleanup_timeout_seconds=(settings.artifact_reconciliation_grace_seconds),
        )
        workspace: CaptureWorkspace | None = None
        journal: FileCaptureJournal | None = None
        try:
            workspace = CaptureWorkspace(stager.artifact_root)
            journal = FileCaptureJournal(settings.state_dir)
            recovery_store = CaptureRecoveryStore(
                settings.state_dir,
                settings.effective_artifacts_dir,
            )
            return CaptureLiveDependencies(
                workspace=workspace,
                stager=stager,
                journal=journal,
                recovery_store=recovery_store,
            )
        except BaseException as error:
            if journal is not None:
                try:
                    journal.close()
                except BaseException as cleanup_error:
                    error.add_note(f"capture journal cleanup also failed: {cleanup_error!r}")
            if workspace is not None:
                try:
                    workspace.close()
                except BaseException as cleanup_error:
                    error.add_note(f"capture workspace cleanup also failed: {cleanup_error!r}")
            raise

    def _live_capture_provider(self) -> CaptureCoordinator:
        self._initialize_live()
        return cast(CaptureCoordinator, self._capture_live)

    @staticmethod
    def _secret_store(settings: AgentSettings) -> SecretStore:
        backend = settings.linux_secret_backend
        if backend in {"auto", "secret_service"}:
            return LinuxSecretServiceStore(
                total_timeout_seconds=(settings.linux_secret_service_total_timeout_seconds),
                operation_timeout_seconds=(settings.linux_secret_service_operation_timeout_seconds),
            )
        if backend == "encrypted_file":
            try:
                return LinuxEncryptedFileSecretStore(settings.state_dir)
            except SecureStoreUnavailableError as error:
                return UnavailableLinuxSecretStore(error)
        return UnavailableLinuxSecretStore()

    def _agent_id(self) -> str | None:
        try:
            identity = self._store.identity_immutable()
        except Exception:
            return None
        if identity is None or identity.get("agent_id") is None:
            return None
        return str(identity["agent_id"])

    @property
    def platform_id(self) -> str:
        return "linux"

    @property
    def platform_version(self) -> str:
        release = platform.release()
        return release[:64] if release else "unknown"

    @property
    def default_state_dir(self) -> Path:
        getter = getattr(os, "geteuid", None)
        if getter is not None and getter() == 0:
            return Path("/var/lib/wto-agent")
        return Path.home() / ".local" / "state" / "wto-agent"

    @property
    def wifi_collector(self) -> LinuxInventoryCollector:
        self._initialize_live()
        return cast(LinuxInventoryCollector, self._wifi)

    @property
    def network_controller(self) -> UnsupportedNetworkController:
        return self._network

    @property
    def process_runner(self) -> LinuxProcessRunner:
        self._initialize_live()
        return cast(LinuxProcessRunner, self._process)

    @property
    def secret_store(self) -> SecretStore:
        if self._secrets is None:
            self._secrets = self._secret_store(self._settings)
        return self._secrets

    @property
    def service_manager(self) -> LinuxServiceManager:
        self._initialize_live()
        return cast(LinuxServiceManager, self._services)

    @property
    def capture_provider(self) -> DeferredCaptureCoordinator:
        return self._capture

    @property
    def replay_provider(self) -> TcpreplayValidator:
        self._initialize_live()
        return cast(TcpreplayValidator, self._replay)

    def capability_overrides(self) -> dict[str, dict[str, object]]:
        self._initialize_live()
        wifi = cast(LinuxInventoryCollector, self._wifi)
        services = cast(LinuxServiceManager, self._services)
        return self._capability_overrides(wifi.capability_overrides(), services.status())

    async def capability_overrides_async(self) -> dict[str, dict[str, object]]:
        self._initialize_live()
        wifi = cast(LinuxInventoryCollector, self._wifi)
        services = cast(LinuxServiceManager, self._services)
        wifi_overrides, service_state = await asyncio.gather(
            wifi.capability_overrides_async(),
            services.status_async(),
        )
        return self._capability_overrides(wifi_overrides, service_state)

    def _capability_overrides(
        self,
        wifi_overrides: dict[str, dict[str, object]],
        service_state: str,
    ) -> dict[str, dict[str, object]]:
        result = dict(wifi_overrides)
        dumpcap = cast(ToolStatus, self._dumpcap)
        flent = cast(ToolStatus, self._flent)
        netperf = cast(ToolStatus, self._netperf)
        tcpreplay = cast(ToolStatus, self._tcpreplay)
        result.update(
            linux_capability_overrides(
                self._settings,
                service_state=service_state,
                dumpcap=dumpcap,
                flent=flent,
                netperf=netperf,
                tcpreplay=tcpreplay,
                monitor_interfaces=self._monitor_interfaces,
                effective_capabilities=self._effective_capabilities,
                agent_id=self._agent_id(),
                authorization=self._control_plane_authorization,
                tree_containment_ready=self._tree_containment_ready(),
            )
        )
        return result

    def _tree_containment_ready(self) -> bool:
        self._initialize_live()
        return cast(CgroupV2Manager, self._cgroups).readiness.available
