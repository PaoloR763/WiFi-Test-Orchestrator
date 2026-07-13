from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from pydantic import BaseModel

from wto_desktop_agent.config import AgentSettings
from wto_desktop_agent.domain.errors import (
    PluginUnavailableError,
    SecureStoreUnavailableError,
)
from wto_desktop_agent.platforms.factory import create_platform_adapter
from wto_desktop_agent.ports.platform import CommandRequest
from wto_desktop_agent.ports.plugins import CancellationToken

pytestmark = [
    pytest.mark.windows,
    pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows"),
]


def test_factory_creates_real_windows_adapter_without_linux_imports(tmp_path: Path) -> None:
    assert "secretstorage" not in sys.modules
    assert not any("platforms.linux" in name for name in sys.modules)

    import pywintypes
    import win32api
    import win32con
    import win32cred
    import win32job

    from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
    from wto_desktop_agent.platforms.windows.adapter import WindowsPlatformAdapter
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner
    from wto_desktop_agent.platforms.windows.secret_store import (
        WindowsCredentialManagerStore,
    )

    settings = AgentSettings(environment="test", server_url="http://testserver", state_dir=tmp_path)
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    store.initialize()
    adapter = create_platform_adapter(in_memory=False, settings=settings, store=store)

    assert isinstance(adapter, WindowsPlatformAdapter)
    assert adapter.platform_id == "windows"
    assert isinstance(adapter.process_runner, WindowsProcessRunner)
    assert isinstance(adapter.secret_store, WindowsCredentialManagerStore)
    assert adapter.secret_store.secure is True
    assert all(
        module.__loader__ is not None
        for module in (pywintypes, win32api, win32con, win32cred, win32job)
    )
    assert "secretstorage" not in sys.modules
    assert not any("platforms.linux" in name for name in sys.modules)


def test_windows_secret_store_fails_closed_on_credential_manager_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32cred

    from wto_desktop_agent.platforms.windows.secret_store import (
        WindowsCredentialManagerStore,
    )

    store = WindowsCredentialManagerStore()
    failure = OSError("controlled Credential Manager failure")
    monkeypatch.setattr(win32cred, "CredWrite", Mock(side_effect=failure))
    monkeypatch.setattr(win32cred, "CredRead", Mock(side_effect=failure))

    with pytest.raises(SecureStoreUnavailableError, match="write failed"):
        store.put("credential-active", "controlled-test-value")
    with pytest.raises(SecureStoreUnavailableError, match="read failed"):
        store.get("credential-active")


def test_windows_credential_manager_round_trip_is_cleaned_up() -> None:
    from wto_desktop_agent.platforms.windows.secret_store import (
        WindowsCredentialManagerStore,
    )

    store = WindowsCredentialManagerStore()
    key = f"phase06-ci-{uuid4()}"
    try:
        store.put(key, "controlled-test-value")
        assert store.get(key) == "controlled-test-value"
    finally:
        store.delete(key)
    assert store.get(key) is None


@pytest.mark.asyncio
async def test_fixed_powershell_51_inventory_script_returns_strict_json(tmp_path: Path) -> None:
    from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
    from wto_desktop_agent.platforms.windows.adapter import WindowsPlatformAdapter
    from wto_desktop_agent.platforms.windows.powershell import (
        PowerShellAdapter,
        PowerShellInventory,
        parse_powershell_inventory,
    )

    settings = AgentSettings(environment="test", server_url="http://testserver", state_dir=tmp_path)
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    store.initialize()
    adapter = WindowsPlatformAdapter(settings, store)
    started = time.monotonic()
    output = await adapter.process_runner.run(
        CommandRequest(
            command_id="windows.powershell.network_inventory",
            arguments={},
            timeout_seconds=settings.windows_inventory_timeout_seconds,
        ),
        CancellationToken(),
    )
    elapsed = time.monotonic() - started
    assert output.return_code == 0, output.stderr.decode("utf-8", errors="replace")
    document = json.loads(output.stdout)
    assert set(document) == set(PowerShellInventory.model_fields)
    assert all(
        set(adapter) == set(PowerShellAdapter.model_fields) for adapter in document["adapters"]
    )
    inventory = parse_powershell_inventory(output.stdout)
    assert inventory.powershell_edition == "Desktop"
    assert inventory.powershell_version.startswith("5.1")
    assert elapsed < settings.windows_inventory_timeout_seconds


def test_powershell_51_inventory_global_queries_and_partial_failure(tmp_path: Path) -> None:
    from wto_desktop_agent.platforms.windows.powershell import (
        PowerShellAdapter,
        PowerShellAddress,
        PowerShellInventory,
        inventory_script_path,
        parse_powershell_inventory,
    )

    script_path = str(inventory_script_path()).replace("'", "''")
    harness = r"""
$ErrorActionPreference = 'Stop'
$global:queryCounts = [ordered]@{
    drivers = 0; adapters = 0; statistics = 0; ip_configuration = 0
    addresses = 0; routes = 0; dns = 0
}
function Get-CimInstance {
    param($ClassName, $Property, $OperationTimeoutSec, $ErrorAction)
    $global:queryCounts.drivers++
    [pscustomobject]@{
        DeviceID = 'PCI\MOCK'; Manufacturer = 'Mock Manufacturer'; DeviceName = 'Mock Adapter'
        DriverProviderName = 'Mock Provider'; DriverVersion = '1.2.3'
    }
}
function Get-NetAdapter {
    param([switch]$IncludeHidden, $ErrorAction)
    $global:queryCounts.adapters++
    [pscustomobject]@{
        ifIndex = 7; PnPDeviceID = 'PCI\MOCK'
        InterfaceGuid = '11111111-1111-4111-8111-111111111111'; Name = 'Wi-Fi Mock'
        InterfaceDescription = 'Mock Adapter'; Status = 'Up'; Virtual = $false
        HardwareInterface = $true; DriverDescription = 'Mock Driver'; DriverVersion = '0.0.1'
        MacAddress = '00-11-22-33-44-55'; LinkSpeed = '1 Gbps'
    }
}
function Get-NetAdapterStatistics {
    param([switch]$IncludeHidden, $ErrorAction)
    $global:queryCounts.statistics++
    [pscustomobject]@{
        ifIndex = 7; ReceivedBytes = 100; SentBytes = 200
        ReceivedUnicastPackets = 1; ReceivedMulticastPackets = 2; ReceivedBroadcastPackets = 3
        SentUnicastPackets = 4; SentMulticastPackets = 5; SentBroadcastPackets = 6
        ReceivedPacketErrors = 0; OutboundPacketErrors = 0
        ReceivedDiscardedPackets = 0; OutboundDiscardedPackets = 0
    }
}
function Get-NetIPConfiguration {
    param($ErrorAction)
    $global:queryCounts.ip_configuration++
    [pscustomobject]@{
        InterfaceIndex = 7
        IPv4DefaultGateway = @([pscustomobject]@{ NextHop = '192.0.2.1' })
        IPv6DefaultGateway = @()
    }
}
function Get-NetIPAddress {
    param($ErrorAction)
    $global:queryCounts.addresses++
    [pscustomobject]@{
        InterfaceIndex = 7; AddressFamily = 'IPv4'; IPAddress = '192.0.2.10'; PrefixLength = 24
    }
}
function Get-NetRoute {
    param($ErrorAction)
    $global:queryCounts.routes++
    throw 'controlled route provider failure'
}
function Get-DnsClientServerAddress {
    param($ErrorAction)
    $global:queryCounts.dns++
    [pscustomobject]@{ InterfaceIndex = 7; ServerAddresses = @('192.0.2.53') }
}
$inventoryScript = '__SCRIPT__'
$inventoryText = [string](& $inventoryScript)
[ordered]@{
    counts = $global:queryCounts
    inventory = ($inventoryText | ConvertFrom-Json)
} | ConvertTo-Json -Compress -Depth 10
""".replace(
        "__SCRIPT__", script_path
    )
    harness_path = tmp_path / "inventory-partial-failure.ps1"
    harness_path.write_text(harness, encoding="utf-8")

    completed = subprocess.run(  # noqa: S603 - fixed system executable and local harness
        [
            str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(harness_path),
        ],
        check=False,
        capture_output=True,
        timeout=30.0,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    envelope = json.loads(completed.stdout)
    assert set(envelope["counts"].values()) == {1}
    raw_inventory = envelope["inventory"]
    assert set(raw_inventory) == set(PowerShellInventory.model_fields)
    assert len(raw_inventory["adapters"]) == 1
    raw_adapter = raw_inventory["adapters"][0]
    assert set(raw_adapter) == set(PowerShellAdapter.model_fields)
    assert set(raw_adapter["addresses"][0]) == set(PowerShellAddress.model_fields)
    assert raw_adapter["routes_available"] is False
    assert raw_adapter["routes"] == []
    assert raw_adapter["statistics_available"] is True
    assert raw_adapter["ip_configuration_available"] is True
    assert raw_adapter["addresses_available"] is True
    assert raw_adapter["dns_available"] is True
    assert (
        parse_powershell_inventory(json.dumps(raw_inventory, separators=(",", ":")).encode())
        .adapters[0]
        .routes
        == []
    )


def test_native_wifi_open_enum_is_honest_without_requiring_hardware() -> None:
    from wto_desktop_agent.platforms.windows.native_wifi.client import NativeWifiClient
    from wto_desktop_agent.platforms.windows.native_wifi.errors import NativeWifiError

    try:
        interfaces = NativeWifiClient().interfaces()
        assert all(str(item["guid"]) == str(item["guid"]).lower() for item in interfaces)
    except NativeWifiError as error:
        assert error.category in {
            "access_denied",
            "service_stopped",
            "not_found",
            "unsupported",
            "failed",
        }


def test_powershell_7_inventory_when_available() -> None:
    from wto_desktop_agent.platforms.windows.powershell import (
        inventory_script_path,
        parse_powershell_inventory,
    )

    executable = shutil.which("pwsh")
    if executable is None:
        pytest.skip("PowerShell 7 is not installed")
    completed = subprocess.run(  # noqa: S603 - executable and script are locally fixed
        [
            executable,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(inventory_script_path()),
        ],
        check=False,
        capture_output=True,
        timeout=30.0,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert parse_powershell_inventory(completed.stdout).powershell_edition == "Core"


def test_doctor_reports_windows_runtime_without_hardware_assumptions(tmp_path: Path) -> None:
    from wto_desktop_agent.application.doctor import DoctorService
    from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
    from wto_desktop_agent.platforms.windows.adapter import WindowsPlatformAdapter

    settings = AgentSettings(environment="test", server_url="http://testserver", state_dir=tmp_path)
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    checks = DoctorService(settings, store, WindowsPlatformAdapter(settings, store)).run()
    by_name = {check.name: check for check in checks}
    assert by_name["contracts"].status == "OK"
    assert by_name["sqlite"].status == "OK"
    assert by_name["windows_wifi_privacy"].status in {"DEGRADED", "BLOCKED"}
    assert by_name["service_manager"].status in {"OK", "DEGRADED", "BLOCKED"}


def test_directory_acl_can_be_applied_to_temporary_programdata(tmp_path: Path) -> None:
    import win32security

    from wto_desktop_agent.platforms.windows.acl import apply_directory_acl

    service_sid = "S-1-5-80-123-456-789-1011-1213"
    target = tmp_path / "state"
    target.mkdir()
    original = win32security.GetFileSecurity(str(target), win32security.DACL_SECURITY_INFORMATION)
    try:
        apply_directory_acl(target, service_sid, writable=True)
        descriptor = win32security.GetFileSecurity(
            str(target), win32security.DACL_SECURITY_INFORMATION
        )
        rendered = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
            descriptor,
            win32security.SDDL_REVISION_1,
            win32security.DACL_SECURITY_INFORMATION,
        )
        assert service_sid in rendered
        assert "WD" not in rendered
    finally:
        win32security.SetFileSecurity(
            str(target), win32security.DACL_SECURITY_INFORMATION, original
        )


def test_enrollment_pipe_native_mode_rejects_remote_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32pipe

    import wto_desktop_agent.platforms.windows.enrollment_ipc as enrollment_ipc
    from wto_desktop_agent.platforms.windows.enrollment_ipc import EnrollmentPipeServer

    class PipeModeInspected(Exception):
        pass

    pipe_flags: list[int] = []

    def inspect_pipe_mode(pipe: object, _overlapped: object) -> None:
        pipe_flags.append(win32pipe.GetNamedPipeInfo(pipe)[0])
        raise PipeModeInspected

    monkeypatch.setattr(
        enrollment_ipc,
        "PIPE_NAME",
        rf"\\.\pipe\WiFiTestOrchestrator.Agent.Enrollment.test.{uuid4()}",
    )
    monkeypatch.setattr(win32pipe, "ConnectNamedPipe", inspect_pipe_mode)

    server = EnrollmentPipeServer(AsyncMock(), "S-1-5-19")
    with pytest.raises(PipeModeInspected):
        server.serve_once()

    assert pipe_flags
    assert pipe_flags[0] & win32pipe.PIPE_REJECT_REMOTE_CLIENTS


def test_service_install_configuration_is_localservice_and_never_reboots(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import win32service

    import wto_desktop_agent.platforms.windows.service_manager as service_module
    from wto_desktop_agent.platforms.windows.acl import SERVICE_ACCOUNT
    from wto_desktop_agent.platforms.windows.service_manager import (
        WindowsServiceManager,
        service_image_path,
    )

    program_files = tmp_path / "Program Files"
    program_data = tmp_path / "ProgramData"
    executable = program_files / "Agent" / "wto-agent.exe"
    config = program_data / "Agent" / "config" / "wto-agent.toml"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"test")
    config.parent.mkdir(parents=True)
    config.write_text("[agent]\n", encoding="utf-8")
    expected_image = service_image_path(executable, config)
    scm = object()
    service = object()
    monkeypatch.setattr(win32service, "OpenSCManager", Mock(return_value=scm))
    monkeypatch.setattr(win32service, "CreateService", Mock(return_value=service))
    monkeypatch.setattr(win32service, "ChangeServiceConfig", Mock())
    config2 = Mock()
    monkeypatch.setattr(win32service, "ChangeServiceConfig2", config2)
    monkeypatch.setattr(
        win32service,
        "QueryServiceConfig",
        Mock(return_value=(0, 0, 0, expected_image, None, 0, None, SERVICE_ACCOUNT, "WTO")),
    )
    monkeypatch.setattr(win32service, "CloseServiceHandle", Mock())
    monkeypatch.setattr(service_module, "lookup_service_sid", Mock(return_value="S-1-5-80-123"))
    monkeypatch.setattr(service_module, "apply_directory_acl", Mock())

    WindowsServiceManager(
        program_data / "Agent" / "state",
        program_files_root=program_files,
        program_data_root=program_data,
    ).install(executable, config)

    failure_actions = next(
        call.args[2]
        for call in config2.call_args_list
        if call.args[1] == win32service.SERVICE_CONFIG_FAILURE_ACTIONS
    )
    assert all(action[0] != win32service.SC_ACTION_REBOOT for action in failure_actions["Actions"])


@pytest.mark.asyncio
async def test_windows_process_runner_is_deny_by_default() -> None:
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    runner = WindowsProcessRunner()
    with pytest.raises(PluginUnavailableError, match="not locally allowlisted"):
        await runner.run(
            CommandRequest(
                command_id="not-allowlisted",
                arguments={},
                timeout_seconds=1.0,
            ),
            CancellationToken(),
        )


class EmptyArguments(BaseModel):
    pass


@pytest.mark.asyncio
async def test_windows_process_runner_uses_exec_and_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32con

    from wto_desktop_agent.platforms.common import CommandSpec
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    process = SimpleNamespace(pid=4200)
    create_process = AsyncMock(return_value=process)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    executable = Path(sys.executable).resolve()
    spec = CommandSpec(
        command_id="controlled-test",
        executable=executable,
        argument_model=EmptyArguments,
        build_argv=lambda _: [],
        cwd=executable.parent,
        environment={},
    )

    runner = WindowsProcessRunner()
    result = await runner.start_process(spec, ["python.exe"], {"PATH": "controlled"})

    assert result is process
    create_process.assert_awaited_once_with(
        str(spec.executable),
        "python.exe",
        cwd=spec.cwd,
        env={"PATH": "controlled"},
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        creationflags=win32con.CREATE_NEW_PROCESS_GROUP,
    )


def test_windows_process_runner_configures_and_assigns_kill_on_close_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32api
    import win32con
    import win32job

    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    process_id = 4201
    job = object()
    process_handle = Mock()
    information = {"BasicLimitInformation": {"LimitFlags": 0}}
    create_job = Mock(return_value=job)
    query_job = Mock(return_value=information)
    set_job = Mock()
    open_process = Mock(return_value=process_handle)
    assign_process = Mock()
    monkeypatch.setattr(win32job, "CreateJobObject", create_job)
    monkeypatch.setattr(win32job, "QueryInformationJobObject", query_job)
    monkeypatch.setattr(win32job, "SetInformationJobObject", set_job)
    monkeypatch.setattr(win32api, "OpenProcess", open_process)
    monkeypatch.setattr(win32job, "AssignProcessToJobObject", assign_process)

    runner = WindowsProcessRunner()
    runner.after_start(SimpleNamespace(pid=process_id))  # type: ignore[arg-type]

    create_job.assert_called_once_with(None, "")
    query_job.assert_called_once_with(job, win32job.JobObjectExtendedLimitInformation)
    assert (
        information["BasicLimitInformation"]["LimitFlags"]
        & win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    set_job.assert_called_once_with(
        job,
        win32job.JobObjectExtendedLimitInformation,
        information,
    )
    open_process.assert_called_once_with(
        win32con.PROCESS_TERMINATE | win32con.PROCESS_SET_QUOTA,
        False,
        process_id,
    )
    assign_process.assert_called_once_with(job, process_handle)
    process_handle.Close.assert_called_once_with()
