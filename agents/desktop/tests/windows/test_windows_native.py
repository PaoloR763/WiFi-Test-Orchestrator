from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock
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

    settings = AgentSettings(
        environment="test",
        server_url="http://testserver",
        state_dir=tmp_path,
        windows_inventory_timeout_seconds=17.25,
    )
    store = SQLiteStore(tmp_path / "agent.sqlite3")
    store.initialize()
    adapter = create_platform_adapter(in_memory=False, settings=settings, store=store)

    assert isinstance(adapter, WindowsPlatformAdapter)
    assert adapter.platform_id == "windows"
    assert isinstance(adapter.process_runner, WindowsProcessRunner)
    inventory_command = adapter.process_runner._commands[  # noqa: SLF001 - wiring is under test
        "windows.powershell.network_inventory"
    ]
    assert inventory_command.environment["WTO_INVENTORY_OUTER_TIMEOUT_MILLISECONDS"] == "17250"
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


INVENTORY_PROVIDERS = (
    "Win32_PnPSignedDriver",
    "Get-NetAdapter",
    "Get-NetAdapterStatistics",
    "Get-NetIPConfiguration",
    "Get-NetIPAddress",
    "Get-NetRoute",
    "Get-DnsClientServerAddress",
)

MOCK_PROVIDER_PREAMBLE = r"""
$ErrorActionPreference = 'Stop'
function Invoke-WtoInventoryMockBehavior {
    param([string]$Provider)
    $logDirectory = $env:WTO_TEST_INVENTORY_LOG_DIRECTORY
    [IO.File]::WriteAllText(
        (Join-Path $logDirectory ($Provider + '.pid')),
        [string]$PID,
        (New-Object Text.UTF8Encoding($false))
    )
    [IO.File]::AppendAllText(
        (Join-Path $logDirectory ($Provider + '.count')),
        "1`n",
        (New-Object Text.UTF8Encoding($false))
    )
    $blocked = @($env:WTO_TEST_INVENTORY_BLOCKED_PROVIDERS -split ',')
    $failed = @($env:WTO_TEST_INVENTORY_FAILED_PROVIDERS -split ',')
    if ($blocked -contains $Provider) {
        $childInfo = New-Object Diagnostics.ProcessStartInfo
        $childInfo.FileName = Join-Path $PSHOME 'powershell.exe'
        $childInfo.Arguments = '-NoLogo -NoProfile -NonInteractive -Command "Start-Sleep 60"'
        $childInfo.UseShellExecute = $false
        $child = [Diagnostics.Process]::Start($childInfo)
        [IO.File]::WriteAllText(
            (Join-Path $logDirectory ($Provider + '.child.pid')),
            [string]$child.Id,
            (New-Object Text.UTF8Encoding($false))
        )
        [Threading.Thread]::Sleep(60000)
    }
    if ($failed -contains $Provider) {
        throw ('controlled provider failure: ' + $Provider)
    }
}
"""

MOCK_MODULES = {
    "CimCmdlets": r"""
function Get-CimInstance {
    param($ClassName, $Property, $OperationTimeoutSec, $ErrorAction)
    Invoke-WtoInventoryMockBehavior 'Win32_PnPSignedDriver'
    [pscustomobject]@{
        DeviceID = 'PCI\WTO_MOCK'; Manufacturer = 'Mock Manufacturer'
        DeviceName = 'Mock Adapter'; DriverProviderName = 'Mock Provider'
        DriverVersion = '1.2.3'
    }
}
Export-ModuleMember -Function Get-CimInstance
""",
    "NetAdapter": r"""
function Get-NetAdapter {
    param([switch]$IncludeHidden, $ErrorAction)
    Invoke-WtoInventoryMockBehavior 'Get-NetAdapter'
    [pscustomobject]@{
        ifIndex = 7; PnPDeviceID = 'PCI\WTO_MOCK'
        InterfaceGuid = '11111111-1111-4111-8111-111111111111'; Name = 'Wi-Fi Mock'
        InterfaceDescription = 'Mock Adapter'; Status = 'Up'; Virtual = $false
        HardwareInterface = $true; DriverDescription = 'Mock Driver'; DriverVersion = '0.0.1'
        MacAddress = '00-11-22-33-44-55'; LinkSpeed = '1 Gbps'
    }
}
function Get-NetAdapterStatistics {
    param([switch]$IncludeHidden, $ErrorAction)
    Invoke-WtoInventoryMockBehavior 'Get-NetAdapterStatistics'
    [pscustomobject]@{
        ifIndex = 7; ReceivedBytes = 100; SentBytes = 200
        ReceivedUnicastPackets = 1; ReceivedMulticastPackets = 2
        ReceivedBroadcastPackets = 3; SentUnicastPackets = 4
        SentMulticastPackets = 5; SentBroadcastPackets = 6
        ReceivedPacketErrors = 0; OutboundPacketErrors = 0
        ReceivedDiscardedPackets = 0; OutboundDiscardedPackets = 0
    }
}
Export-ModuleMember -Function Get-NetAdapter, Get-NetAdapterStatistics
""",
    "NetTCPIP": r"""
function Get-NetIPConfiguration {
    param($ErrorAction)
    Invoke-WtoInventoryMockBehavior 'Get-NetIPConfiguration'
    [pscustomobject]@{
        InterfaceIndex = 7
        IPv4DefaultGateway = @([pscustomobject]@{ NextHop = '192.0.2.1' })
        IPv6DefaultGateway = @()
    }
}
function Get-NetIPAddress {
    param($ErrorAction)
    Invoke-WtoInventoryMockBehavior 'Get-NetIPAddress'
    [pscustomobject]@{
        InterfaceIndex = 7; AddressFamily = 'IPv4'
        IPAddress = '192.0.2.10'; PrefixLength = 24
    }
}
function Get-NetRoute {
    param($ErrorAction)
    Invoke-WtoInventoryMockBehavior 'Get-NetRoute'
    [pscustomobject]@{
        InterfaceIndex = 7; AddressFamily = 'IPv4'; DestinationPrefix = '0.0.0.0/0'
        NextHop = '192.0.2.1'; RouteMetric = 25
    }
}
Export-ModuleMember -Function Get-NetIPConfiguration, Get-NetIPAddress, Get-NetRoute
""",
    "DnsClient": r"""
function Get-DnsClientServerAddress {
    param($ErrorAction)
    Invoke-WtoInventoryMockBehavior 'Get-DnsClientServerAddress'
    [pscustomobject]@{ InterfaceIndex = 7; ServerAddresses = @('192.0.2.53') }
}
Export-ModuleMember -Function Get-DnsClientServerAddress
""",
}


def _write_inventory_mock_modules(root: Path) -> None:
    for index, (module_name, functions) in enumerate(MOCK_MODULES.items(), start=1):
        module = root / module_name
        module.mkdir(parents=True)
        (module / f"{module_name}.psm1").write_text(
            MOCK_PROVIDER_PREAMBLE + functions,
            encoding="utf-8",
        )
        manifest = f"""@{{
RootModule = '{module_name}.psm1'
ModuleVersion = '1.0.0'
GUID = '00000000-0000-4000-8000-{index:012d}'
FunctionsToExport = @('*')
CmdletsToExport = @()
VariablesToExport = @()
AliasesToExport = @()
}}
"""
        (module / f"{module_name}.psd1").write_text(manifest, encoding="utf-8")


def _powershell_literal(path: Path) -> str:
    return str(path).replace("'", "''")


def _wait_for_file(path: Path, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while not path.is_file() and time.monotonic() < deadline:
        time.sleep(0.025)
    return path.is_file()


def _run_mocked_inventory(
    tmp_path: Path,
    *,
    blocked_providers: tuple[str, ...] = (),
    failed_providers: tuple[str, ...] = (),
    inventory_script: Path | None = None,
    outer_timeout_milliseconds: int = 30000,
) -> tuple[subprocess.CompletedProcess[bytes], float, dict[str, int], dict[str, int]]:
    from wto_desktop_agent.platforms.windows.powershell import inventory_script_path

    module_root = tmp_path / "modules"
    log_directory = tmp_path / "provider-logs"
    module_root.mkdir()
    log_directory.mkdir()
    _write_inventory_mock_modules(module_root)
    selected_inventory_script = inventory_script or inventory_script_path()
    harness = f"""
$ErrorActionPreference = 'Stop'
$inventoryText = [string](& '{_powershell_literal(selected_inventory_script)}')
$remainingJobs = @(Get-Job -Name 'wto-inventory-*' -ErrorAction SilentlyContinue).Count
$providerProcesses = @(
    Get-ChildItem -LiteralPath '{_powershell_literal(log_directory)}' -Filter '*.pid' |
        ForEach-Object {{ [int](Get-Content -Raw -LiteralPath $_.FullName) }}
)
$remainingProcesses = 0
foreach ($providerProcess in $providerProcesses) {{
    if ($null -ne (Get-Process -Id $providerProcess -ErrorAction SilentlyContinue)) {{
        $remainingProcesses++
    }}
}}
$cleanupValues = @($remainingJobs, $remainingProcesses)
[Console]::Error.WriteLine((
    'wto_test_cleanup jobs_remaining={{0}} processes_remaining={{1}}' -f $cleanupValues
))
[Console]::Out.Write($inventoryText)
"""
    harness_path = tmp_path / "inventory-harness.ps1"
    harness_path.write_text(harness, encoding="utf-8")
    environment = os.environ.copy()
    environment["PSModulePath"] = str(module_root)
    environment["WTO_INVENTORY_DIAGNOSTICS"] = "1"
    environment["WTO_TEST_INVENTORY_LOG_DIRECTORY"] = str(log_directory)
    environment["WTO_TEST_INVENTORY_BLOCKED_PROVIDERS"] = ",".join(blocked_providers)
    environment["WTO_TEST_INVENTORY_FAILED_PROVIDERS"] = ",".join(failed_providers)
    environment["WTO_INVENTORY_OUTER_TIMEOUT_MILLISECONDS"] = str(outer_timeout_milliseconds)
    started = time.monotonic()
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
        env=environment,
    )
    elapsed = time.monotonic() - started
    provider_pids = {
        path.name.removesuffix(".pid"): int(path.read_text(encoding="utf-8"))
        for path in log_directory.glob("*.pid")
    }
    query_counts = {
        provider: (len(path.read_text(encoding="utf-8").splitlines()) if path.is_file() else 0)
        for provider in INVENTORY_PROVIDERS
        for path in (log_directory / f"{provider}.count",)
    }
    return completed, elapsed, provider_pids, query_counts


def _inventory_script_with_worker_preamble(
    tmp_path: Path,
    provider: str,
    behavior: str,
) -> Path:
    from wto_desktop_agent.platforms.windows.powershell import inventory_script_path

    source = inventory_script_path().read_text(encoding="utf-8")
    escaped_provider = provider.replace("'", "''")
    fixed_query_line = "    $fixedQuery = [string]$Definition.Query\n"
    assert fixed_query_line in source
    injection = f"""
    if ($Definition.Name -eq '{escaped_provider}') {{
        $testPreamble = @'
    [IO.File]::WriteAllText(
        (Join-Path $env:WTO_TEST_INVENTORY_LOG_DIRECTORY '{escaped_provider}.pid'),
        [string]$PID,
        (New-Object Text.UTF8Encoding($false))
    )
    {behavior}
'@
        $readyStatement = '    $null = $readyEvent.Set()'
        $workerTemplate = $workerTemplate.Replace(
            $readyStatement,
            $testPreamble + [Environment]::NewLine + $readyStatement
        )
    }}
"""
    modified = source.replace(fixed_query_line, injection + fixed_query_line, 1)
    target = tmp_path / "network_inventory.worker-state.ps1"
    target.write_bytes(modified.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8"))
    return target


def _inventory_script_with_setup_delay(tmp_path: Path, delay_milliseconds: int) -> Path:
    from wto_desktop_agent.platforms.windows.powershell import inventory_script_path

    source = inventory_script_path().read_text(encoding="utf-8")
    initializer = "\nInitialize-WtoInventoryNativeProcess\n"
    assert initializer in source
    modified = source.replace(
        initializer,
        f"\n[Threading.Thread]::Sleep({delay_milliseconds})\n{initializer.lstrip()}",
        1,
    )
    target = tmp_path / "network_inventory.slow-setup.ps1"
    target.write_bytes(modified.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8"))
    return target


def _inventory_script_with_ready_without_marker(tmp_path: Path, provider: str) -> Path:
    from wto_desktop_agent.platforms.windows.powershell import inventory_script_path

    source = inventory_script_path().read_text(encoding="utf-8")
    fixed_query_line = "    $fixedQuery = [string]$Definition.Query\n"
    assert fixed_query_line in source
    escaped_provider = provider.replace("'", "''")
    injection = f"""
    if ($Definition.Name -eq '{escaped_provider}') {{
        $markerStatement = '    [Console]::Out.WriteLine($marker)'
        $workerTemplate = $workerTemplate.Replace(
            $markerStatement,
            '    $null = $readyEvent.Set()' + [Environment]::NewLine +
                '    [Threading.Thread]::Sleep(60000)'
        )
    }}
"""
    modified = source.replace(fixed_query_line, injection + fixed_query_line, 1)
    target = tmp_path / "network_inventory.ready-without-marker.ps1"
    target.write_bytes(modified.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8"))
    return target


def _inventory_script_with_handle_attach_failure(tmp_path: Path, provider: str) -> Path:
    from wto_desktop_agent.platforms.windows.powershell import inventory_script_path

    source = inventory_script_path().read_text(encoding="utf-8")
    attach_line = "        $workerHandle = [WtoInventoryProcessHandle]::OpenForProcess($process)\n"
    assert attach_line in source
    escaped_provider = provider.replace("'", "''")
    replacement = f"""        if ($definition.Name -eq '{escaped_provider}') {{
            [IO.File]::WriteAllText(
                (Join-Path $env:WTO_TEST_INVENTORY_LOG_DIRECTORY '{escaped_provider}.pid'),
                [string]$process.Id,
                (New-Object Text.UTF8Encoding($false))
            )
            throw 'controlled handle attach failure'
        }}
{attach_line}"""
    modified = source.replace(attach_line, replacement, 1)
    target = tmp_path / "network_inventory.handle-attach-failure.ps1"
    target.write_bytes(modified.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8"))
    return target


def _inventory_script_with_job_cleanup_failure(tmp_path: Path, provider: str) -> Path:
    from wto_desktop_agent.platforms.windows.powershell import inventory_script_path

    source = inventory_script_path().read_text(encoding="utf-8")
    close_line = "            $state.WorkerHandle.CloseProviderJobForCleanup()\n"
    assert close_line in source
    escaped_provider = provider.replace("'", "''")
    replacement = f"""            if ($state.Definition.Name -eq '{escaped_provider}') {{
                throw 'controlled provider Job cleanup failure'
            }}
{close_line}"""
    modified = source.replace(close_line, replacement, 1)
    target = tmp_path / "network_inventory.job-cleanup-failure.ps1"
    target.write_bytes(modified.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8"))
    return target


def _native_process_initializer_source() -> str:
    from wto_desktop_agent.platforms.windows.powershell import inventory_script_path

    source = inventory_script_path().read_text(encoding="utf-8")
    start = source.index("function Initialize-WtoInventoryNativeProcess")
    call = source.index("\n\nInitialize-WtoInventoryNativeProcess", start)
    return source[start:call] + "\nInitialize-WtoInventoryNativeProcess\n"


def _provider_identity_coordinator_source() -> str:
    from wto_desktop_agent.platforms.windows.powershell import inventory_script_path

    source = inventory_script_path().read_text(encoding="utf-8")
    start = source.index("function Request-ProviderTermination")
    end = source.index("\n\nfunction Update-ProviderReadyState", start)
    return source[start:end]


def _process_is_running(process_id: int) -> bool:
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(0x00100000, False, process_id)
    if not handle:
        return False
    try:
        exit_code = ctypes.c_ulong()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return False
        return exit_code.value == 259
    finally:
        kernel32.CloseHandle(handle)


def _assert_provider_processes_stopped(provider_pids: dict[str, int]) -> None:
    deadline = time.monotonic() + 2.0
    running = {
        provider
        for provider, process_id in provider_pids.items()
        if _process_is_running(process_id)
    }
    while running and time.monotonic() < deadline:
        time.sleep(0.05)
        running = {
            provider
            for provider, process_id in provider_pids.items()
            if _process_is_running(process_id)
        }
    assert not running


def test_powershell_51_native_handle_identity_and_exit_races_are_fail_closed(
    tmp_path: Path,
) -> None:
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    harness = f"""
$ErrorActionPreference = 'Stop'
{_native_process_initializer_source()}
function Start-WtoControlledProcess {{
    param([int]$SleepMilliseconds)
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = '{_powershell_literal(powershell)}'
    $info.Arguments = @(
        '-NoLogo -NoProfile -NonInteractive -Command "[Threading.Thread]::Sleep('
        [string]$SleepMilliseconds
        ')"'
    ) -join ''
    $info.UseShellExecute = $false
    return [Diagnostics.Process]::Start($info)
}}
$validProcess = $null
$mismatchProcess = $null
$exitingProcess = $null
$handles = New-Object Collections.Generic.List[IDisposable]
try {{
    $validProcess = Start-WtoControlledProcess 60000
    $validHandle = [WtoInventoryProcessHandle]::OpenForProcess($validProcess)
    $handles.Add($validHandle)
    $validMarker = $validHandle.ValidateMarker(
        $validProcess.Id,
        $validProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
    )
    $validTermination = [string]$validHandle.Terminate()
    $validExited = $validProcess.WaitForExit(2000)

    $mismatchProcess = Start-WtoControlledProcess 60000
    $mismatchHandle = [WtoInventoryProcessHandle]::OpenForProcess($mismatchProcess)
    $handles.Add($mismatchHandle)
    $mismatchRejected = -not $mismatchHandle.ValidateMarker(
        $mismatchProcess.Id,
        $mismatchProcess.StartTime.ToUniversalTime().ToFileTimeUtc() + 1
    )
    $mismatchWorkerAlive = -not $mismatchProcess.HasExited
    $null = $mismatchHandle.Terminate()

    $exitingProcess = Start-WtoControlledProcess 100
    $exitingHandle = [WtoInventoryProcessHandle]::OpenForProcess($exitingProcess)
    $handles.Add($exitingHandle)
    $null = $exitingProcess.WaitForExit(2000)
    $exitRaceMarkerStillStable = $exitingHandle.ValidateMarker(
        $exitingProcess.Id,
        $exitingProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
    )
    $exitRaceResult = [string]$exitingHandle.Terminate()

    [ordered]@{{
        valid_marker = $validMarker
        valid_termination = $validTermination
        valid_exited = $validExited
        mismatch_rejected = $mismatchRejected
        mismatch_worker_alive = $mismatchWorkerAlive
        exit_race_marker_stable = $exitRaceMarkerStillStable
        exit_race_result = $exitRaceResult
    }} | ConvertTo-Json -Compress
}} finally {{
    foreach ($handle in $handles) {{
        try {{ $null = $handle.Terminate() }} catch {{}}
        try {{ $handle.CloseProviderJobForCleanup() }} catch {{}}
        $handle.Dispose()
    }}
    foreach ($process in @($validProcess, $mismatchProcess, $exitingProcess)) {{
        if ($null -ne $process -and -not $process.HasExited) {{ $process.Kill() }}
        if ($null -ne $process) {{ $null = $process.WaitForExit(2000); $process.Dispose() }}
    }}
}}
"""
    harness_path = tmp_path / "stable-process-handle.ps1"
    harness_path.write_text(harness, encoding="utf-8")

    completed = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(harness_path),
        ],
        check=False,
        capture_output=True,
        timeout=20.0,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert json.loads(completed.stdout) == {
        "valid_marker": True,
        "valid_termination": "TerminationRequested",
        "valid_exited": True,
        "mismatch_rejected": True,
        "mismatch_worker_alive": True,
        "exit_race_marker_stable": True,
        "exit_race_result": "AlreadyExited",
    }


def test_powershell_51_coordinator_uses_stable_handle_for_same_numeric_pid(
    tmp_path: Path,
) -> None:
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    harness = f"""
$ErrorActionPreference = 'Stop'
{_provider_identity_coordinator_source()}
$reusedProcessId = 4242
$stableLaunchHandle = [pscustomobject]@{{
    ProcessId = $reusedProcessId
    CreationFileTimeUtc = [int64]111
    IsPowerShell = $true
    TerminateCalls = 0
}}
$stableLaunchHandle | Add-Member -MemberType ScriptMethod -Name Terminate -Value {{
    $this.TerminateCalls++
    return 'AlreadyExited'
}}
$substitute = [pscustomobject]@{{
    ProcessId = $reusedProcessId
    CreationFileTimeUtc = [int64]222
    TerminateCalls = 0
}}
$substitute | Add-Member -MemberType ScriptMethod -Name Terminate -Value {{
    $this.TerminateCalls++
    return 'TerminationRequested'
}}
$state = [pscustomobject]@{{
    WorkerHandle = $stableLaunchHandle
    Ready = $true
    TerminationRequested = $false
    Termination = 'none'
}}

Request-ProviderTermination $state
[ordered]@{{
    same_pid = $stableLaunchHandle.ProcessId -eq $substitute.ProcessId
    different_creation_time = (
        $stableLaunchHandle.CreationFileTimeUtc -ne $substitute.CreationFileTimeUtc
    )
    stable_handle_terminate_calls = $stableLaunchHandle.TerminateCalls
    substitute_terminate_calls = $substitute.TerminateCalls
    termination = $state.Termination
}} | ConvertTo-Json -Compress
"""
    harness_path = tmp_path / "reused-pid-coordinator.ps1"
    harness_path.write_text(harness, encoding="utf-8")

    completed = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(harness_path),
        ],
        check=False,
        capture_output=True,
        timeout=10.0,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert json.loads(completed.stdout) == {
        "same_pid": True,
        "different_creation_time": True,
        "stable_handle_terminate_calls": 1,
        "substitute_terminate_calls": 0,
        "termination": "already_exited",
    }


@pytest.mark.asyncio
async def test_fixed_powershell_51_inventory_script_returns_strict_json(
    tmp_path: Path,
) -> None:
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
    if os.environ.get("WTO_INVENTORY_DIAGNOSTICS") == "1":
        sys.stderr.buffer.write(output.stderr)
        sys.stderr.buffer.flush()
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


def test_powershell_51_inventory_global_queries_and_partial_failure(
    tmp_path: Path,
) -> None:
    from wto_desktop_agent.platforms.windows.powershell import (
        PowerShellAdapter,
        PowerShellAddress,
        PowerShellInventory,
        parse_powershell_inventory,
    )

    completed, elapsed, provider_pids, query_counts = _run_mocked_inventory(
        tmp_path,
        failed_providers=("Get-NetRoute",),
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert elapsed < 20.0
    assert set(query_counts.values()) == {1}
    diagnostics = completed.stderr.decode("utf-8", errors="strict")
    assert "provider=Get-NetRoute status=failed" in diagnostics
    assert "controlled provider failure" not in diagnostics
    assert "wto_test_cleanup jobs_remaining=0 processes_remaining=0" in diagnostics
    raw_inventory = json.loads(completed.stdout)
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
    _assert_provider_processes_stopped(provider_pids)


@pytest.mark.parametrize(
    ("blocked_providers", "unavailable_flags"),
    [
        (("Get-NetRoute",), {"routes_available"}),
        (
            ("Get-NetAdapterStatistics", "Get-DnsClientServerAddress"),
            {"statistics_available", "dns_available"},
        ),
    ],
)
def test_powershell_51_inventory_hard_timeouts_are_fail_soft_and_cleaned_up(
    tmp_path: Path,
    blocked_providers: tuple[str, ...],
    unavailable_flags: set[str],
) -> None:
    from wto_desktop_agent.platforms.windows.powershell import (
        PowerShellAdapter,
        PowerShellInventory,
        parse_powershell_inventory,
    )

    completed, elapsed, provider_pids, query_counts = _run_mocked_inventory(
        tmp_path,
        blocked_providers=blocked_providers,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert 4.0 < elapsed < 20.0
    assert set(query_counts.values()) == {1}
    diagnostics = completed.stderr.decode("utf-8", errors="strict")
    for provider in INVENTORY_PROVIDERS:
        expected_status = "timed_out" if provider in blocked_providers else "completed"
        assert f"provider={provider} status={expected_status}" in diagnostics
        provider_diagnostic = next(
            line for line in diagnostics.splitlines() if f"provider={provider} " in line
        )
        if provider in blocked_providers:
            assert "termination=process_handle" in provider_diagnostic
            fields = {
                key: value
                for key, value in (
                    token.split("=", maxsplit=1)
                    for token in provider_diagnostic.split()
                    if "=" in token
                )
            }
            assert int(fields["elapsed_ms"]) <= int(fields["timeout_ms"]) + 500
            assert f"{provider}.child" in provider_pids
    assert "wto_inventory cleanup jobs_remaining=0 processes_remaining=0" in diagnostics
    assert "wto_test_cleanup jobs_remaining=0 processes_remaining=0" in diagnostics

    raw_inventory = json.loads(completed.stdout)
    assert set(raw_inventory) == set(PowerShellInventory.model_fields)
    assert len(raw_inventory["adapters"]) == 1
    raw_adapter = raw_inventory["adapters"][0]
    assert set(raw_adapter) == set(PowerShellAdapter.model_fields)
    for flag in (
        "statistics_available",
        "ip_configuration_available",
        "addresses_available",
        "routes_available",
        "dns_available",
    ):
        assert raw_adapter[flag] is (flag not in unavailable_flags)

    assert raw_adapter["manufacturer"] == "Mock Manufacturer"
    assert raw_adapter["addresses"] == [
        {"family": "IPv4", "address": "192.0.2.10", "prefix_length": 24}
    ]
    assert raw_adapter["gateways"] == ["192.0.2.1"]
    if "routes_available" in unavailable_flags:
        assert raw_adapter["routes"] == []
    else:
        assert raw_adapter["routes"][0]["next_hop"] == "192.0.2.1"
    if "statistics_available" in unavailable_flags:
        assert raw_adapter["received_bytes"] is None
        assert raw_adapter["sent_bytes"] is None
    else:
        assert raw_adapter["received_bytes"] == 100
        assert raw_adapter["sent_bytes"] == 200
    if "dns_available" in unavailable_flags:
        assert raw_adapter["dns_servers"] == []
    else:
        assert raw_adapter["dns_servers"] == ["192.0.2.53"]

    parse_powershell_inventory(completed.stdout)
    _assert_provider_processes_stopped(provider_pids)


def test_powershell_51_mixed_deadlines_do_not_accumulate_reaping_waits(
    tmp_path: Path,
) -> None:
    from wto_desktop_agent.platforms.windows.powershell import parse_powershell_inventory

    blocked_providers = (
        "Get-NetAdapterStatistics",
        "Get-NetIPAddress",
        "Get-NetRoute",
        "Get-DnsClientServerAddress",
        "Win32_PnPSignedDriver",
        "Get-NetIPConfiguration",
    )
    expected_timeouts = {
        "Get-NetAdapterStatistics": 5000,
        "Get-NetIPAddress": 5000,
        "Get-NetRoute": 5000,
        "Get-DnsClientServerAddress": 5000,
        "Win32_PnPSignedDriver": 8000,
        "Get-NetIPConfiguration": 10000,
    }

    completed, elapsed, provider_pids, query_counts = _run_mocked_inventory(
        tmp_path,
        blocked_providers=blocked_providers,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    # Explicit worker creation is a separate phase; the common release still
    # gives the 10-second provider its full budget before shared cleanup.
    assert 9.0 < elapsed < 22.0
    assert set(query_counts.values()) == {1}
    diagnostics = completed.stderr.decode("utf-8", errors="strict")
    for provider, timeout_ms in expected_timeouts.items():
        line = next(item for item in diagnostics.splitlines() if f"provider={provider} " in item)
        fields = {
            key: value
            for key, value in (
                token.split("=", maxsplit=1) for token in line.split() if "=" in token
            )
        }
        assert fields["status"] == "timed_out"
        assert fields["termination"] == "process_handle"
        assert timeout_ms - 100 <= int(fields["elapsed_ms"]) <= timeout_ms + 750
        assert f"{provider}.child" in provider_pids
    assert "wto_inventory cleanup jobs_remaining=0 processes_remaining=0" in diagnostics
    assert "wto_test_cleanup jobs_remaining=0 processes_remaining=0" in diagnostics

    inventory = parse_powershell_inventory(completed.stdout)
    assert len(inventory.adapters) == 1
    adapter = inventory.adapters[0]
    assert adapter.manufacturer is None
    assert adapter.statistics_available is False
    assert adapter.ip_configuration_available is False
    assert adapter.addresses_available is False
    assert adapter.routes_available is False
    assert adapter.dns_available is False
    _assert_provider_processes_stopped(provider_pids)


def test_powershell_51_slow_setup_aborts_before_releasing_any_provider(
    tmp_path: Path,
) -> None:
    from wto_desktop_agent.platforms.windows.powershell import parse_powershell_inventory

    modified_script = _inventory_script_with_setup_delay(tmp_path, 12000)
    completed, elapsed, provider_pids, query_counts = _run_mocked_inventory(
        tmp_path,
        inventory_script=modified_script,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert 11.5 < elapsed < 20.0
    assert set(query_counts.values()) == {0}
    assert provider_pids == {}
    diagnostics = completed.stderr.decode("utf-8", errors="strict")
    assert diagnostics.count("status=timed_out") == len(INVENTORY_PROVIDERS)
    assert "wto_inventory cleanup jobs_remaining=0 processes_remaining=0" in diagnostics
    assert "wto_test_cleanup jobs_remaining=0 processes_remaining=0" in diagnostics
    parse_powershell_inventory(completed.stdout)


def test_powershell_51_short_outer_budget_aborts_before_starting_workers(
    tmp_path: Path,
) -> None:
    from wto_desktop_agent.platforms.windows.powershell import parse_powershell_inventory

    completed, elapsed, provider_pids, query_counts = _run_mocked_inventory(
        tmp_path,
        outer_timeout_milliseconds=10000,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert elapsed < 10.0
    assert set(query_counts.values()) == {0}
    assert provider_pids == {}
    diagnostics = completed.stderr.decode("utf-8", errors="strict")
    assert diagnostics.count("worker_state=BudgetUnavailable") == len(INVENTORY_PROVIDERS)
    assert "wto_inventory cleanup jobs_remaining=0 processes_remaining=0" in diagnostics
    parse_powershell_inventory(completed.stdout)


def test_powershell_51_handle_attach_failure_uses_original_process_handle_and_cleans_up(
    tmp_path: Path,
) -> None:
    from wto_desktop_agent.platforms.windows.powershell import parse_powershell_inventory

    provider = "Get-NetRoute"
    modified_script = _inventory_script_with_handle_attach_failure(tmp_path, provider)
    completed, elapsed, provider_pids, query_counts = _run_mocked_inventory(
        tmp_path,
        inventory_script=modified_script,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert elapsed < 15.0
    assert query_counts[provider] == 0
    assert provider in provider_pids
    diagnostics = completed.stderr.decode("utf-8", errors="strict")
    provider_line = next(
        line for line in diagnostics.splitlines() if f"provider={provider} " in line
    )
    assert "status=failed" in provider_line
    assert "termination=process_object_handle" in provider_line
    assert "wto_inventory cleanup jobs_remaining=0 processes_remaining=0" in diagnostics
    assert "wto_test_cleanup jobs_remaining=0 processes_remaining=0" in diagnostics
    parse_powershell_inventory(completed.stdout)
    _assert_provider_processes_stopped(provider_pids)


def test_powershell_51_job_cleanup_failure_remains_visible_and_reaps_worker_tree(
    tmp_path: Path,
) -> None:
    from wto_desktop_agent.platforms.windows.powershell import parse_powershell_inventory

    provider = "Get-NetRoute"
    modified_script = _inventory_script_with_job_cleanup_failure(tmp_path, provider)
    completed, elapsed, provider_pids, query_counts = _run_mocked_inventory(
        tmp_path,
        blocked_providers=(provider,),
        inventory_script=modified_script,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert 4.0 < elapsed < 20.0
    assert query_counts[provider] == 1
    diagnostics = completed.stderr.decode("utf-8", errors="strict")
    assert "wto_inventory cleanup jobs_remaining=0 processes_remaining=1" in diagnostics
    assert "wto_test_cleanup jobs_remaining=0 processes_remaining=0" in diagnostics
    parse_powershell_inventory(completed.stdout)
    _assert_provider_processes_stopped(provider_pids)


@pytest.mark.parametrize(
    ("provider", "behavior"),
    [
        ("Get-NetRoute", "[Threading.Thread]::Sleep(60000)"),
    ],
    ids=("running-without-marker",),
)
def test_powershell_51_startup_without_marker_is_terminated_and_removed(
    tmp_path: Path,
    provider: str,
    behavior: str,
) -> None:
    from wto_desktop_agent.platforms.windows.powershell import parse_powershell_inventory

    modified_script = _inventory_script_with_worker_preamble(
        tmp_path,
        provider,
        behavior,
    )
    completed, elapsed, provider_pids, query_counts = _run_mocked_inventory(
        tmp_path,
        inventory_script=modified_script,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert elapsed < 12.0
    assert query_counts[provider] == 0
    diagnostics = completed.stderr.decode("utf-8", errors="strict")
    assert f"provider={provider} status=timed_out" in diagnostics
    provider_line = next(
        line for line in diagnostics.splitlines() if f"provider={provider} " in line
    )
    assert "termination=launch_handle" in provider_line
    assert "worker_state=MarkerMissing" in provider_line
    assert "wto_inventory cleanup jobs_remaining=0 processes_remaining=0" in diagnostics
    assert "wto_test_cleanup jobs_remaining=0 processes_remaining=0" in diagnostics
    parse_powershell_inventory(completed.stdout)
    _assert_provider_processes_stopped(provider_pids)


def test_powershell_51_signalled_ready_without_marker_is_terminated_immediately(
    tmp_path: Path,
) -> None:
    from wto_desktop_agent.platforms.windows.powershell import parse_powershell_inventory

    provider = "Get-NetRoute"
    modified_script = _inventory_script_with_ready_without_marker(tmp_path, provider)
    completed, elapsed, provider_pids, query_counts = _run_mocked_inventory(
        tmp_path,
        inventory_script=modified_script,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert elapsed < 15.0
    assert query_counts[provider] == 0
    diagnostics = completed.stderr.decode("utf-8", errors="strict")
    provider_line = next(
        line for line in diagnostics.splitlines() if f"provider={provider} " in line
    )
    assert "status=timed_out" in provider_line
    assert "termination=launch_handle" in provider_line
    assert "worker_state=MarkerMissing" in provider_line
    fields = {
        key: value
        for key, value in (
            token.split("=", maxsplit=1) for token in provider_line.split() if "=" in token
        )
    }
    assert int(fields["elapsed_ms"]) <= 750
    assert "wto_inventory cleanup jobs_remaining=0 processes_remaining=0" in diagnostics
    assert "wto_test_cleanup jobs_remaining=0 processes_remaining=0" in diagnostics
    parse_powershell_inventory(completed.stdout)
    _assert_provider_processes_stopped(provider_pids)


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
    import win32job

    from wto_desktop_agent.platforms.common import CommandSpec
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    process = SimpleNamespace(pid=4200)
    job = Mock()
    thread = Mock()
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
    runner._create_job = Mock(return_value=job)  # type: ignore[method-assign]
    runner._assign_job = Mock()  # type: ignore[method-assign]
    runner._process_handle = Mock(return_value=9000)  # type: ignore[method-assign]
    runner._validate_process_handle = Mock()  # type: ignore[method-assign]
    runner._open_initial_thread = Mock(return_value=thread)  # type: ignore[method-assign]
    runner._resume_initial_thread = Mock(  # type: ignore[method-assign]
        side_effect=lambda context, _handle: runner._close_suspended_thread(context)
    )
    monkeypatch.setattr(win32job, "TerminateJobObject", Mock())
    monkeypatch.setattr(
        win32job,
        "QueryInformationJobObject",
        Mock(return_value={"ActiveProcesses": 0}),
    )
    result = await runner.start_process(
        spec,
        ["python.exe"],
        {"PATH": "controlled"},
        execution_token=object(),
    )

    assert result is process
    create_process.assert_awaited_once_with(
        str(spec.executable),
        "python.exe",
        cwd=spec.cwd,
        env={"PATH": "controlled"},
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        creationflags=win32con.CREATE_NEW_PROCESS_GROUP | win32con.CREATE_SUSPENDED,
    )
    runner._assign_job.assert_called_once_with(job, 9000)  # type: ignore[attr-defined]
    runner._open_initial_thread.assert_called_once_with(  # type: ignore[attr-defined]
        process.pid, 9000
    )
    runner._resume_initial_thread.assert_called_once()  # type: ignore[attr-defined]
    runner.after_finish(process)  # type: ignore[arg-type]
    await runner.wait_after_finish(process)  # type: ignore[arg-type]
    thread.Close.assert_called_once_with()
    job.Close.assert_called_once_with()
    assert runner._contexts == {}


def test_windows_process_runner_configures_and_assigns_kill_on_close_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32job

    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    job = Mock()
    process_handle = 9001
    information = {"BasicLimitInformation": {"LimitFlags": 0}}
    create_job = Mock(return_value=job)
    query_job = Mock(
        side_effect=lambda _job, information_class: (
            information
            if information_class == win32job.JobObjectExtendedLimitInformation
            else {"ActiveProcesses": 0}
        )
    )
    set_job = Mock()
    assign_process = Mock()
    terminate_job = Mock()
    monkeypatch.setattr(win32job, "CreateJobObject", create_job)
    monkeypatch.setattr(win32job, "QueryInformationJobObject", query_job)
    monkeypatch.setattr(win32job, "SetInformationJobObject", set_job)
    monkeypatch.setattr(win32job, "AssignProcessToJobObject", assign_process)
    monkeypatch.setattr(win32job, "TerminateJobObject", terminate_job)

    runner = WindowsProcessRunner()
    configured_job = runner._create_job()
    try:
        runner._assign_job(configured_job, process_handle)
    finally:
        configured_job.Close()

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
    assign_process.assert_called_once_with(job, process_handle)
    assert terminate_job.call_count == 0
    job.Close.assert_called_once_with()


def test_windows_process_runner_resumes_only_the_validated_initial_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32process

    import wto_desktop_agent.platforms.windows.process_runner as process_runner_module
    from wto_desktop_agent.platforms.windows.process_runner import (
        ProcessContext,
        WindowsProcessRunner,
    )

    process_id = 4204
    thread = MagicMock()
    thread.__int__.return_value = 9004
    get_owner = Mock(return_value=process_id)
    resume = Mock(return_value=1)
    monkeypatch.setattr(process_runner_module._kernel32, "GetProcessIdOfThread", get_owner)
    monkeypatch.setattr(win32process, "ResumeThread", resume)
    runner = WindowsProcessRunner()
    runner._validate_process_handle = Mock()  # type: ignore[method-assign]
    process = SimpleNamespace(pid=process_id)
    context = ProcessContext(
        execution_token=object(),
        job=Mock(),
        process=process,  # type: ignore[arg-type]
        process_id=process_id,
        suspended_thread=thread,
        assigned=True,
    )

    runner._resume_initial_thread(context, 9005)

    get_owner.assert_called_once_with(9004)
    resume.assert_called_once_with(thread)
    thread.Close.assert_called_once_with()
    assert context.suspended_thread is None


def test_windows_process_runner_preserves_identity_error_when_thread_close_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32api

    import wto_desktop_agent.platforms.windows.process_runner as process_runner_module
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    process_id = 4205
    identity_error = RuntimeError("controlled original process identity failure")
    close_error = OSError("controlled initial thread close failure")
    thread = MagicMock()
    thread.__int__.return_value = 9006
    thread.Close.side_effect = close_error
    monkeypatch.setattr(win32api, "OpenThread", Mock(return_value=thread))
    monkeypatch.setattr(
        process_runner_module._kernel32,
        "GetProcessIdOfThread",
        Mock(return_value=process_id),
    )
    runner = WindowsProcessRunner()
    runner._thread_ids = Mock(return_value=[9006])  # type: ignore[method-assign]
    runner._validate_process_handle = Mock(  # type: ignore[method-assign]
        side_effect=[None, identity_error]
    )

    with pytest.raises(RuntimeError) as raised:
        runner._open_initial_thread(process_id, 9007)

    assert raised.value is identity_error
    assert raised.value.__notes__ == [f"Initial thread handle close also failed: {close_error!r}"]
    thread.Close.assert_called_once_with()


def test_windows_process_runner_preserves_owner_error_when_thread_close_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32api

    import wto_desktop_agent.platforms.windows.process_runner as process_runner_module
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    process_id = 4206
    close_error = OSError("controlled initial thread close failure")
    thread = MagicMock()
    thread.__int__.return_value = 9008
    thread.Close.side_effect = close_error
    monkeypatch.setattr(win32api, "OpenThread", Mock(return_value=thread))
    monkeypatch.setattr(
        process_runner_module._kernel32,
        "GetProcessIdOfThread",
        Mock(return_value=process_id + 1),
    )
    runner = WindowsProcessRunner()
    runner._thread_ids = Mock(return_value=[9008])  # type: ignore[method-assign]
    runner._validate_process_handle = Mock()  # type: ignore[method-assign]

    with pytest.raises(RuntimeError) as raised:
        runner._open_initial_thread(process_id, 9009)

    assert str(raised.value) == "initial thread does not belong to the suspended process"
    assert raised.value.__notes__ == [f"Initial thread handle close also failed: {close_error!r}"]
    thread.Close.assert_called_once_with()


@pytest.mark.asyncio
async def test_windows_process_runner_releases_job_when_thread_close_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32job

    from wto_desktop_agent.platforms.windows.process_runner import (
        ProcessContext,
        WindowsProcessRunner,
    )

    process_id = 4207
    close_error = OSError("controlled suspended thread close failure")
    thread = Mock()
    thread.Close.side_effect = close_error
    job = Mock()
    terminate_job = Mock()
    monkeypatch.setattr(win32job, "TerminateJobObject", terminate_job)
    monkeypatch.setattr(
        win32job,
        "QueryInformationJobObject",
        Mock(return_value={"ActiveProcesses": 0}),
    )
    runner = WindowsProcessRunner()
    process = SimpleNamespace(pid=process_id)
    token = object()
    runner._contexts[token] = ProcessContext(
        execution_token=token,
        job=job,
        process=process,  # type: ignore[arg-type]
        process_id=process_id,
        suspended_thread=thread,
        assigned=True,
    )

    with pytest.raises(OSError) as raised:
        runner.after_finish(process)  # type: ignore[arg-type]
    assert raised.value is close_error

    await runner.wait_after_finish(process)  # type: ignore[arg-type]
    terminate_job.assert_called_once_with(job, 1)
    job.Close.assert_called_once_with()
    assert runner._contexts == {}


def test_windows_process_context_force_release_is_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32job

    from wto_desktop_agent.platforms.windows.process_runner import (
        ProcessContext,
        WindowsProcessRunner,
    )

    process = SimpleNamespace(
        pid=42071,
        returncode=None,
        kill=Mock(),
        _transport=SimpleNamespace(get_pipe_transport=lambda _fd: None, close=Mock()),
    )

    def kill() -> None:
        process.returncode = -1

    process.kill.side_effect = kill
    process._transport.close.side_effect = (  # type: ignore[attr-defined]
        lambda: process.kill() if process.returncode is None else None
    )
    job = Mock()
    thread = Mock()
    terminate_job = Mock()
    monkeypatch.setattr(win32job, "TerminateJobObject", terminate_job)
    runner = WindowsProcessRunner()
    token = object()
    context = ProcessContext(
        execution_token=token,
        job=job,
        process=process,  # type: ignore[arg-type]
        process_id=process.pid,
        suspended_thread=thread,
        assigned=True,
    )
    runner._contexts[token] = context

    runner._force_release_context(context)
    runner._force_release_context(context)
    runner._force_cleanup_process(process)  # type: ignore[arg-type]

    terminate_job.assert_called_once_with(job, 1)
    thread.Close.assert_called_once_with()
    job.Close.assert_called_once_with()
    process.kill.assert_called_once_with()
    process._transport.close.assert_called_once_with()
    assert context.released
    assert runner._contexts == {}


@pytest.mark.asyncio
async def test_windows_process_contexts_are_isolated_for_distinct_objects_with_same_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32job
    import win32process

    import wto_desktop_agent.platforms.windows.process_runner as process_runner_module
    from wto_desktop_agent.platforms.common import CommandSpec
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    reused_pid = 4242
    process_a = SimpleNamespace(pid=reused_pid, returncode=None)
    process_b = SimpleNamespace(pid=reused_pid, returncode=None)
    old_job = Mock(name="old_job")
    replacement_job = Mock(name="replacement_job")
    old_thread = MagicMock(name="old_thread")
    old_thread.__int__.return_value = 9100
    replacement_thread = MagicMock(name="replacement_thread")
    replacement_thread.__int__.return_value = 9101
    create_process = AsyncMock(side_effect=[process_a, process_b])
    terminate_job = Mock()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    monkeypatch.setattr(win32job, "TerminateJobObject", terminate_job)
    monkeypatch.setattr(
        win32job,
        "QueryInformationJobObject",
        Mock(return_value={"ActiveProcesses": 0}),
    )
    monkeypatch.setattr(
        process_runner_module._kernel32,
        "GetProcessIdOfThread",
        Mock(return_value=reused_pid),
    )
    monkeypatch.setattr(win32process, "ResumeThread", Mock(return_value=1))
    runner = WindowsProcessRunner()
    runner._create_job = Mock(side_effect=[old_job, replacement_job])  # type: ignore[method-assign]
    runner._process_handle = Mock(side_effect=[9200, 9201])  # type: ignore[method-assign]
    runner._validate_process_handle = Mock()  # type: ignore[method-assign]
    runner._assign_job = Mock()  # type: ignore[method-assign]
    runner._open_initial_thread = Mock(  # type: ignore[method-assign]
        side_effect=[old_thread, replacement_thread]
    )
    executable = Path(sys.executable).resolve()
    spec = CommandSpec(
        command_id="controlled-same-pid",
        executable=executable,
        argument_model=EmptyArguments,
        build_argv=lambda _: [],
        cwd=executable.parent,
        environment={},
    )

    assert await runner.start_process(spec, [], {}, execution_token=object()) is process_a
    assert await runner.start_process(spec, [], {}, execution_token=object()) is process_b
    assert len(runner._contexts) == 2

    runner.after_finish(process_a)  # type: ignore[arg-type]
    await runner.wait_after_finish(process_a)  # type: ignore[arg-type]

    terminate_job.assert_called_once_with(old_job, 1)
    old_job.Close.assert_called_once_with()
    replacement_job.Close.assert_not_called()
    assert process_b.returncode is None
    assert len(runner._contexts) == 1
    assert runner._context_for_process(process_b) is not None  # type: ignore[arg-type]

    runner.after_finish(process_b)  # type: ignore[arg-type]
    await runner.wait_after_finish(process_b)  # type: ignore[arg-type]

    assert [entry.args for entry in terminate_job.call_args_list] == [
        (old_job, 1),
        (replacement_job, 1),
    ]
    replacement_job.Close.assert_called_once_with()
    old_thread.Close.assert_called_once_with()
    replacement_thread.Close.assert_called_once_with()
    assert runner._contexts == {}


@pytest.mark.asyncio
async def test_windows_process_runner_closes_job_handle_when_assignment_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32job

    from wto_desktop_agent.platforms.common import CommandSpec
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    job = Mock()
    process_handle = 9002
    process = SimpleNamespace(
        pid=4208,
        returncode=None,
        wait=AsyncMock(return_value=-1),
        _transport=SimpleNamespace(get_pipe_transport=lambda _fd: None, close=Mock()),
    )

    def kill() -> None:
        process.returncode = -1

    process.kill = Mock(side_effect=kill)
    process._transport.close.side_effect = (  # type: ignore[attr-defined]
        lambda: process.kill() if process.returncode is None else None
    )
    create_process = AsyncMock(return_value=process)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    assign = Mock(side_effect=RuntimeError("controlled assignment failure"))
    monkeypatch.setattr(
        win32job,
        "AssignProcessToJobObject",
        assign,
    )
    terminate_job = Mock()
    monkeypatch.setattr(win32job, "TerminateJobObject", terminate_job)
    runner = WindowsProcessRunner()
    runner._create_job = Mock(return_value=job)  # type: ignore[method-assign]
    runner._process_handle = Mock(return_value=process_handle)  # type: ignore[method-assign]
    runner._validate_process_handle = Mock()  # type: ignore[method-assign]
    spec = CommandSpec(
        command_id="controlled-assignment-failure",
        executable=Path(sys.executable).resolve(),
        argument_model=EmptyArguments,
        build_argv=lambda _: [],
        cwd=Path(sys.executable).resolve().parent,
        environment={},
    )

    with pytest.raises(RuntimeError, match="controlled assignment failure"):
        await runner.start_process(spec, [], {}, execution_token=object())

    create_process.assert_awaited_once()
    assign.assert_called_once_with(job, process_handle)
    process.kill.assert_called_once_with()
    process.wait.assert_awaited_once_with()
    assert terminate_job.call_count == 0
    job.Close.assert_called_once_with()
    assert runner._contexts == {}


@pytest.mark.asyncio
async def test_windows_process_runner_recovers_process_created_during_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32job

    from wto_desktop_agent.platforms.common import CommandSpec
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    creation_reached_return = asyncio.Event()
    process = SimpleNamespace(
        pid=42081,
        returncode=None,
        wait=AsyncMock(return_value=-1),
        _transport=SimpleNamespace(get_pipe_transport=lambda _fd: None, close=Mock()),
    )

    def kill() -> None:
        process.returncode = -1

    process.kill = Mock(side_effect=kill)
    process._transport.close.side_effect = (  # type: ignore[attr-defined]
        lambda: process.kill() if process.returncode is None else None
    )

    async def create_process(*_args: object, **_kwargs: object) -> SimpleNamespace:
        creation_reached_return.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            # Model CreateProcess winning the race with cancellation: the child
            # exists and its object must be recovered before cleanup propagates.
            return process

    job = Mock()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    monkeypatch.setattr(win32job, "TerminateJobObject", Mock())
    runner = WindowsProcessRunner()
    runner._create_job = Mock(return_value=job)  # type: ignore[method-assign]
    executable = Path(sys.executable).resolve()
    spec = CommandSpec(
        command_id="controlled-create-cancel-race",
        executable=executable,
        argument_model=EmptyArguments,
        build_argv=lambda _: [],
        cwd=executable.parent,
        environment={},
    )
    task = asyncio.create_task(runner.start_process(spec, [], {}, execution_token=object()))
    await creation_reached_return.wait()

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=1.0)

    process.kill.assert_called_once_with()
    process.wait.assert_awaited_once_with()
    job.Close.assert_called_once_with()
    assert runner._contexts == {}


@pytest.mark.asyncio
async def test_windows_process_runner_cancellation_after_create_is_transactional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32job

    from wto_desktop_agent.platforms.common import CommandSpec
    from wto_desktop_agent.platforms.windows.process_runner import (
        ProcessContext,
        WindowsProcessRunner,
    )

    process_created = asyncio.Event()
    release_created = asyncio.Event()
    wait_started = asyncio.Event()
    release_wait = asyncio.Event()

    async def wait() -> int:
        wait_started.set()
        await release_wait.wait()
        return -1

    process = SimpleNamespace(
        pid=4210,
        returncode=None,
        wait=wait,
        _transport=SimpleNamespace(get_pipe_transport=lambda _fd: None, close=Mock()),
    )

    def kill() -> None:
        process.returncode = -1

    process.kill = Mock(side_effect=kill)
    process._transport.close.side_effect = (  # type: ignore[attr-defined]
        lambda: process.kill() if process.returncode is None else None
    )
    job = Mock()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=process))
    terminate_job = Mock()
    monkeypatch.setattr(win32job, "TerminateJobObject", terminate_job)

    class BlockedAfterCreateRunner(WindowsProcessRunner):
        async def _after_process_created(self, context: ProcessContext) -> None:
            assert context.process is process
            process_created.set()
            await release_created.wait()

    runner = BlockedAfterCreateRunner()
    runner._cleanup_grace_seconds = 0.5
    runner._cleanup_force_close_reserve_seconds = 0.05
    runner._create_job = Mock(return_value=job)  # type: ignore[method-assign]
    executable = Path(sys.executable).resolve()
    spec = CommandSpec(
        command_id="controlled-cancel-after-create",
        executable=executable,
        argument_model=EmptyArguments,
        build_argv=lambda _: [],
        cwd=executable.parent,
        environment={},
    )
    task = asyncio.create_task(runner.start_process(spec, [], {}, execution_token=object()))
    await process_created.wait()

    task.cancel()
    await wait_started.wait()
    task.cancel()
    release_wait.set()

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=1.0)

    process.kill.assert_called_once_with()
    assert terminate_job.call_count == 0
    job.Close.assert_called_once_with()
    assert runner._contexts == {}


@pytest.mark.asyncio
async def test_windows_process_runner_cleans_full_spawn_when_resume_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import win32job
    import win32process

    import wto_desktop_agent.platforms.windows.process_runner as process_runner_module
    from wto_desktop_agent.platforms.common import CommandSpec
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    process_id = 4209
    process = SimpleNamespace(
        pid=process_id,
        returncode=None,
        wait=AsyncMock(return_value=-1),
        _transport=SimpleNamespace(get_pipe_transport=lambda _fd: None, close=Mock()),
    )

    def kill() -> None:
        process.returncode = -1

    process.kill = Mock(side_effect=kill)
    process._transport.close.side_effect = (  # type: ignore[attr-defined]
        lambda: process.kill() if process.returncode is None else None
    )
    job = Mock()
    thread = MagicMock()
    thread.__int__.return_value = 9300
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=process))
    monkeypatch.setattr(
        process_runner_module._kernel32,
        "GetProcessIdOfThread",
        Mock(return_value=process_id),
    )
    resume_error = RuntimeError("controlled resume failure")
    monkeypatch.setattr(win32process, "ResumeThread", Mock(side_effect=resume_error))
    terminate_job = Mock()
    monkeypatch.setattr(win32job, "TerminateJobObject", terminate_job)
    runner = WindowsProcessRunner()
    runner._create_job = Mock(return_value=job)  # type: ignore[method-assign]
    runner._process_handle = Mock(return_value=9301)  # type: ignore[method-assign]
    runner._validate_process_handle = Mock()  # type: ignore[method-assign]
    runner._assign_job = Mock()  # type: ignore[method-assign]
    runner._open_initial_thread = Mock(return_value=thread)  # type: ignore[method-assign]
    executable = Path(sys.executable).resolve()
    spec = CommandSpec(
        command_id="controlled-resume-failure",
        executable=executable,
        argument_model=EmptyArguments,
        build_argv=lambda _: [],
        cwd=executable.parent,
        environment={},
    )

    with pytest.raises(RuntimeError) as raised:
        await runner.start_process(spec, [], {}, execution_token=object())

    assert raised.value is resume_error
    runner._assign_job.assert_called_once_with(job, 9301)  # type: ignore[attr-defined]
    thread.Close.assert_called_once_with()
    terminate_job.assert_called_once_with(job, 1)
    job.Close.assert_called_once_with()
    process.kill.assert_called_once_with()
    process.wait.assert_awaited_once_with()
    assert runner._contexts == {}


@pytest.mark.asyncio
async def test_windows_process_runner_never_resumes_after_spawn_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import time

    import win32job
    import win32process

    from wto_desktop_agent.platforms.common import CommandSpec
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    process_id = 4211
    process = SimpleNamespace(
        pid=process_id,
        returncode=None,
        wait=AsyncMock(return_value=-1),
        _transport=SimpleNamespace(get_pipe_transport=lambda _fd: None, close=Mock()),
    )

    def kill() -> None:
        process.returncode = -1

    process.kill = Mock(side_effect=kill)
    process._transport.close.side_effect = (  # type: ignore[attr-defined]
        lambda: process.kill() if process.returncode is None else None
    )
    job = Mock()
    thread = MagicMock()
    thread.__int__.return_value = 9302
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=process))
    resume = Mock(return_value=1)
    monkeypatch.setattr(win32process, "ResumeThread", resume)
    terminate_job = Mock()
    monkeypatch.setattr(win32job, "TerminateJobObject", terminate_job)
    runner = WindowsProcessRunner()
    runner._create_job = Mock(return_value=job)  # type: ignore[method-assign]
    runner._process_handle = Mock(return_value=9303)  # type: ignore[method-assign]
    runner._validate_process_handle = Mock()  # type: ignore[method-assign]
    runner._assign_job = Mock()  # type: ignore[method-assign]

    def open_thread_after_deadline(_process_id: int, _process_handle: int) -> MagicMock:
        time.sleep(0.04)
        return thread

    runner._open_initial_thread = open_thread_after_deadline  # type: ignore[method-assign]
    executable = Path(sys.executable).resolve()
    spec = CommandSpec(
        command_id="controlled-expired-resume",
        executable=executable,
        argument_model=EmptyArguments,
        build_argv=lambda _: [],
        cwd=executable.parent,
        environment={},
    )
    deadline = asyncio.get_running_loop().time() + 0.01

    with pytest.raises(TimeoutError, match="initial thread validation"):
        await runner.start_process(
            spec,
            [],
            {},
            execution_token=object(),
            deadline=deadline,
        )

    resume.assert_not_called()
    thread.Close.assert_called_once_with()
    terminate_job.assert_called_once_with(job, 1)
    job.Close.assert_called_once_with()
    process.kill.assert_called_once_with()
    process.wait.assert_awaited_once_with()
    assert runner._contexts == {}


@pytest.mark.asyncio
async def test_process_is_terminated_when_after_start_hook_fails() -> None:
    from wto_desktop_agent.platforms.common import CommandSpec
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    executable = Path(sys.executable).resolve()
    spec = CommandSpec(
        command_id="controlled-after-start-failure",
        executable=executable,
        argument_model=EmptyArguments,
        build_argv=lambda _: [],
        cwd=executable.parent,
        environment={},
    )
    process = SimpleNamespace(
        pid=4203,
        returncode=None,
        stdout=asyncio.StreamReader(),
        stderr=asyncio.StreamReader(),
        kill=Mock(),
        wait=AsyncMock(),
    )
    runner = WindowsProcessRunner({spec.command_id: spec})
    runner.start_process = AsyncMock(return_value=process)  # type: ignore[method-assign]
    runner.after_start = Mock(side_effect=RuntimeError("controlled hook failure"))  # type: ignore[method-assign]

    async def terminate(controlled_process: SimpleNamespace) -> None:
        controlled_process.returncode = -1

    runner.terminate = AsyncMock(side_effect=terminate)  # type: ignore[method-assign]
    runner.after_finish = Mock()  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="controlled hook failure"):
        await runner.run(
            CommandRequest(
                command_id=spec.command_id,
                arguments={},
                timeout_seconds=1.0,
            ),
            CancellationToken(),
        )

    runner.terminate.assert_awaited_once_with(process)  # type: ignore[attr-defined]
    runner.after_finish.assert_called_once_with(process)  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_windows_runner_post_spawn_stat_failure_releases_all_native_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from wto_desktop_agent.platforms.common import CommandSpec
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    executable = Path(sys.executable).resolve()
    spec = CommandSpec(
        command_id="controlled-post-spawn-stat-failure",
        executable=executable,
        argument_model=EmptyArguments,
        build_argv=lambda _: ["-c", "import time; time.sleep(60)"],
        cwd=executable.parent,
        environment=dict(os.environ),
    )

    class ObservedRunner(WindowsProcessRunner):
        def __init__(self) -> None:
            super().__init__({spec.command_id: spec})
            self.process: asyncio.subprocess.Process | None = None

        async def start_process(
            self,
            command_spec: CommandSpec,
            argv: list[str],
            environment: dict[str, str],
            *,
            execution_token: object,
            deadline: float | None = None,
        ) -> asyncio.subprocess.Process:
            self.process = await super().start_process(
                command_spec,
                argv,
                environment,
                execution_token=execution_token,
                deadline=deadline,
            )
            return self.process

    runner = ObservedRunner()
    original_stat = Path.stat
    sentinel = OSError("controlled post-spawn stat failure")

    def fail_after_spawn(path: Path, *args: object, **kwargs: object) -> Any:
        if runner.process is not None and path == executable:
            raise sentinel
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fail_after_spawn)

    with pytest.raises(OSError) as raised:
        await runner.run(
            CommandRequest(
                command_id=spec.command_id,
                arguments={},
                timeout_seconds=5.0,
            ),
            CancellationToken(),
        )

    assert raised.value is sentinel
    assert runner.process is not None and runner.process.returncode is not None
    assert runner._contexts == {}
    transport = runner.process._transport  # noqa: SLF001 - cleanup is under test
    assert transport.get_pipe_transport(1).is_closing()
    assert transport.get_pipe_transport(2).is_closing()


@pytest.mark.asyncio
async def test_external_cancellation_reaps_immediate_descendant_and_all_async_tasks(
    tmp_path: Path,
) -> None:
    import ctypes

    from wto_desktop_agent.platforms.common import CommandSpec
    from wto_desktop_agent.platforms.windows.process_runner import WindowsProcessRunner

    pid_file = tmp_path / "contained-processes.txt"
    child_program = (
        "import os,pathlib,subprocess,sys,time;"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
        "pathlib.Path(sys.argv[1]).write_text(f'{os.getpid()},{child.pid}',encoding='utf-8');"
        "time.sleep(60)"
    )
    executable = Path(sys.executable).resolve()
    spec = CommandSpec(
        command_id="controlled.immediate-descendant",
        executable=executable,
        argument_model=EmptyArguments,
        build_argv=lambda _: ["-c", child_program, str(pid_file)],
        cwd=executable.parent,
        environment=dict(os.environ),
    )

    class ObservedRunner(WindowsProcessRunner):
        def __init__(self) -> None:
            super().__init__({spec.command_id: spec})
            self.process: asyncio.subprocess.Process | None = None
            self.terminate_calls = 0
            self.after_finish_calls = 0
            self.terminate_started = asyncio.Event()
            self.allow_terminate = asyncio.Event()
            self.managed: list[asyncio.Future[Any]] = []

        async def start_process(
            self,
            command_spec: CommandSpec,
            argv: list[str],
            environment: dict[str, str],
            *,
            execution_token: object,
            deadline: float | None = None,
        ) -> asyncio.subprocess.Process:
            self.process = await super().start_process(
                command_spec,
                argv,
                environment,
                execution_token=execution_token,
                deadline=deadline,
            )
            return self.process

        async def terminate(self, process: asyncio.subprocess.Process) -> None:
            self.terminate_calls += 1
            self.terminate_started.set()
            await self.allow_terminate.wait()
            await super().terminate(process)

        def after_finish(self, process: asyncio.subprocess.Process) -> None:
            self.after_finish_calls += 1
            super().after_finish(process)

        def _create_managed_task(
            self,
            awaitable: Any,
            managed: list[asyncio.Future[Any]],
        ) -> asyncio.Task[Any]:
            task = super()._create_managed_task(awaitable, managed)
            self.managed.append(task)
            return task

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    kernel32.WaitForSingleObject.restype = ctypes.c_ulong
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    synchronize = 0x00100000
    runner = ObservedRunner()
    loop = asyncio.get_running_loop()
    loop_messages: list[dict[str, object]] = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: loop_messages.append(context))
    handles: list[int] = []
    try:
        task = asyncio.create_task(
            runner.run(
                CommandRequest(
                    command_id=spec.command_id,
                    arguments={},
                    timeout_seconds=30.0,
                ),
                CancellationToken(),
            )
        )
        assert await asyncio.to_thread(_wait_for_file, pid_file, 10.0)
        parent_pid, child_pid = (
            int(value) for value in pid_file.read_text(encoding="utf-8").split(",")
        )
        for process_id in (parent_pid, child_pid):
            handle = kernel32.OpenProcess(synchronize, False, process_id)
            assert handle
            handles.append(int(handle))

        task.cancel()
        await runner.terminate_started.wait()
        task.cancel()
        runner.allow_terminate.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0)

        assert runner.terminate_calls == 1
        assert runner.after_finish_calls == 1
        assert runner.process is not None and runner.process.returncode is not None
        assert all(kernel32.WaitForSingleObject(handle, 2000) == 0 for handle in handles)
        assert all(managed.done() for managed in runner.managed)
        assert runner._contexts == {}
        transport = runner.process._transport  # noqa: SLF001 - cleanup is under test
        assert transport.get_pipe_transport(1).is_closing()
        assert transport.get_pipe_transport(2).is_closing()
        forbidden_messages = ("Task was destroyed", "exception was never retrieved")
        assert not any(
            any(fragment in str(context.get("message", "")) for fragment in forbidden_messages)
            for context in loop_messages
        )
    finally:
        runner.allow_terminate.set()
        loop.set_exception_handler(previous_handler)
        for handle in handles:
            kernel32.CloseHandle(handle)
        if "task" in locals() and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
