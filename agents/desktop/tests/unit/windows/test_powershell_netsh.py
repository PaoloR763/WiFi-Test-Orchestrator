from __future__ import annotations

import re
from pathlib import Path

import pytest

from wto_desktop_agent.platforms.windows.netsh import parse_netsh_interfaces
from wto_desktop_agent.platforms.windows.powershell import (
    NETWORK_INVENTORY_SCRIPT_SHA256,
    PowerShellAdapter,
    PowerShellInventory,
    parse_powershell_inventory,
    script_sha256,
    verify_inventory_script,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "windows"
SCRIPT = (
    Path(__file__).parents[3]
    / "src"
    / "wto_desktop_agent"
    / "platforms"
    / "windows"
    / "scripts"
    / "network_inventory.ps1"
)


def test_powershell_51_and_7_have_stable_arrays() -> None:
    desktop = parse_powershell_inventory(
        (FIXTURES / "powershell" / "5.1" / "inventory.json").read_bytes()
    )
    core = parse_powershell_inventory(
        (FIXTURES / "powershell" / "7" / "inventory.json").read_bytes()
    )
    assert desktop.adapters[0].name == "Wi-Fi Ñ"
    assert desktop.adapters[0].received_errors is None
    assert desktop.adapters[0].sent_errors == 0
    assert core.adapters == []


@pytest.mark.parametrize("locale_name", ["en-US", "es-AR", "es-ES"])
def test_localized_netsh_fixtures(locale_name: str) -> None:
    raw = (FIXTURES / "netsh" / f"{locale_name}.txt").read_bytes()
    interfaces = parse_netsh_interfaces(raw)
    assert len(interfaces) == 1
    assert interfaces[0].guid is not None


def test_netsh_cp1252_and_unknown_labels() -> None:
    text = (FIXTURES / "netsh" / "es-AR.txt").read_text(encoding="utf-8")
    interface = parse_netsh_interfaces(text.encode("cp1252"))[0]
    assert interface.name == "Wi-Fi Ñ"
    assert interface.transmit_rate_mbps == 960.5


def test_noisy_or_invalid_powershell_is_rejected() -> None:
    with pytest.raises(ValueError, match="noise"):
        parse_powershell_inventory(b"warning\n{}")
    with pytest.raises(ValueError, match="invalid JSON"):
        parse_powershell_inventory(b"{truncated")


def test_packaged_powershell_script_hash_is_verified(tmp_path: Path) -> None:
    assert script_sha256() == NETWORK_INVENTORY_SCRIPT_SHA256
    assert verify_inventory_script().name == "network_inventory.ps1"
    changed = tmp_path / "network_inventory.ps1"
    changed.write_bytes(b"Write-Output '{}'")
    with pytest.raises(RuntimeError, match="integrity"):
        verify_inventory_script(changed)


def test_inventory_script_is_utf8_without_bom_and_crlf_only() -> None:
    raw = SCRIPT.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert b"\n" in raw
    assert raw.replace(b"\r\n", b"").find(b"\n") == -1


def test_inventory_script_schema_keys_match_strict_models() -> None:
    inventory = parse_powershell_inventory(
        (FIXTURES / "powershell" / "5.1" / "inventory.json").read_bytes()
    ).model_dump(mode="json")

    assert set(inventory) == set(PowerShellInventory.model_fields)
    assert set(inventory["adapters"][0]) == set(PowerShellAdapter.model_fields)


def test_inventory_script_queries_each_global_source_once_before_assembly() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assembly_offset = source.index("$adapters =")
    commands = (
        "Get-CimInstance",
        "Get-NetAdapter",
        "Get-NetAdapterStatistics",
        "Get-NetIPConfiguration",
        "Get-NetIPAddress",
        "Get-NetRoute",
        "Get-DnsClientServerAddress",
    )

    for command in commands:
        occurrences = list(re.finditer(rf"(?m)^\s*{re.escape(command)}(?:\s|$)", source))
        assert len(occurrences) == 1, command
        assert occurrences[0].start() < assembly_offset, command
    assert "$signedDrivers | Where-Object" not in source
    assert re.search(
        r"-Property\s+DeviceID,\s*Manufacturer,\s*DeviceName,\s*"
        r"DriverProviderName,\s*DriverVersion",
        source,
    )
    assert "-OperationTimeoutSec 8" in source
    provider_timeouts = {
        "Win32_PnPSignedDriver": 8000,
        "Get-NetAdapter": 8000,
        "Get-NetAdapterStatistics": 5000,
        "Get-NetIPConfiguration": 10000,
        "Get-NetIPAddress": 5000,
        "Get-NetRoute": 5000,
        "Get-DnsClientServerAddress": 5000,
    }
    for provider, timeout_ms in provider_timeouts.items():
        assert re.search(
            rf"Name\s*=\s*'{re.escape(provider)}'.*?" rf"TimeoutMilliseconds\s*=\s*{timeout_ms}\b",
            source,
            re.DOTALL,
        )
    active_loop_offset = source.index(
        "while (@($providerStates | Where-Object { $_.Status -eq 'running' }).Count -gt 0)"
    )
    assert "$coordinatorTimeoutMilliseconds = 26000" in source
    assert "$providerPhaseTimeoutMilliseconds = 20000" in source
    assert "$providerStartupTimeoutMilliseconds = 5000" in source
    assert "Start-Job" not in source
    assert "JobRepository" not in source
    assert "StopAsync" not in source
    assert "Stop-Job" not in source
    assert "Remove-Job" not in source
    assert "Wait-Job" not in source
    assert "Receive-Job" not in source
    assert "New-ProviderWorkerCommand" in source
    assert "-EncodedCommand ' + $encodedCommand" in source
    assert "ScriptBlock]::Create" not in source
    assert "Invoke-Expression" not in source
    assert "[Threading.EventWaitHandle]::OpenExisting('__WTO_START_EVENT__')" in source
    assert "[Threading.EventWaitHandle]::OpenExisting('__WTO_READY_EVENT__')" in source
    assert "$null = $readyEvent.Set()" in source
    assert "$null = $state.StartEvent.Set()" in source
    assert "$markerTask = $process.StandardOutput.ReadLineAsync()" in source
    assert "$State.WorkerHandle.ValidateMarker($markerProcessId, $markerCreationFileTime)" in source
    marker_read_offset = source.index("$markerTask = $process.StandardOutput.ReadLineAsync()")
    containment_offset = source.index("OpenForProcess($process)")
    release_offset = source.index("$null = $state.StartEvent.Set()")
    assert marker_read_offset < containment_offset < release_offset
    ready_function = source[
        source.index("function Update-ProviderReadyState") : source.index(
            "function Update-ProviderMarker"
        )
    ]
    assert "$markerDeliveryGraceMilliseconds" not in source
    assert "ReadySignaledMilliseconds" not in source
    assert "$State.ReadyObserved = $true" in ready_function
    assert ready_function.index("Update-ProviderMarker $State") < ready_function.index(
        "$State.Status = 'ready'"
    )
    assert "$State.MarkerObserved -and $State.IdentityStatus -ne 'validated'" in ready_function
    assert "$State.ReadyObserved -and $State.IdentityStatus -eq 'validated'" in ready_function
    assert "ReadyObserved = $false" in source
    assert "'ReadyMissing'" in source
    assert "Stop-Process" not in source
    assert "GetDirectChildProcessIds" not in source
    assert "Open($State.WorkerProcessId)" not in source
    assert "public static WtoInventoryProcessHandle Open(int processId)" not in source
    assert "OpenForProcess($process)" in source
    assert "DuplicateHandle(" in source
    assert "OpenProcess(" in source
    assert "GetProcessTimes(" in source
    assert "TerminateProcess(handle, 1)" in source
    assert "ProcessTerminate" not in source
    assert "AssignProcessToJobObject(" in source
    assert "TerminateJobObject(" in source
    assert "$providerCleanupTimeoutMilliseconds = 3000" in source
    assert "$providerFinalCleanupTimeoutMilliseconds = 1000" in source
    assert "$inventoryAssemblyReserveMilliseconds = 1000" in source
    assert "CloseProviderJobForCleanup()" in source
    assert "$state.ProviderJobCleanupVerified = $false" in source
    assert "$state.ProviderJobCleanupVerified = $true" in source
    assert "$state.ProviderJobCleanupVerified -and" in source
    assert "AllKnownProcessesExited" in source
    assert "IsProcessInJob(" in source
    assert containment_offset < release_offset
    close_offset = source.index("$state.WorkerHandle.CloseProviderJobForCleanup()")
    final_wait_offset = source.index("Update-ProviderProcessCleanupState $state", close_offset)
    event_dispose_offset = source.index("$state.StartEvent.Dispose()", final_wait_offset)
    assert close_offset < final_wait_offset < event_dispose_offset
    active_loop_start = active_loop_offset
    active_loop_end = source.index("} finally {", active_loop_start)
    active_loop = source[active_loop_start:active_loop_end]
    for forbidden_operation in ("WaitOne(", "ReadToEnd", "WaitForExit", "GetResult"):
        assert forbidden_operation not in active_loop
    assert "Complete-ProviderWorkers $providerStates" in source[active_loop_end:]
    assert "Test-ProviderReleaseBudgetAvailable" in source
    assert "$requiredPostReleaseMilliseconds" in source
    assert "$inventoryAssemblyReserveMilliseconds -le $coordinatorTimeoutMilliseconds" in source
    assert "WTO_INVENTORY_OUTER_TIMEOUT_MILLISECONDS" in source
    assert "$nowMilliseconds -ge $internalTimeoutMilliseconds" not in active_loop
    assert "[Console]::Error.WriteLine" in source


def test_inventory_script_never_opens_a_pid_with_terminate_access() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert "ProcessTerminate" not in source
    assert "PROCESS_TERMINATE" not in source
    assert "public static WtoInventoryProcessHandle Open(int processId)" not in source
    open_process_calls = list(re.finditer(r"\bOpenProcess\s*\(", source))
    assert len(open_process_calls) == 2  # wait-only cleanup call plus P/Invoke declaration
    cleanup_call = source[open_process_calls[0].start() : open_process_calls[1].start()]
    assert "ProcessQueryLimitedInformation | Synchronize" in cleanup_call
    assert "IsProcessInJob(processHandle, providerJob" in cleanup_call
