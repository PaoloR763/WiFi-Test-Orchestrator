param(
    [Parameter(Mandatory = $true)][string]$AgentExecutable,
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [string]$OutputPath = "$PWD\windows-real-hardware-validation.json",
    [switch]$Run
)

$ErrorActionPreference = 'Stop'
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
function Write-ValidationJson([object]$Value, [int]$Depth) {
    $Json = $Value | ConvertTo-Json -Depth $Depth
    [IO.File]::WriteAllText($OutputPath, $Json, (New-Object Text.UTF8Encoding($false)))
}
if (-not $Run) {
    $Result = [ordered]@{
        schema_version = '1.0.0'
        status = 'NOT RUN'
        reason = 'Re-run with -Run on an explicitly authorized Windows 10/11 host.'
        checks = @('inventory', 'capabilities', 'doctor', 'scan-manual', 'sleep-resume-manual', 'reboot-manual', 'npcap-optional')
    }
    Write-ValidationJson $Result 3
    exit 0
}

$Executable = (Resolve-Path -LiteralPath $AgentExecutable).Path
$Config = (Resolve-Path -LiteralPath $ConfigPath).Path
$Inventory = & $Executable --config $Config inventory | ConvertFrom-Json
$Capabilities = & $Executable --config $Config capabilities --json | ConvertFrom-Json
$Doctor = & $Executable --config $Config doctor --json | ConvertFrom-Json
$Result = [ordered]@{
    schema_version = '1.0.0'
    status = 'PARTIAL'
    sensitive_wifi_identifiers = $true
    collected_at = [DateTimeOffset]::UtcNow.ToString('o')
    os = [Environment]::OSVersion.VersionString
    culture = [Globalization.CultureInfo]::CurrentUICulture.Name
    inventory = $Inventory
    capabilities = $Capabilities
    doctor = $Doctor
    manual_checks = [ordered]@{
        scan_real = 'NOT RUN'
        rssi_real = 'NOT RUN'
        six_ghz = 'NOT RUN'
        sleep_resume = 'NOT RUN'
        reboot = 'NOT RUN'
        localservice = 'NOT RUN'
        npcap = 'NOT RUN'
    }
}
Write-ValidationJson $Result 20
