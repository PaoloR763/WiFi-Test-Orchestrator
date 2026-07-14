param(
    [Parameter(Mandatory = $true)][string]$PreviousVersion,
    [Parameter(Mandatory = $true)][string]$DatabaseBackup,
    [string]$InstallRoot = "$env:ProgramFiles\WiFi Test Orchestrator\Agent",
    [string]$DataRoot = "$env:ProgramData\WiFiTestOrchestrator\Agent",
    [switch]$ConfirmRollback,
    [switch]$TestMode,
    [string]$WorkRoot
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\path-safety.ps1"
$Layout = Resolve-WtoPathLayout -InstallRoot $InstallRoot -DataRoot $DataRoot -TestMode:$TestMode -WorkRoot $WorkRoot
if (-not $ConfirmRollback) { throw 'Rollback requires -ConfirmRollback.' }
$PreviousVersion = Assert-WtoSemanticVersion -Version $PreviousVersion -Name 'PreviousVersion'
$Executable = Join-Path (Get-WtoVersionRoot -Layout $Layout -Version $PreviousVersion) 'wto-agent.exe'
$Executable = Assert-WtoInstalledExecutable -Path $Executable -Layout $Layout -Version $PreviousVersion
$DatabaseBackup = Assert-WtoDatabaseBackup -Path $DatabaseBackup -Layout $Layout -MustExist
$MaintenanceExecutable = Get-WtoInstalledExecutables -Layout $Layout |
    Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
$ConfigPath = Get-WtoConfigPath -Layout $Layout
if (-not $TestMode) {
    if ($null -eq $MaintenanceExecutable) { throw 'Maintenance executable is unavailable.' }
    & $MaintenanceExecutable.FullName --config $ConfigPath service stop
    if (($LASTEXITCODE -ne 0) -and ($LASTEXITCODE -ne 1)) { throw 'Service stop failed.' }
    & $MaintenanceExecutable.FullName --config $ConfigPath maintenance restore --source $DatabaseBackup --confirm
    if ($LASTEXITCODE -ne 0) { throw 'Verified database restore failed.' }
}
if (-not $TestMode) {
    & $Executable --config $ConfigPath service install --executable $Executable
    if ($LASTEXITCODE -ne 0) { throw 'Rollback service registration failed.' }
    & $Executable --config $ConfigPath service start
    if ($LASTEXITCODE -ne 0) { throw 'Rollback service start failed.' }
    $Status = & $Executable --config $ConfigPath service status | ConvertFrom-Json
    if (($LASTEXITCODE -ne 0) -or ($Status.status -ne 'running')) { throw 'Rollback health check failed.' }
}
