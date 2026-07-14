param(
    [string]$InstallRoot = "$env:ProgramFiles\WiFi Test Orchestrator\Agent",
    [string]$DataRoot = "$env:ProgramData\WiFiTestOrchestrator\Agent",
    [switch]$PurgeIdentity,
    [switch]$ConfirmPurge,
    [switch]$TestMode,
    [string]$WorkRoot
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\path-safety.ps1"
$Layout = Resolve-WtoPathLayout -InstallRoot $InstallRoot -DataRoot $DataRoot -TestMode:$TestMode -WorkRoot $WorkRoot
if ($TestMode -and $PurgeIdentity) { throw 'Identity purge cannot run in TestMode.' }
$ConfigPath = Get-WtoConfigPath -Layout $Layout
$Executable = Get-WtoInstalledExecutables -Layout $Layout |
    Sort-Object FullName -Descending | Select-Object -First 1
if ($PurgeIdentity -and ($null -eq $Executable)) {
    throw 'Identity purge requires the installed service executable.'
}
if (($null -ne $Executable) -and (-not $TestMode)) {
    if ($PurgeIdentity) {
        if (-not $ConfirmPurge) { throw 'Identity purge requires -ConfirmPurge.' }
        & $Executable.FullName --config $ConfigPath service purge-identity --confirm
        if ($LASTEXITCODE -ne 0) { throw 'Service-owned identity purge failed; uninstall aborted.' }
    }
    & $Executable.FullName --config $ConfigPath service uninstall
    if ($LASTEXITCODE -ne 0) { throw 'Service uninstall failed.' }
}
if (Test-Path -LiteralPath $Layout.InstallRoot) {
    Remove-WtoApprovedTree -Path $Layout.InstallRoot -Layout $Layout -Kind InstallRoot
}
if ($PurgeIdentity -and $ConfirmPurge -and (Test-Path -LiteralPath $Layout.DataRoot)) {
    Remove-WtoApprovedTree -Path $Layout.DataRoot -Layout $Layout -Kind DataRoot
}
