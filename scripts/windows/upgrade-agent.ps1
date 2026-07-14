param(
    [Parameter(Mandatory = $true)][string]$BundlePath,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$ConfigTemplate,
    [string]$InstallRoot = "$env:ProgramFiles\WiFi Test Orchestrator\Agent",
    [string]$DataRoot = "$env:ProgramData\WiFiTestOrchestrator\Agent",
    [switch]$TestMode,
    [string]$WorkRoot
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\path-safety.ps1"
$Layout = Resolve-WtoPathLayout -InstallRoot $InstallRoot -DataRoot $DataRoot -TestMode:$TestMode -WorkRoot $WorkRoot
$Version = Assert-WtoSemanticVersion -Version $Version
$ConfigPath = Get-WtoConfigPath -Layout $Layout
$Current = Get-WtoInstalledExecutables -Layout $Layout |
    Sort-Object FullName -Descending | Select-Object -First 1
$PreviousVersion = if ($null -ne $Current) { $Current.Directory.Name } else { $null }
$Backup = $null
if (($null -ne $Current) -and (-not $TestMode)) {
    & $Current.FullName --config $ConfigPath service stop
    if (($LASTEXITCODE -ne 0) -and ($LASTEXITCODE -ne 1)) { throw 'Service stop failed.' }
    $Backup = Assert-WtoDatabaseBackup -Path (Join-Path (Get-WtoStateRoot -Layout $Layout) "agent.sqlite3.pre-upgrade-$Version.bak") -Layout $Layout
    & $Current.FullName --config $ConfigPath maintenance backup --destination $Backup
    if ($LASTEXITCODE -ne 0) { throw 'Verified SQLite backup failed; upgrade aborted.' }
    $Backup = Assert-WtoDatabaseBackup -Path $Backup -Layout $Layout -MustExist
}
try {
    & "$PSScriptRoot\install-agent.ps1" -BundlePath $BundlePath -Version $Version -ConfigTemplate $ConfigTemplate -InstallRoot $Layout.InstallRoot -DataRoot $Layout.DataRoot -TestMode:$TestMode -WorkRoot $Layout.WorkRoot
}
catch {
    if ((-not $TestMode) -and $PreviousVersion -and $Backup) {
        $Backup = Assert-WtoDatabaseBackup -Path $Backup -Layout $Layout -MustExist
        & "$PSScriptRoot\rollback-agent.ps1" -PreviousVersion $PreviousVersion -DatabaseBackup $Backup -InstallRoot $Layout.InstallRoot -DataRoot $Layout.DataRoot -ConfirmRollback
    }
    throw
}
