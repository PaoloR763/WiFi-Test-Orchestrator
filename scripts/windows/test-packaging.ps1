param(
    [Parameter(Mandatory = $true)][string]$BundlePath,
    [Parameter(Mandatory = $true)][string]$WorkRoot
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
. "$PSScriptRoot\path-safety.ps1"
$Bundle = Assert-WtoNoReparseComponents -Path $BundlePath -Name 'BundlePath'
$WorkRoot = Assert-WtoNoReparseComponents -Path $WorkRoot -Name 'WorkRoot'
$InstallRoot = Join-Path $WorkRoot 'ProgramFiles\Agent'
$DataRoot = Join-Path $WorkRoot 'ProgramData\Agent'
$Layout = Resolve-WtoPathLayout -InstallRoot $InstallRoot -DataRoot $DataRoot -TestMode -WorkRoot $WorkRoot
$ConfigTemplate = Join-Path $Root 'agents\desktop\wto-agent.example.toml'

Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' | ForEach-Object {
    $null = [scriptblock]::Create((Get-Content -Raw -LiteralPath $_.FullName))
}

& "$PSScriptRoot\install-agent.ps1" -BundlePath $Bundle -Version '0.1.0' -ConfigTemplate $ConfigTemplate -InstallRoot $Layout.InstallRoot -DataRoot $Layout.DataRoot -TestMode -WorkRoot $Layout.WorkRoot
$First = Join-Path $InstallRoot 'versions\0.1.0\wto-agent.exe'
if (-not (Test-Path -LiteralPath $First -PathType Leaf)) { throw 'TestMode install failed.' }

& "$PSScriptRoot\upgrade-agent.ps1" -BundlePath $Bundle -Version '0.1.1' -ConfigTemplate $ConfigTemplate -InstallRoot $Layout.InstallRoot -DataRoot $Layout.DataRoot -TestMode -WorkRoot $Layout.WorkRoot
$Current = Join-Path $InstallRoot 'versions\0.1.1\wto-agent.exe'
if (-not (Test-Path -LiteralPath $Current -PathType Leaf)) { throw 'TestMode upgrade failed.' }

$ConfigPath = Join-Path $DataRoot 'config\wto-agent.toml'
& $Current --config $ConfigPath doctor --json | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Frozen executable doctor failed.' }
$Backup = Join-Path $DataRoot 'state\agent.sqlite3.test-backup'
& $Current --config $ConfigPath maintenance backup --destination $Backup | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Frozen executable backup failed.' }

& "$PSScriptRoot\rollback-agent.ps1" -PreviousVersion '0.1.0' -DatabaseBackup $Backup -InstallRoot $Layout.InstallRoot -DataRoot $Layout.DataRoot -ConfirmRollback -TestMode -WorkRoot $Layout.WorkRoot
& "$PSScriptRoot\uninstall-agent.ps1" -InstallRoot $Layout.InstallRoot -DataRoot $Layout.DataRoot -TestMode -WorkRoot $Layout.WorkRoot
if (Test-Path -LiteralPath $InstallRoot) { throw 'TestMode uninstall left the install root.' }
if (-not (Test-Path -LiteralPath $DataRoot)) { throw 'Uninstall removed identity/state by default.' }
