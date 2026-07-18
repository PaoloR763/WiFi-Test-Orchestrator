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
$SourceInventoryScript = Join-Path $Root 'agents\desktop\src\wto_desktop_agent\platforms\windows\scripts\network_inventory.ps1'
$BundledInventoryScript = Join-Path $Bundle '_internal\wto_desktop_agent\platforms\windows\scripts\network_inventory.ps1'
$BundleManifest = Get-Content -Raw -LiteralPath (Join-Path $Bundle 'bundle-manifest.json') | ConvertFrom-Json
$InventoryManifestPath = '_internal/wto_desktop_agent/platforms/windows/scripts/network_inventory.ps1'
$InventoryManifestHash = $BundleManifest.files.PSObject.Properties[$InventoryManifestPath].Value
$ExpectedInventoryHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $SourceInventoryScript).Hash.ToLowerInvariant()
if (-not (Test-Path -LiteralPath $BundledInventoryScript -PathType Leaf)) { throw 'PyInstaller bundle omitted the inventory script.' }
if ($InventoryManifestHash -ne $ExpectedInventoryHash) { throw 'PyInstaller inventory manifest hash differs from the source.' }
$SourceInventoryBytes = [IO.File]::ReadAllBytes($SourceInventoryScript)
$BundledInventoryBytes = [IO.File]::ReadAllBytes($BundledInventoryScript)
if (
    $SourceInventoryBytes.Length -ne $BundledInventoryBytes.Length -or
    [Convert]::ToBase64String($SourceInventoryBytes) -cne [Convert]::ToBase64String($BundledInventoryBytes)
) {
    throw 'PyInstaller bundled inventory script differs from the source.'
}

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
# Doctor is intentionally read-only and must not bootstrap the SQLite/state
# layout. Exercise a normal runtime command first, then verify diagnostics.
& $Current --config $ConfigPath status | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Frozen executable state initialization failed.' }
& $Current --config $ConfigPath doctor --json | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Frozen executable doctor failed.' }
$Backup = Join-Path $DataRoot 'state\agent.sqlite3.test-backup'
& $Current --config $ConfigPath maintenance backup --destination $Backup | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Frozen executable backup failed.' }

& "$PSScriptRoot\rollback-agent.ps1" -PreviousVersion '0.1.0' -DatabaseBackup $Backup -InstallRoot $Layout.InstallRoot -DataRoot $Layout.DataRoot -ConfirmRollback -TestMode -WorkRoot $Layout.WorkRoot
& "$PSScriptRoot\uninstall-agent.ps1" -InstallRoot $Layout.InstallRoot -DataRoot $Layout.DataRoot -TestMode -WorkRoot $Layout.WorkRoot
if (Test-Path -LiteralPath $InstallRoot) { throw 'TestMode uninstall left the install root.' }
if (-not (Test-Path -LiteralPath $DataRoot)) { throw 'Uninstall removed identity/state by default.' }
