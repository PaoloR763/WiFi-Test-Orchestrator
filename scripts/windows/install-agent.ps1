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
$Bundle = Assert-WtoNoReparseComponents -Path $BundlePath -Name 'BundlePath'
if (-not (Test-Path -LiteralPath $Bundle -PathType Container)) { throw 'BundlePath is unavailable.' }
$ConfigTemplate = Assert-WtoRegularFile -Path $ConfigTemplate -Name 'ConfigTemplate'
$BundlePrefix = $Bundle.TrimEnd('\') + '\'
$ManifestPath = Join-Path $Bundle 'bundle-manifest.json'
$ManifestPath = Assert-WtoRegularFile -Path $ManifestPath -Name 'Bundle manifest'
$Manifest = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json
foreach ($Property in $Manifest.files.PSObject.Properties) {
    if ([IO.Path]::IsPathRooted($Property.Name) -or $Property.Name -match '(^|[\\/])\.\.([\\/]|$)') {
        throw "Unsafe bundle manifest path: $($Property.Name)"
    }
    $Candidate = Join-Path $Bundle $Property.Name
    $CandidateFull = [IO.Path]::GetFullPath($Candidate)
    if (-not $CandidateFull.StartsWith($BundlePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Bundle manifest path escapes bundle: $($Property.Name)"
    }
    $Candidate = Assert-WtoRegularFile -Path $Candidate -Name "Bundle file $($Property.Name)"
    $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Candidate).Hash.ToLowerInvariant()
    if ($Actual -ne [string]$Property.Value) { throw "Bundle hash mismatch: $($Property.Name)" }
}

$VersionRoot = Get-WtoVersionRoot -Layout $Layout -Version $Version
New-Item -ItemType Directory -Force -Path $VersionRoot | Out-Null
foreach ($Property in $Manifest.files.PSObject.Properties) {
    $Source = Assert-WtoRegularFile -Path (Join-Path $Bundle $Property.Name) -Name "Bundle file $($Property.Name)"
    $Destination = Assert-WtoChildPath -Path (Join-Path $VersionRoot $Property.Name) -Root $VersionRoot -Name 'Bundle destination'
    $DestinationParent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Force -Path $DestinationParent | Out-Null
    $null = Assert-WtoNoReparseComponents -Path $DestinationParent -Name 'Bundle destination parent'
    if (Test-Path -LiteralPath $Destination) {
        $null = Assert-WtoRegularFile -Path $Destination -Name 'Existing bundle destination'
    }
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    $null = Assert-WtoRegularFile -Path $Destination -Name 'Installed bundle file'
}
foreach ($Name in @('config', 'state', 'logs', 'artifacts')) {
    $Directory = Assert-WtoChildPath -Path (Join-Path $Layout.DataRoot $Name) -Root $Layout.DataRoot -Name "Data directory $Name"
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $null = Assert-WtoNoReparseComponents -Path $Directory -Name "Data directory $Name"
}
$ConfigPath = Get-WtoConfigPath -Layout $Layout
if (-not (Test-Path -LiteralPath $ConfigPath)) {
    $Content = [IO.File]::ReadAllText($ConfigTemplate)
    $StatePath = (Get-WtoStateRoot -Layout $Layout).Replace('\', '/')
    $ArtifactsPath = (Assert-WtoChildPath -Path (Join-Path $Layout.DataRoot 'artifacts') -Root $Layout.DataRoot -Name 'ArtifactsRoot').Replace('\', '/')
    if ([regex]::Matches($Content, '(?m)^state_dir\s*=.*$').Count -ne 1) {
        throw 'Config template must contain exactly one state_dir assignment.'
    }
    $Content = [regex]::Replace($Content, '(?m)^state_dir\s*=.*$', "state_dir = `"$StatePath`"")
    if ([regex]::Matches($Content, '(?m)^artifacts_dir\s*=.*$').Count -gt 1) {
        throw 'Config template contains duplicate artifacts_dir assignments.'
    }
    if ($Content -match '(?m)^artifacts_dir\s*=.*$') {
        $Content = [regex]::Replace($Content, '(?m)^artifacts_dir\s*=.*$', "artifacts_dir = `"$ArtifactsPath`"")
    } else {
        $Content = $Content.TrimEnd() + "`r`nartifacts_dir = `"$ArtifactsPath`"`r`n"
    }
    [IO.File]::WriteAllText($ConfigPath, $Content, (New-Object Text.UTF8Encoding($false)))
}
$Executable = Join-Path $VersionRoot 'wto-agent.exe'
$Executable = Assert-WtoInstalledExecutable -Path $Executable -Layout $Layout -Version $Version
if (-not $TestMode) {
    & $Executable --config $ConfigPath service install --executable $Executable
    if ($LASTEXITCODE -ne 0) { throw 'Service registration failed.' }
    & $Executable --config $ConfigPath service start
    if ($LASTEXITCODE -ne 0) { throw 'Service start failed.' }
    $Status = & $Executable --config $ConfigPath service status | ConvertFrom-Json
    if (($LASTEXITCODE -ne 0) -or ($Status.status -ne 'running')) { throw 'Service health check failed.' }
}
