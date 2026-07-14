param(
    [string]$OutputRoot = "$PSScriptRoot\..\..\release\windows-agent"
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
$null = New-Item -ItemType Directory -Force -Path $OutputRoot
$OutputRoot = (Resolve-Path -LiteralPath $OutputRoot).Path
$Project = Join-Path $Root 'agents\desktop'
$Spec = Join-Path $Project 'packaging\windows\wto-agent.spec'
$Dist = Join-Path $OutputRoot 'dist'
$Work = Join-Path $OutputRoot 'build'
$Mutex = New-Object Threading.Mutex($false, 'Local\WTO.WindowsAgent.Build')
if (-not $Mutex.WaitOne(0)) { throw 'Another Windows agent build is active.' }

try {
    & python (Join-Path $Root 'scripts\sync_desktop_contracts.py') --check
    if ($LASTEXITCODE -ne 0) { throw 'Desktop contract verification failed.' }
    & python -m PyInstaller --clean --noconfirm --distpath $Dist --workpath $Work $Spec
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed.' }

    $Bundle = Join-Path $Dist 'wto-agent'
    $BundleUri = New-Object Uri(($Bundle.TrimEnd('\') + '\'))
    $Files = [ordered]@{}
    Get-ChildItem -LiteralPath $Bundle -Recurse -File | Sort-Object FullName | ForEach-Object {
        $FileUri = New-Object Uri($_.FullName)
        $Relative = [Uri]::UnescapeDataString($BundleUri.MakeRelativeUri($FileUri).ToString())
        $Files[$Relative] = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
    }
    $Manifest = [ordered]@{
        schema_version = '1.0.0'
        product = 'wto-desktop-agent'
        packaging = 'pyinstaller-onedir'
        reproducible_byte_for_byte = $false
        build_inputs = [ordered]@{
            spec_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Spec).Hash.ToLowerInvariant()
            requirements_lock_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $Project 'requirements-dev.lock')).Hash.ToLowerInvariant()
        }
        files = $Files
    }
    $Json = $Manifest | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText((Join-Path $Bundle 'bundle-manifest.json'), $Json, (New-Object Text.UTF8Encoding($false)))
}
finally {
    $Mutex.ReleaseMutex()
    $Mutex.Dispose()
}
