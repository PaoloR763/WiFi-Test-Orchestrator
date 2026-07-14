Set-StrictMode -Version Latest

$script:WtoSemVerPattern = '^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$'

function Get-WtoFullPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { throw "$Name cannot be empty." }
    if ($Path -match '(^|[\\/])\.\.([\\/]|$)') { throw "$Name cannot contain traversal segments." }
    if (-not [IO.Path]::IsPathRooted($Path)) { throw "$Name must be absolute." }
    try {
        $FullPath = [IO.Path]::GetFullPath($Path)
        $VolumeRoot = [IO.Path]::GetPathRoot($FullPath)
    }
    catch {
        throw "$Name cannot be normalized."
    }
    if ([string]::IsNullOrWhiteSpace($VolumeRoot)) { throw "$Name has no volume root." }
    if ($FullPath.TrimEnd('\', '/') -eq $VolumeRoot.TrimEnd('\', '/')) {
        throw "$Name cannot be a volume root."
    }
    return $FullPath.TrimEnd('\', '/')
}

function Test-WtoSamePath {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    return [string]::Equals(
        $Left.TrimEnd('\', '/'),
        $Right.TrimEnd('\', '/'),
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Test-WtoDescendantPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $Prefix = $Root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    return $Path.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-WtoNoReparseComponents {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $FullPath = Get-WtoFullPath -Path $Path -Name $Name
    $VolumeRoot = [IO.Path]::GetPathRoot($FullPath)
    $Current = $VolumeRoot.TrimEnd('\', '/')
    if ([string]::IsNullOrEmpty($Current)) { $Current = $VolumeRoot }
    $Relative = $FullPath.Substring($VolumeRoot.Length)
    foreach ($Part in $Relative.Split([char[]]@('\', '/'), [StringSplitOptions]::RemoveEmptyEntries)) {
        $Current = Join-Path $Current $Part
        try {
            $Item = Get-Item -Force -LiteralPath $Current -ErrorAction Stop
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            break
        }
        catch [System.Management.Automation.DriveNotFoundException] {
            break
        }
        catch {
            throw "$Name cannot be inspected safely: $Current"
        }
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Name cannot contain reparse points: $Current"
        }
    }
    return $FullPath
}

function Assert-WtoNotProtectedPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    foreach ($VariableName in @('ProgramFiles', 'ProgramData', 'SystemRoot')) {
        $Value = [Environment]::GetEnvironmentVariable($VariableName)
        if (-not [string]::IsNullOrWhiteSpace($Value)) {
            $Protected = Get-WtoFullPath -Path $Value -Name $VariableName
            if (Test-WtoSamePath -Left $Path -Right $Protected) {
                throw "$Name cannot be $VariableName."
            }
        }
    }
}

function Resolve-WtoPathLayout {
    param(
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [Parameter(Mandatory = $true)][string]$DataRoot,
        [switch]$TestMode,
        [string]$WorkRoot
    )

    $Install = Assert-WtoNoReparseComponents -Path $InstallRoot -Name 'InstallRoot'
    $Data = Assert-WtoNoReparseComponents -Path $DataRoot -Name 'DataRoot'
    Assert-WtoNotProtectedPath -Path $Install -Name 'InstallRoot'
    Assert-WtoNotProtectedPath -Path $Data -Name 'DataRoot'
    if (Test-WtoSamePath -Left $Install -Right $Data) {
        throw 'InstallRoot and DataRoot must be different directories.'
    }
    if ((Test-WtoDescendantPath -Path $Install -Root $Data) -or
        (Test-WtoDescendantPath -Path $Data -Root $Install)) {
        throw 'InstallRoot and DataRoot cannot contain one another.'
    }

    $NormalizedWorkRoot = $null
    if ($TestMode) {
        if ([string]::IsNullOrWhiteSpace($WorkRoot)) {
            throw 'TestMode requires an explicit WorkRoot.'
        }
        $NormalizedWorkRoot = Assert-WtoNoReparseComponents -Path $WorkRoot -Name 'WorkRoot'
        Assert-WtoNotProtectedPath -Path $NormalizedWorkRoot -Name 'WorkRoot'
        if (-not (Test-WtoDescendantPath -Path $Install -Root $NormalizedWorkRoot)) {
            throw 'InstallRoot must be below WorkRoot in TestMode.'
        }
        if (-not (Test-WtoDescendantPath -Path $Data -Root $NormalizedWorkRoot)) {
            throw 'DataRoot must be below WorkRoot in TestMode.'
        }
    }
    else {
        if ([string]::IsNullOrWhiteSpace($env:ProgramFiles) -or
            [string]::IsNullOrWhiteSpace($env:ProgramData)) {
            throw 'Canonical Windows installation roots are unavailable.'
        }
        $ExpectedInstall = Get-WtoFullPath -Path (Join-Path $env:ProgramFiles 'WiFi Test Orchestrator\Agent') -Name 'ExpectedInstallRoot'
        $ExpectedData = Get-WtoFullPath -Path (Join-Path $env:ProgramData 'WiFiTestOrchestrator\Agent') -Name 'ExpectedDataRoot'
        if (-not (Test-WtoSamePath -Left $Install -Right $ExpectedInstall)) {
            throw 'Production InstallRoot override is not permitted.'
        }
        if (-not (Test-WtoSamePath -Left $Data -Right $ExpectedData)) {
            throw 'Production DataRoot override is not permitted.'
        }
    }

    return [PSCustomObject]@{
        InstallRoot = $Install
        DataRoot = $Data
        WorkRoot = $NormalizedWorkRoot
        TestMode = [bool]$TestMode
    }
}

function Assert-WtoSemanticVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Version,
        [string]$Name = 'Version'
    )

    if ($Version -notmatch $script:WtoSemVerPattern) {
        throw "$Name must be a semantic version without path characters."
    }
    return $Version
}

function Assert-WtoChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $FullPath = Assert-WtoNoReparseComponents -Path $Path -Name $Name
    if (-not (Test-WtoDescendantPath -Path $FullPath -Root $Root)) {
        throw "$Name must be below its approved root."
    }
    return $FullPath
}

function Get-WtoConfigPath {
    param([Parameter(Mandatory = $true)]$Layout)

    $ConfigRoot = Assert-WtoChildPath -Path (Join-Path $Layout.DataRoot 'config') -Root $Layout.DataRoot -Name 'ConfigRoot'
    return Assert-WtoChildPath -Path (Join-Path $ConfigRoot 'wto-agent.toml') -Root $ConfigRoot -Name 'ConfigPath'
}

function Get-WtoStateRoot {
    param([Parameter(Mandatory = $true)]$Layout)

    return Assert-WtoChildPath -Path (Join-Path $Layout.DataRoot 'state') -Root $Layout.DataRoot -Name 'StateRoot'
}

function Get-WtoVersionRoot {
    param(
        [Parameter(Mandatory = $true)]$Layout,
        [Parameter(Mandatory = $true)][string]$Version
    )

    $SafeVersion = Assert-WtoSemanticVersion -Version $Version
    $VersionsRoot = Assert-WtoChildPath -Path (Join-Path $Layout.InstallRoot 'versions') -Root $Layout.InstallRoot -Name 'VersionsRoot'
    return Assert-WtoChildPath -Path (Join-Path $VersionsRoot $SafeVersion) -Root $VersionsRoot -Name 'VersionRoot'
}

function Assert-WtoRegularFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $FullPath = Assert-WtoNoReparseComponents -Path $Path -Name $Name
    try {
        $Item = Get-Item -Force -LiteralPath $FullPath -ErrorAction Stop
    }
    catch {
        throw "$Name is unavailable."
    }
    if ($Item.PSIsContainer -or (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Name must be a regular file."
    }
    return $FullPath
}

function Assert-WtoDatabaseBackup {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Layout,
        [switch]$MustExist
    )

    $StateRoot = Get-WtoStateRoot -Layout $Layout
    $Backup = Assert-WtoChildPath -Path $Path -Root $StateRoot -Name 'DatabaseBackup'
    $Name = [IO.Path]::GetFileName($Backup)
    $ExpectedName = $false
    if ($Name -match '^agent\.sqlite3\.pre-upgrade-(?<Version>.+)\.bak$') {
        $null = Assert-WtoSemanticVersion -Version $Matches.Version -Name 'DatabaseBackup version'
        $ExpectedName = $true
    }
    if ($Layout.TestMode -and $Name -eq 'agent.sqlite3.test-backup') {
        $ExpectedName = $true
    }
    if (-not $ExpectedName) { throw 'DatabaseBackup has an unexpected filename.' }
    if ($MustExist) {
        $Backup = Assert-WtoRegularFile -Path $Backup -Name 'DatabaseBackup'
    }
    return $Backup
}

function Assert-WtoInstalledExecutable {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Layout,
        [Parameter(Mandatory = $true)][string]$Version
    )

    $VersionRoot = Get-WtoVersionRoot -Layout $Layout -Version $Version
    $Expected = Join-Path $VersionRoot 'wto-agent.exe'
    $Executable = Assert-WtoRegularFile -Path $Path -Name 'InstalledExecutable'
    if (-not (Test-WtoSamePath -Left $Executable -Right $Expected)) {
        throw 'InstalledExecutable is outside the approved version root.'
    }
    return $Executable
}

function Get-WtoInstalledExecutables {
    param([Parameter(Mandatory = $true)]$Layout)

    $VersionsRoot = Assert-WtoChildPath -Path (Join-Path $Layout.InstallRoot 'versions') -Root $Layout.InstallRoot -Name 'VersionsRoot'
    if (-not (Test-Path -LiteralPath $VersionsRoot -PathType Container)) { return @() }
    $Result = @()
    foreach ($Directory in Get-ChildItem -Force -LiteralPath $VersionsRoot -Directory -ErrorAction Stop) {
        if (($Directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'VersionsRoot contains a reparse point.'
        }
        $Version = Assert-WtoSemanticVersion -Version $Directory.Name -Name 'Installed version'
        $Candidate = Join-Path $Directory.FullName 'wto-agent.exe'
        if (Test-Path -LiteralPath $Candidate -PathType Leaf) {
            $Executable = Assert-WtoInstalledExecutable -Path $Candidate -Layout $Layout -Version $Version
            $Result += Get-Item -Force -LiteralPath $Executable
        }
    }
    return @($Result)
}

function Assert-WtoNoReparseTree {
    param([Parameter(Mandatory = $true)][string]$Path)

    $Pending = New-Object System.Collections.Stack
    $Pending.Push($Path)
    while ($Pending.Count -gt 0) {
        $Current = [string]$Pending.Pop()
        $Item = Get-Item -Force -LiteralPath $Current -ErrorAction Stop
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Removal target contains a reparse point: $Current"
        }
        if ($Item.PSIsContainer) {
            foreach ($Child in Get-ChildItem -Force -LiteralPath $Current -ErrorAction Stop) {
                if (($Child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Removal target contains a reparse point: $($Child.FullName)"
                }
                if ($Child.PSIsContainer) { $Pending.Push($Child.FullName) }
            }
        }
    }
}

function Assert-WtoApprovedRemovalTarget {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Layout,
        [Parameter(Mandatory = $true)][ValidateSet('InstallRoot', 'DataRoot')][string]$Kind
    )

    $Approved = if ($Kind -eq 'InstallRoot') { $Layout.InstallRoot } else { $Layout.DataRoot }
    $Target = Assert-WtoNoReparseComponents -Path $Path -Name 'RemovalTarget'
    Assert-WtoNotProtectedPath -Path $Target -Name 'RemovalTarget'
    if (-not (Test-WtoSamePath -Left $Target -Right $Approved)) {
        throw 'RemovalTarget is outside the approved layout.'
    }
    if (-not (Test-Path -LiteralPath $Target -PathType Container)) {
        throw 'RemovalTarget must be an existing directory.'
    }
    Assert-WtoNoReparseTree -Path $Target
    return $Target
}

function Remove-WtoApprovedTree {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Layout,
        [Parameter(Mandatory = $true)][ValidateSet('InstallRoot', 'DataRoot')][string]$Kind
    )

    $ApprovedPath = Assert-WtoApprovedRemovalTarget -Path $Path -Layout $Layout -Kind $Kind
    Remove-Item -LiteralPath $ApprovedPath -Recurse -Force
}
