param([Parameter(Mandatory = $true)][string]$Username)
$ErrorActionPreference = 'Stop'
$secure = Read-Host 'Initial administrator credential' -AsSecureString
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    $plain | docker compose exec -T backend python -m wto_backend.cli bootstrap-admin --username $Username --password-stdin
    if ($LASTEXITCODE -ne 0) { throw 'Administrator bootstrap failed' }
}
finally {
    if ($null -ne $plain) { $plain = $null }
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
}
