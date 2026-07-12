$ErrorActionPreference = 'Stop'

$ProjectName = "wto-smoke-$PID"
$TrackedEnvironment = @(
    'COMPOSE_PROJECT_NAME',
    'WTO_HTTP_PORT',
    'WTO_ALLOWED_ORIGIN',
    'SIM_ENROLLMENT_TOKEN'
)
$OriginalEnvironment = @{}
foreach ($name in $TrackedEnvironment) {
    $OriginalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

function Restore-SmokeEnvironment {
    foreach ($name in $TrackedEnvironment) {
        $value = $OriginalEnvironment[$name]
        if ($null -eq $value) {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
        else {
            [Environment]::SetEnvironmentVariable($name, $value, 'Process')
        }
    }
}

function Invoke-SmokeCompose {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    & docker compose --project-name $ProjectName @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Compose command failed with exit code $LASTEXITCODE"
    }
}

function Assert-SmokeProjectRemoved {
    $resourceCommands = @(
        @{ Type = 'container'; Arguments = @('container', 'ls', '--all', '--quiet') },
        @{ Type = 'network'; Arguments = @('network', 'ls', '--quiet') },
        @{ Type = 'volume'; Arguments = @('volume', 'ls', '--quiet') }
    )
    $leftovers = @()

    foreach ($resourceCommand in $resourceCommands) {
        $resourceType = $resourceCommand.Type
        $arguments = $resourceCommand.Arguments + @(
            '--filter',
            "label=com.docker.compose.project=$ProjectName"
        )
        $ids = @(& docker @arguments)
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to verify smoke $resourceType cleanup."
        }
        foreach ($id in $ids) {
            if ($id) { $leftovers += "${resourceType}:$id" }
        }
    }

    if ($leftovers.Count -gt 0) {
        throw "Smoke cleanup regression: resources remain for project ${ProjectName}: $($leftovers -join ', ')"
    }
}

function Remove-SmokeProject {
    $cleanupFailure = $null
    try {
        Invoke-SmokeCompose down --volumes --remove-orphans
    }
    catch {
        $cleanupFailure = $_
    }

    Assert-SmokeProjectRemoved
    if ($null -ne $cleanupFailure) { throw $cleanupFailure }
}

$smokePort = if ([string]::IsNullOrWhiteSpace($env:WTO_SMOKE_PORT)) {
    '18080'
}
else {
    $env:WTO_SMOKE_PORT
}
$env:WTO_HTTP_PORT = $smokePort
$baseUrl = "http://127.0.0.1:$smokePort"
$env:WTO_ALLOWED_ORIGIN = $baseUrl
$randomBytes = New-Object byte[] 24
$randomGenerator = [Security.Cryptography.RandomNumberGenerator]::Create()
$randomGenerator.GetBytes($randomBytes)
$randomGenerator.Dispose()
$adminPassword = 'Smoke-' + [Convert]::ToBase64String($randomBytes)
$operationFailure = $null
$cleanupFailure = $null

try {
    Invoke-SmokeCompose up -d --build --wait
    Invoke-SmokeCompose exec -T backend python -m wto_backend.cli seed-rbac
    $adminPassword | docker compose --project-name $ProjectName exec -T backend python -m wto_backend.cli bootstrap-admin --username smoke-admin --password-stdin
    if ($LASTEXITCODE -ne 0) { throw 'Admin bootstrap failed' }
    $live = Invoke-RestMethod "$baseUrl/health/live"
    if ($live.status -ne 'alive') { throw 'Liveness response was unexpected' }
    $ready = Invoke-RestMethod "$baseUrl/health/ready"
    if ($ready.status -ne 'ready') { throw 'Readiness response was unexpected' }
    $frontend = Invoke-WebRequest "$baseUrl/" -UseBasicParsing
    if ($frontend.Content -notmatch 'WiFi Test Orchestrator') { throw 'Frontend was not served' }
    $openapi = Invoke-RestMethod "$baseUrl/openapi.json"
    if ($openapi.paths.PSObject.Properties.Name -notcontains '/health/live') {
        throw 'OpenAPI was not served through the reverse proxy'
    }
    if ($openapi.paths.PSObject.Properties.Name -match '^/demo/') {
        throw 'Demo endpoints must not appear in OpenAPI'
    }
    $webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $login = Invoke-RestMethod "$baseUrl/api/internal/v1/auth/login" -Method Post -WebSession $webSession -ContentType 'application/json' -Body (@{ username = 'smoke-admin'; password = $adminPassword } | ConvertTo-Json)
    $protected = Invoke-RestMethod "$baseUrl/api/internal/v1/admin/protected" -Headers @{ Authorization = "Bearer $($login.access_token)" }
    if ($protected.status -ne 'authorized') { throw 'RBAC protected endpoint failed' }
    $enrollment = Invoke-RestMethod "$baseUrl/api/v1/enrollment-tokens" -Method Post -Headers @{ Authorization = "Bearer $($login.access_token)" } -ContentType 'application/json' -Body (@{ scope = 'agent.enroll'; expires_in_minutes = 15; allowed_platforms = @('simulated'); bound_agent_id = $null } | ConvertTo-Json)
    $env:SIM_ENROLLMENT_TOKEN = $enrollment.enrollment_token
    Invoke-SmokeCompose up -d --no-deps --force-recreate --wait simulated-agent
    $refresh = Invoke-RestMethod "$baseUrl/api/internal/v1/auth/refresh" -Method Post -WebSession $webSession -Headers @{ Origin = $baseUrl }
    if ($refresh.token_type -ne 'bearer') { throw 'Refresh rotation failed' }
    $adminPassword = $null

    $smokePassed = $false
    for ($attempt = 0; $attempt -lt 12; $attempt++) {
        $agentLogs = Invoke-SmokeCompose logs --no-color simulated-agent
        if ($agentLogs -match [Regex]::Escape($env:SIM_ENROLLMENT_TOKEN)) {
            throw 'Simulated-agent logs exposed the enrollment token.'
        }
        if (($agentLogs -match 'Normative enrollment and credential rotation completed') -and ($agentLogs -match 'Normative presence heartbeat accepted')) {
            $smokePassed = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    if (-not $smokePassed) {
        Invoke-SmokeCompose logs --no-color backend simulated-agent
        throw 'Simulated agent did not complete normative enrollment, rotation and heartbeat.'
    }
    Write-Output 'Smoke test passed: simulated agent enrolled, rotated and sent a normative heartbeat.'
}
catch {
    $operationFailure = $_
}
finally {
    $env:SIM_ENROLLMENT_TOKEN = $null
    try {
        Remove-SmokeProject
    }
    catch {
        $cleanupFailure = $_
    }
    Restore-SmokeEnvironment
    if ([Environment]::GetEnvironmentVariable('COMPOSE_PROJECT_NAME', 'Process') -ne $OriginalEnvironment['COMPOSE_PROJECT_NAME']) {
        $cleanupFailure = [System.Management.Automation.RuntimeException]::new('COMPOSE_PROJECT_NAME restoration regression failed.')
    }
}

if (($null -ne $operationFailure) -and ($null -ne $cleanupFailure)) {
    throw "Smoke failed and cleanup also failed. Smoke: $($operationFailure.Exception.Message) Cleanup: $($cleanupFailure.Exception.Message)"
}
if ($null -ne $operationFailure) { throw $operationFailure }
if ($null -ne $cleanupFailure) { throw $cleanupFailure }
Write-Output "Smoke cleanup regression passed: COMPOSE_PROJECT_NAME restored and no Docker resources remain for $ProjectName."
