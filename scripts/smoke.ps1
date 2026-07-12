$ErrorActionPreference = 'Stop'
$env:COMPOSE_PROJECT_NAME = "wto-smoke-$PID"
if (-not $env:WTO_SMOKE_PORT) { $env:WTO_HTTP_PORT = '18080' } else { $env:WTO_HTTP_PORT = $env:WTO_SMOKE_PORT }
$baseUrl = "http://127.0.0.1:$($env:WTO_HTTP_PORT)"
$env:WTO_ALLOWED_ORIGIN = $baseUrl
$randomBytes = New-Object byte[] 24
$randomGenerator = [Security.Cryptography.RandomNumberGenerator]::Create()
$randomGenerator.GetBytes($randomBytes)
$randomGenerator.Dispose()
$adminPassword = 'Smoke-' + [Convert]::ToBase64String($randomBytes)

try {
    docker compose up -d --build --wait
    if ($LASTEXITCODE -ne 0) { throw 'Compose startup failed' }
    docker compose exec -T backend python -m wto_backend.cli seed-rbac
    if ($LASTEXITCODE -ne 0) { throw 'RBAC seed failed' }
    $adminPassword | docker compose exec -T backend python -m wto_backend.cli bootstrap-admin --username smoke-admin --password-stdin
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
    $refresh = Invoke-RestMethod "$baseUrl/api/internal/v1/auth/refresh" -Method Post -WebSession $webSession -Headers @{ Origin = $baseUrl }
    if ($refresh.token_type -ne 'bearer') { throw 'Refresh rotation failed' }
    $adminPassword = $null

    for ($attempt = 0; $attempt -lt 12; $attempt++) {
        $inventory = Invoke-RestMethod "$baseUrl/demo/agents"
        if ($inventory.agents.agent_id -contains 'simulated-agent-01') {
            Write-Output 'Smoke test passed: simulated agent is visible through the reverse proxy.'
            exit 0
        }
        Start-Sleep -Seconds 2
    }
    docker compose logs --no-color backend simulated-agent
    throw 'Simulated agent did not appear in the demo inventory.'
}
finally {
    docker compose down --volumes --remove-orphans | Out-Null
}
