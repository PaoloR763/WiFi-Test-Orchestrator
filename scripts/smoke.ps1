$ErrorActionPreference = 'Stop'
$env:COMPOSE_PROJECT_NAME = "wto-smoke-$PID"
if (-not $env:WTO_SMOKE_PORT) { $env:WTO_HTTP_PORT = '18080' } else { $env:WTO_HTTP_PORT = $env:WTO_SMOKE_PORT }

try {
    docker compose up -d --build --wait
    if ($LASTEXITCODE -ne 0) { throw 'Compose startup failed' }
    $baseUrl = "http://127.0.0.1:$($env:WTO_HTTP_PORT)"
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
