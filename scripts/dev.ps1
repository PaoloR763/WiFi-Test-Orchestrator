param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('up', 'down', 'logs', 'build', 'lint', 'format-check', 'typecheck', 'test', 'test-integration', 'contracts', 'smoke', 'migrate', 'seed', 'validate', 'reset')]
    [string]$Action,
    [switch]$ConfirmReset
)

$ErrorActionPreference = 'Stop'
$IntegrationProjectName = 'wto-phase05-integration'

function Invoke-Checked {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Command)
    & $Command[0] $Command[1..($Command.Length - 1)]
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE"
    }
}

function Invoke-BackendTool {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    Invoke-Checked docker compose --profile tools run --rm --no-deps --build backend-tools @Arguments
}

function Invoke-FrontendTool {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    Invoke-Checked docker compose --profile tools run --rm --build frontend-tools @Arguments
}

function Invoke-DesktopTool {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    Invoke-Checked docker compose --profile tools run --rm --no-deps --build desktop-agent-tools @Arguments
}

function Assert-IntegrationProjectRemoved {
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
            "label=com.docker.compose.project=$IntegrationProjectName"
        )
        $ids = @(& docker @arguments)
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to verify integration $resourceType cleanup."
        }
        foreach ($id in $ids) {
            if ($id) { $leftovers += "${resourceType}:$id" }
        }
    }

    if ($leftovers.Count -gt 0) {
        throw "Integration cleanup regression: resources remain for project ${IntegrationProjectName}: $($leftovers -join ', ')"
    }
}

function Remove-IntegrationProject {
    $cleanupFailure = $null
    try {
        Invoke-Checked docker compose --project-name $IntegrationProjectName --profile tools down --volumes --remove-orphans
    }
    catch {
        $cleanupFailure = $_
    }

    try {
        Assert-IntegrationProjectRemoved
    }
    catch {
        if ($null -ne $cleanupFailure) {
            throw "Integration cleanup and verification failed. Cleanup: $($cleanupFailure.Exception.Message) Verification: $($_.Exception.Message)"
        }
        throw
    }

    if ($null -ne $cleanupFailure) {
        throw $cleanupFailure
    }
}

function Invoke-IntegrationCommands {
    $validationCommands = "pytest -m integration`nalembic check"
    Invoke-Checked docker compose --project-name $IntegrationProjectName --profile tools run --rm --build backend-tools env WTO_RUN_INTEGRATION=1 sh -ec $validationCommands
}

function Invoke-WithIntegrationCleanup {
    param([Parameter(Mandatory = $true)][scriptblock]$Operation)

    $operationFailure = $null
    $cleanupFailure = $null
    $hadComposeProjectName = Test-Path Env:COMPOSE_PROJECT_NAME
    $originalComposeProjectName = $env:COMPOSE_PROJECT_NAME
    $env:COMPOSE_PROJECT_NAME = $IntegrationProjectName
    try {
        & $Operation
    }
    catch {
        $operationFailure = $_
    }
    finally {
        try {
            Remove-IntegrationProject
        }
        catch {
            $cleanupFailure = $_
        }
        if ($hadComposeProjectName) {
            $env:COMPOSE_PROJECT_NAME = $originalComposeProjectName
        }
        else {
            Remove-Item Env:COMPOSE_PROJECT_NAME -ErrorAction SilentlyContinue
        }
    }

    if (($null -ne $operationFailure) -and ($null -ne $cleanupFailure)) {
        throw "Validation failed and integration cleanup also failed. Validation: $($operationFailure.Exception.Message) Cleanup: $($cleanupFailure.Exception.Message)"
    }
    if ($null -ne $operationFailure) { throw $operationFailure }
    if ($null -ne $cleanupFailure) { throw $cleanupFailure }
}

switch ($Action) {
    'up' { Invoke-Checked docker compose up -d --wait }
    'down' { Invoke-Checked docker compose down --remove-orphans }
    'logs' { Invoke-Checked docker compose logs --follow --tail 200 }
    'build' { Invoke-Checked docker compose build }
    'lint' {
        Invoke-BackendTool ruff check src tests migrations
        Invoke-DesktopTool ruff check src tests
        Invoke-FrontendTool npm run lint
    }
    'format-check' {
        Invoke-BackendTool black --check src tests migrations
        Invoke-DesktopTool black --check src tests
        Invoke-FrontendTool npm run format-check
    }
    'typecheck' {
        Invoke-BackendTool mypy src
        Invoke-DesktopTool mypy src
        Invoke-FrontendTool npm run typecheck
    }
    'test' {
        Invoke-BackendTool pytest --cov=wto_backend --cov-report=term-missing
        Invoke-DesktopTool pytest tests --cov=wto_desktop_agent --cov-report=term-missing
        Invoke-FrontendTool npm test
    }
    'test-integration' { Invoke-WithIntegrationCleanup { Invoke-IntegrationCommands } }
    'contracts' {
        Invoke-BackendTool python scripts/validate_contracts.py
        Invoke-Checked docker compose --profile contracts build contracts-typescript contracts-kotlin contracts-swift
        Invoke-Checked docker compose --profile contracts run --rm contracts-typescript
        Invoke-Checked docker compose --profile contracts run --rm contracts-kotlin
        Invoke-Checked docker compose --profile contracts run --rm contracts-swift
    }
    'smoke' { & "$PSScriptRoot/smoke.ps1"; if ($LASTEXITCODE -ne 0) { throw 'Smoke test failed' } }
    'migrate' { Invoke-Checked docker compose run --rm backend alembic upgrade head }
    'seed' { Invoke-Checked docker compose exec backend python -m wto_backend.cli seed-rbac }
    'validate' {
        Invoke-WithIntegrationCleanup {
            Invoke-Checked python scripts/validate_repository.py
            Invoke-Checked python scripts/build_openapi.py --check
            Invoke-Checked python scripts/check_contract_compatibility.py --verify-release
            Invoke-Checked python scripts/sync_desktop_contracts.py --check
            Invoke-Checked docker compose config --quiet
            Invoke-Checked python tests/compose/test_compose_policy.py
            & $PSCommandPath lint
            & $PSCommandPath format-check
            & $PSCommandPath typecheck
            & $PSCommandPath test
            Invoke-DesktopTool python /workspace/scripts/test_desktop_wheel.py
            Invoke-BackendTool python scripts/validate_contracts.py
            Invoke-BackendTool python scripts/check_openapi_drift.py
            Invoke-IntegrationCommands
        }
    }
    'reset' {
        if (-not $ConfirmReset) {
            throw 'Refusing destructive reset. Re-run with: reset -ConfirmReset'
        }
        Write-Warning 'Destructive reset confirmed: removing Compose containers and named volumes.'
        Invoke-Checked docker compose down --volumes --remove-orphans
    }
}
