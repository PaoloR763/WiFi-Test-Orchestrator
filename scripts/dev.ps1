param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('up', 'down', 'logs', 'build', 'lint', 'format-check', 'typecheck', 'test', 'smoke', 'migrate', 'validate', 'reset')]
    [string]$Action,
    [switch]$ConfirmReset
)

$ErrorActionPreference = 'Stop'

function Invoke-Checked {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Command)
    & $Command[0] $Command[1..($Command.Length - 1)]
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE"
    }
}

function Invoke-BackendTool {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    Invoke-Checked docker compose --profile tools run --rm --build backend-tools @Arguments
}

function Invoke-FrontendTool {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    Invoke-Checked docker compose --profile tools run --rm --build frontend-tools @Arguments
}

switch ($Action) {
    'up' { Invoke-Checked docker compose up -d --wait }
    'down' { Invoke-Checked docker compose down --remove-orphans }
    'logs' { Invoke-Checked docker compose logs --follow --tail 200 }
    'build' { Invoke-Checked docker compose build }
    'lint' {
        Invoke-BackendTool ruff check src tests migrations
        Invoke-FrontendTool npm run lint
    }
    'format-check' {
        Invoke-BackendTool black --check src tests migrations
        Invoke-FrontendTool npm run format-check
    }
    'typecheck' {
        Invoke-BackendTool mypy src
        Invoke-FrontendTool npm run typecheck
    }
    'test' {
        Invoke-BackendTool pytest --cov=wto_backend --cov-report=term-missing
        Invoke-FrontendTool npm test
    }
    'smoke' { & "$PSScriptRoot/smoke.ps1"; if ($LASTEXITCODE -ne 0) { throw 'Smoke test failed' } }
    'migrate' { Invoke-Checked docker compose run --rm backend alembic upgrade head }
    'validate' {
        Invoke-Checked python scripts/validate_repository.py
        Invoke-Checked docker compose config --quiet
        Invoke-Checked python tests/compose/test_compose_policy.py
        & $PSCommandPath lint
        & $PSCommandPath format-check
        & $PSCommandPath typecheck
        & $PSCommandPath test
    }
    'reset' {
        if (-not $ConfirmReset) {
            throw 'Refusing destructive reset. Re-run with: reset -ConfirmReset'
        }
        Write-Warning 'Destructive reset confirmed: removing Compose containers and named volumes.'
        Invoke-Checked docker compose down --volumes --remove-orphans
    }
}
