#!/usr/bin/env sh
set -eu

action="${1:-}"
integration_project_name="wto-phase04-integration"

backend_tool() {
  docker compose --profile tools run --rm --no-deps --build backend-tools "$@"
}

frontend_tool() {
  docker compose --profile tools run --rm --build frontend-tools "$@"
}

assert_integration_project_removed() {
  leftovers=''
  for resource_type in container network volume; do
    case "$resource_type" in
      container)
        ids="$(docker container ls --all --quiet --filter "label=com.docker.compose.project=${integration_project_name}")" || return $?
        ;;
      network)
        ids="$(docker network ls --quiet --filter "label=com.docker.compose.project=${integration_project_name}")" || return $?
        ;;
      volume)
        ids="$(docker volume ls --quiet --filter "label=com.docker.compose.project=${integration_project_name}")" || return $?
        ;;
    esac
    if [ -n "$ids" ]; then
      leftovers="${leftovers} ${resource_type}:${ids}"
    fi
  done
  if [ -n "$leftovers" ]; then
    echo "Integration cleanup regression: resources remain for project ${integration_project_name}:${leftovers}" >&2
    return 1
  fi
}

cleanup_integration_project() {
  original_status="$1"
  trap - EXIT HUP INT TERM
  set +e
  docker compose --project-name "$integration_project_name" --profile tools \
    down --volumes --remove-orphans
  cleanup_status=$?
  assert_integration_project_removed
  verification_status=$?
  if [ "$original_status" -ne 0 ]; then
    exit "$original_status"
  fi
  if [ "$cleanup_status" -ne 0 ]; then
    exit "$cleanup_status"
  fi
  exit "$verification_status"
}

install_integration_cleanup_traps() {
  trap 'cleanup_integration_project $?' EXIT
  trap 'cleanup_integration_project 129' HUP
  trap 'cleanup_integration_project 130' INT
  trap 'cleanup_integration_project 143' TERM
}

integration_commands() {
  docker compose --project-name "$integration_project_name" --profile tools \
    run --rm --build backend-tools env WTO_RUN_INTEGRATION=1 sh -ec '
      pytest -m integration
      alembic check
    '
}

run_integration_tests() (
  export COMPOSE_PROJECT_NAME="$integration_project_name"
  install_integration_cleanup_traps
  integration_commands
)

run_validation() (
  export COMPOSE_PROJECT_NAME="$integration_project_name"
  install_integration_cleanup_traps
  python scripts/validate_repository.py
  python scripts/build_openapi.py --check
  python scripts/check_contract_compatibility.py --verify-release
  docker compose config --quiet
  python tests/compose/test_compose_policy.py
  "$0" lint
  "$0" format-check
  "$0" typecheck
  "$0" test
  backend_tool python scripts/validate_contracts.py
  backend_tool python scripts/check_openapi_drift.py
  integration_commands
)

case "$action" in
  up)
    docker compose up -d --wait
    ;;
  down)
    docker compose down --remove-orphans
    ;;
  logs)
    docker compose logs --follow --tail 200
    ;;
  build)
    docker compose build
    ;;
  lint)
    backend_tool ruff check src tests migrations
    frontend_tool npm run lint
    ;;
  format-check)
    backend_tool black --check src tests migrations
    frontend_tool npm run format-check
    ;;
  typecheck)
    backend_tool mypy src
    frontend_tool npm run typecheck
    ;;
  test)
    backend_tool pytest --cov=wto_backend --cov-report=term-missing
    frontend_tool npm test
    ;;
  test-integration)
    run_integration_tests
    ;;
  contracts)
    backend_tool python scripts/validate_contracts.py
    docker compose --profile contracts build contracts-typescript contracts-kotlin contracts-swift
    docker compose --profile contracts run --rm contracts-typescript
    docker compose --profile contracts run --rm contracts-kotlin
    docker compose --profile contracts run --rm contracts-swift
    ;;
  smoke)
    sh "$(dirname "$0")/smoke.sh"
    ;;
  migrate)
    docker compose run --rm backend alembic upgrade head
    ;;
  seed)
    docker compose exec backend python -m wto_backend.cli seed-rbac
    ;;
  validate)
    run_validation
    ;;
  reset)
    if [ "${2:-}" != "--confirm" ]; then
      echo "Refusing destructive reset. Re-run with: reset --confirm" >&2
      exit 2
    fi
    echo "Destructive reset confirmed: removing Compose containers and named volumes."
    docker compose down --volumes --remove-orphans
    ;;
  *)
    echo "Usage: $0 {up|down|logs|build|lint|format-check|typecheck|test|test-integration|contracts|smoke|migrate|seed|validate|reset --confirm}" >&2
    exit 2
    ;;
esac
