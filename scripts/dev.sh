#!/usr/bin/env sh
set -eu

action="${1:-}"

backend_tool() {
  docker compose --profile tools run --rm --build backend-tools "$@"
}

frontend_tool() {
  docker compose --profile tools run --rm --build frontend-tools "$@"
}

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
  smoke)
    sh "$(dirname "$0")/smoke.sh"
    ;;
  migrate)
    docker compose run --rm backend alembic upgrade head
    ;;
  validate)
    python scripts/validate_repository.py
    docker compose config --quiet
    python tests/compose/test_compose_policy.py
    "$0" lint
    "$0" format-check
    "$0" typecheck
    "$0" test
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
    echo "Usage: $0 {up|down|logs|build|lint|format-check|typecheck|test|smoke|migrate|validate|reset --confirm}" >&2
    exit 2
    ;;
esac
