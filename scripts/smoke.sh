#!/usr/bin/env sh
set -eu

export COMPOSE_PROJECT_NAME="wto-smoke-$$"
export WTO_HTTP_PORT="${WTO_SMOKE_PORT:-18080}"

cleanup() {
  docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker compose up -d --build --wait

base_url="http://127.0.0.1:${WTO_HTTP_PORT}"
curl --fail --silent --show-error "${base_url}/health/live" | grep -q '"status":"alive"'
curl --fail --silent --show-error "${base_url}/health/ready" | grep -q '"status":"ready"'
curl --fail --silent --show-error "${base_url}/" | grep -q 'WiFi Test Orchestrator'
openapi="$(curl --fail --silent --show-error "${base_url}/openapi.json")"
printf '%s' "$openapi" | grep -q '"/health/live"'
if printf '%s' "$openapi" | grep -q '"/demo/'; then
  echo "Demo endpoints must not appear in OpenAPI." >&2
  exit 1
fi

attempt=0
while [ "$attempt" -lt 12 ]; do
  if curl --fail --silent --show-error "${base_url}/demo/agents" | grep -q 'simulated-agent-01'; then
    echo "Smoke test passed: simulated agent is visible through the reverse proxy."
    exit 0
  fi
  attempt=$((attempt + 1))
  sleep 2
done

echo "Simulated agent did not appear in the demo inventory." >&2
docker compose logs --no-color backend simulated-agent >&2
exit 1
