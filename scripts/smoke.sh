#!/usr/bin/env sh
set -eu

export COMPOSE_PROJECT_NAME="wto-smoke-$$"
export WTO_HTTP_PORT="${WTO_SMOKE_PORT:-18080}"
export WTO_ALLOWED_ORIGIN="http://127.0.0.1:${WTO_HTTP_PORT}"
admin_password='Smoke-'$(python -c 'import secrets; print(secrets.token_urlsafe(24))')
cookie_file="${TMPDIR:-/tmp}/wto-smoke-cookies-$$"

cleanup() {
  rm -f "$cookie_file"
  docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker compose up -d --build --wait

base_url="http://127.0.0.1:${WTO_HTTP_PORT}"
docker compose exec -T backend python -m wto_backend.cli seed-rbac
printf '%s\n' "$admin_password" | docker compose exec -T backend \
  python -m wto_backend.cli bootstrap-admin --username smoke-admin --password-stdin
curl --fail --silent --show-error "${base_url}/health/live" | grep -q '"status":"alive"'
curl --fail --silent --show-error "${base_url}/health/ready" | grep -q '"status":"ready"'
curl --fail --silent --show-error "${base_url}/" | grep -q 'WiFi Test Orchestrator'
openapi="$(curl --fail --silent --show-error "${base_url}/openapi.json")"
printf '%s' "$openapi" | grep -q '"/health/live"'
if printf '%s' "$openapi" | grep -q '"/demo/'; then
  echo "Demo endpoints must not appear in OpenAPI." >&2
  exit 1
fi

login_response="$(curl --fail --silent --show-error -c "$cookie_file" \
  -H 'Content-Type: application/json' \
  --data "{\"username\":\"smoke-admin\",\"password\":\"${admin_password}\"}" \
  "${base_url}/api/internal/v1/auth/login")"
access_token="$(printf '%s' "$login_response" | python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
curl --fail --silent --show-error -H "Authorization: Bearer ${access_token}" \
  "${base_url}/api/internal/v1/admin/protected" | grep -q '"status":"authorized"'
curl --fail --silent --show-error -b "$cookie_file" -c "$cookie_file" \
  -H "Origin: ${base_url}" -X POST "${base_url}/api/internal/v1/auth/refresh" \
  | grep -q '"token_type":"bearer"'
unset access_token login_response admin_password

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
