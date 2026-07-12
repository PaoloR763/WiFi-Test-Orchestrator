#!/usr/bin/env sh
set -eu

project_name="wto-smoke-$$"
had_compose_project_name="${COMPOSE_PROJECT_NAME+x}"
original_compose_project_name="${COMPOSE_PROJECT_NAME-}"
had_http_port="${WTO_HTTP_PORT+x}"
original_http_port="${WTO_HTTP_PORT-}"
had_allowed_origin="${WTO_ALLOWED_ORIGIN+x}"
original_allowed_origin="${WTO_ALLOWED_ORIGIN-}"
had_enrollment_token="${SIM_ENROLLMENT_TOKEN+x}"
original_enrollment_token="${SIM_ENROLLMENT_TOKEN-}"

export WTO_HTTP_PORT="${WTO_SMOKE_PORT:-18080}"
export WTO_ALLOWED_ORIGIN="http://127.0.0.1:${WTO_HTTP_PORT}"
admin_password='Smoke-'$(python -c 'import secrets; print(secrets.token_urlsafe(24))')
cookie_file="${TMPDIR:-/tmp}/wto-smoke-cookies-$$"

compose() {
  docker compose --project-name "$project_name" "$@"
}

assert_smoke_project_removed() {
  leftovers=''
  for resource_type in container network volume; do
    case "$resource_type" in
      container)
        ids="$(docker container ls --all --quiet --filter "label=com.docker.compose.project=${project_name}")" || return $?
        ;;
      network)
        ids="$(docker network ls --quiet --filter "label=com.docker.compose.project=${project_name}")" || return $?
        ;;
      volume)
        ids="$(docker volume ls --quiet --filter "label=com.docker.compose.project=${project_name}")" || return $?
        ;;
    esac
    if [ -n "$ids" ]; then
      leftovers="${leftovers} ${resource_type}:${ids}"
    fi
  done
  if [ -n "$leftovers" ]; then
    echo "Smoke cleanup regression: resources remain for project ${project_name}:${leftovers}" >&2
    return 1
  fi
}

restore_environment() {
  if [ "$had_compose_project_name" = x ]; then
    export COMPOSE_PROJECT_NAME="$original_compose_project_name"
  else
    unset COMPOSE_PROJECT_NAME
  fi
  if [ "$had_http_port" = x ]; then
    export WTO_HTTP_PORT="$original_http_port"
  else
    unset WTO_HTTP_PORT
  fi
  if [ "$had_allowed_origin" = x ]; then
    export WTO_ALLOWED_ORIGIN="$original_allowed_origin"
  else
    unset WTO_ALLOWED_ORIGIN
  fi
  if [ "$had_enrollment_token" = x ]; then
    export SIM_ENROLLMENT_TOKEN="$original_enrollment_token"
  else
    unset SIM_ENROLLMENT_TOKEN
  fi
}

cleanup() {
  original_status="$1"
  trap - EXIT HUP INT TERM
  set +e
  rm -f "$cookie_file"
  compose down --volumes --remove-orphans >/dev/null 2>&1
  cleanup_status=$?
  assert_smoke_project_removed
  verification_status=$?
  restore_environment
  if [ "${COMPOSE_PROJECT_NAME+x}" != "$had_compose_project_name" ] \
    || { [ "$had_compose_project_name" = x ] && [ "$COMPOSE_PROJECT_NAME" != "$original_compose_project_name" ]; }; then
    echo "COMPOSE_PROJECT_NAME restoration regression failed." >&2
    restoration_status=1
  else
    restoration_status=0
  fi
  if [ "$original_status" -eq 0 ] && [ "$cleanup_status" -eq 0 ] \
    && [ "$verification_status" -eq 0 ] && [ "$restoration_status" -eq 0 ]; then
    echo "Smoke cleanup regression passed: COMPOSE_PROJECT_NAME restored and no Docker resources remain for ${project_name}."
    exit 0
  fi
  if [ "$original_status" -ne 0 ]; then exit "$original_status"; fi
  if [ "$cleanup_status" -ne 0 ]; then exit "$cleanup_status"; fi
  if [ "$verification_status" -ne 0 ]; then exit "$verification_status"; fi
  exit "$restoration_status"
}

trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

compose up -d --build --wait

base_url="http://127.0.0.1:${WTO_HTTP_PORT}"
compose exec -T backend python -m wto_backend.cli seed-rbac
printf '%s\n' "$admin_password" | compose exec -T backend \
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
enrollment_response="$(curl --fail --silent --show-error \
  -H "Authorization: Bearer ${access_token}" -H 'Content-Type: application/json' \
  --data '{"scope":"agent.enroll","expires_in_minutes":15,"allowed_platforms":["simulated"],"bound_agent_id":null}' \
  "${base_url}/api/v1/enrollment-tokens")"
export SIM_ENROLLMENT_TOKEN
SIM_ENROLLMENT_TOKEN="$(printf '%s' "$enrollment_response" | python -c 'import json,sys; print(json.load(sys.stdin)["enrollment_token"])')"
compose up -d --no-deps --force-recreate --wait simulated-agent
curl --fail --silent --show-error -b "$cookie_file" -c "$cookie_file" \
  -H "Origin: ${base_url}" -X POST "${base_url}/api/internal/v1/auth/refresh" \
  | grep -q '"token_type":"bearer"'
unset access_token login_response enrollment_response admin_password

smoke_passed=0
attempt=0
while [ "$attempt" -lt 12 ]; do
  agent_logs="$(compose logs --no-color simulated-agent)"
  if printf '%s' "$agent_logs" | grep -Fq "$SIM_ENROLLMENT_TOKEN"; then
    echo "Simulated-agent logs exposed the enrollment token." >&2
    exit 1
  fi
  if printf '%s' "$agent_logs" | grep -q 'Normative enrollment and credential rotation completed' \
    && printf '%s' "$agent_logs" | grep -q 'Normative presence heartbeat accepted'; then
    smoke_passed=1
    break
  fi
  attempt=$((attempt + 1))
  sleep 2
done

if [ "$smoke_passed" -ne 1 ]; then
  echo "Simulated agent did not complete normative enrollment, rotation and heartbeat." >&2
  compose logs --no-color backend simulated-agent >&2
  exit 1
fi
echo "Smoke test passed: simulated agent enrolled, rotated and sent a normative heartbeat."
