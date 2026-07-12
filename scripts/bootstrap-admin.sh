#!/usr/bin/env sh
set -eu
username="${1:?usage: bootstrap-admin.sh USERNAME}"
printf 'Initial administrator credential: ' >&2
stty -echo
IFS= read -r password
stty echo
printf '\n' >&2
printf '%s\n' "$password" | docker compose exec -T backend \
  python -m wto_backend.cli bootstrap-admin --username "$username" --password-stdin
unset password
