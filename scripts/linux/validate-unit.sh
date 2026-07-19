#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
python3 "$ROOT/scripts/linux/validate_packaging.py"

if command -v systemd-analyze >/dev/null 2>&1 \
    && getent passwd wto-agent >/dev/null \
    && getent passwd wto-capture >/dev/null \
    && [ -x /usr/bin/wto-agent ]; then
    systemd-analyze verify \
        "$ROOT/agents/desktop/packaging/linux/systemd/wto-agent.service" \
        "$ROOT/agents/desktop/packaging/linux/systemd/wto-agent-capture.service"
else
    echo "systemd-analyze runtime verification: NOT RUN (package accounts/binary unavailable)"
fi
