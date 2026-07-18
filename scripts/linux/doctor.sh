#!/bin/sh
set -eu

ROLE=${1:-endpoint}
case "$ROLE" in
    endpoint)
        SERVICE_USER=wto-agent
        CONFIG=/etc/wto-agent/wto-agent.toml
        UNIT=wto-agent.service
        ;;
    capture)
        SERVICE_USER=wto-capture
        CONFIG=/etc/wto-agent/capture-node.toml
        UNIT=wto-agent-capture.service
        ;;
    *)
        echo "role must be endpoint or capture" >&2
        exit 2
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "doctor wrapper requires root for system checks and identity switching" >&2
    exit 2
fi
if [ -L "$CONFIG" ] || [ ! -f "$CONFIG" ]; then
    echo "configuration is missing or a symlink" >&2
    exit 2
fi
if ! command -v runuser >/dev/null 2>&1; then
    echo "runuser is required" >&2
    exit 3
fi

systemctl show "$UNIT" \
    --property=Id,LoadState,ActiveState,SubState,User,Group,CapabilityBoundingSet \
    --no-pager || true

if runuser --user "$SERVICE_USER" -- /usr/bin/wto-agent --config "$CONFIG" doctor --json; then
    exit 0
else
    STATUS=$?
    exit "$STATUS"
fi
