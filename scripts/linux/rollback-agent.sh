#!/bin/sh
set -eu

PACKAGE=${1:-}
EXPECTED_SHA256=${2:-}
BACKUP=${3:-}
CONFIRM=${4:-}
if [ "$(id -u)" -ne 0 ] || [ "$CONFIRM" != "--confirm-rollback" ]; then
    echo "rollback requires root and --confirm-rollback" >&2
    exit 2
fi
case "$BACKUP" in
    /var/lib/wto-agent/*.bak)
        CONFIG=/etc/wto-agent/wto-agent.toml
        SERVICE_USER=wto-agent
        ;;
    /var/lib/wto-agent-capture/*.bak)
        CONFIG=/etc/wto-agent/capture-node.toml
        SERVICE_USER=wto-capture
        ;;
    *) echo "backup must remain in an agent state directory" >&2; exit 3 ;;
esac
if [ -L "$BACKUP" ] || [ ! -f "$BACKUP" ]; then
    echo "verified SQLite backup is missing or unsafe" >&2
    exit 4
fi
if [ -x /usr/bin/systemctl ]; then
    SYSTEMCTL=/usr/bin/systemctl
elif [ -x /bin/systemctl ]; then
    SYSTEMCTL=/bin/systemctl
else
    echo "systemctl is required to prove agent services are inactive" >&2
    exit 5
fi

unit_active_state() {
    UNIT=$1
    if ! LOAD_STATE=$("$SYSTEMCTL" show "$UNIT" --property=LoadState --value); then
        echo "unable to determine whether $UNIT is installed" >&2
        exit 5
    fi
    case "$LOAD_STATE" in
        loaded|masked|generated|transient|stub|merged) ;;
        not-found) echo "$UNIT is not installed; rollback aborted" >&2; exit 5 ;;
        *) echo "unsafe LoadState '$LOAD_STATE' for $UNIT" >&2; exit 5 ;;
    esac
    if ! ACTIVE_STATE=$("$SYSTEMCTL" show "$UNIT" --property=ActiveState --value); then
        echo "unable to determine whether $UNIT is active" >&2
        exit 5
    fi
    case "$ACTIVE_STATE" in
        active|inactive|failed) printf '%s\n' "$ACTIVE_STATE" ;;
        *) echo "unsafe ActiveState '$ACTIVE_STATE' for $UNIT" >&2; exit 5 ;;
    esac
}

require_unit_inactive() {
    UNIT=$1
    ACTIVE_STATE=$(unit_active_state "$UNIT")
    case "$ACTIVE_STATE" in
        inactive|failed) ;;
        *) echo "$UNIT remained $ACTIVE_STATE after stop" >&2; exit 5 ;;
    esac
}

ACTIVE_ENDPOINT=false
ACTIVE_CAPTURE=false
ACTIVE_ENDPOINT_STATE=$(unit_active_state wto-agent.service)
ACTIVE_CAPTURE_STATE=$(unit_active_state wto-agent-capture.service)
if [ "$ACTIVE_ENDPOINT_STATE" = active ]; then
    ACTIVE_ENDPOINT=true
fi
if [ "$ACTIVE_CAPTURE_STATE" = active ]; then
    ACTIVE_CAPTURE=true
fi
if [ "$ACTIVE_ENDPOINT" = true ] && ! "$SYSTEMCTL" stop wto-agent.service; then
    echo "failed to stop wto-agent.service; rollback aborted" >&2
    exit 5
fi
if [ "$ACTIVE_CAPTURE" = true ] && ! "$SYSTEMCTL" stop wto-agent-capture.service; then
    echo "failed to stop wto-agent-capture.service; rollback aborted" >&2
    exit 5
fi
require_unit_inactive wto-agent.service
require_unit_inactive wto-agent-capture.service
"$(dirname -- "$0")/install-agent.sh" "$PACKAGE" "$EXPECTED_SHA256"
/usr/sbin/runuser --user "$SERVICE_USER" -- \
    /usr/bin/wto-agent --config "$CONFIG" maintenance restore \
    --source "$BACKUP" --confirm
echo "rollback restored; inspect doctor output before starting either unit"
