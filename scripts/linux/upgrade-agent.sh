#!/bin/sh
set -eu

PACKAGE=${1:-}
EXPECTED_SHA256=${2:-}
BACKUP=${3:-/var/lib/wto-agent/agent.sqlite3.pre-upgrade.bak}
if [ "$(id -u)" -ne 0 ] || [ -z "$PACKAGE" ] || [ -z "$EXPECTED_SHA256" ]; then
    echo "usage (as root): upgrade-agent.sh PACKAGE.deb EXPECTED_SHA256 [BACKUP]" >&2
    exit 2
fi
case "$BACKUP" in
    /var/lib/wto-agent/*.bak|/var/lib/wto-agent-capture/*.bak) ;;
    *) echo "backup must remain in an agent state directory" >&2; exit 3 ;;
esac

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
        not-found) echo "$UNIT is not installed; upgrade aborted" >&2; exit 5 ;;
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

require_unit_active() {
    UNIT=$1
    ACTIVE_STATE=$(unit_active_state "$UNIT")
    if [ "$ACTIVE_STATE" != active ]; then
        echo "$UNIT did not resume after upgrade" >&2
        exit 5
    fi
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
RECOVERY_ARMED=true
recover_original_units() {
    STATUS=$?
    trap - EXIT HUP INT TERM
    if [ "$RECOVERY_ARMED" = true ] && [ "$STATUS" -ne 0 ]; then
        if [ "$ACTIVE_ENDPOINT" = true ] && \
            ! "$SYSTEMCTL" start wto-agent.service; then
            echo "failed to resume wto-agent.service during upgrade recovery" >&2
        fi
        if [ "$ACTIVE_CAPTURE" = true ] && \
            ! "$SYSTEMCTL" start wto-agent-capture.service; then
            echo "failed to resume wto-agent-capture.service during upgrade recovery" >&2
        fi
    fi
    exit "$STATUS"
}
trap recover_original_units EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if [ "$ACTIVE_ENDPOINT" = true ] && ! "$SYSTEMCTL" stop wto-agent.service; then
    echo "failed to stop wto-agent.service; upgrade aborted" >&2
    exit 5
fi
if [ "$ACTIVE_CAPTURE" = true ] && ! "$SYSTEMCTL" stop wto-agent-capture.service; then
    echo "failed to stop wto-agent-capture.service; upgrade aborted" >&2
    exit 5
fi
require_unit_inactive wto-agent.service
require_unit_inactive wto-agent-capture.service
if [ -f /var/lib/wto-agent/agent.sqlite3 ]; then
    /usr/sbin/runuser --user wto-agent -- \
        /usr/bin/wto-agent --config /etc/wto-agent/wto-agent.toml \
        maintenance backup --destination "$BACKUP"
fi
if [ -f /var/lib/wto-agent-capture/agent.sqlite3 ]; then
    /usr/sbin/runuser --user wto-capture -- \
        /usr/bin/wto-agent --config /etc/wto-agent/capture-node.toml \
        maintenance backup \
        --destination /var/lib/wto-agent-capture/agent.sqlite3.pre-upgrade.bak
fi
"$(dirname -- "$0")/install-agent.sh" "$PACKAGE" "$EXPECTED_SHA256"
if [ "$ACTIVE_ENDPOINT" = true ]; then
    "$SYSTEMCTL" start wto-agent.service
    require_unit_active wto-agent.service
fi
if [ "$ACTIVE_CAPTURE" = true ]; then
    "$SYSTEMCTL" start wto-agent-capture.service
    require_unit_active wto-agent-capture.service
fi
RECOVERY_ARMED=false
