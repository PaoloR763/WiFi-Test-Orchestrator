#!/bin/sh
set -eu

BASE_DIR=${1:-/deb-one}
UPGRADE_DIR=${2:-/deb-upgrade}
GLOBAL_PYDANTIC=$(python3 -c 'import pydantic; print(pydantic.__version__)')
if [ "${GLOBAL_PYDANTIC%%.*}" != 1 ]; then
    echo "Ubuntu runtime fixture did not start with Pydantic 1" >&2
    exit 2
fi

set -- "$BASE_DIR"/wto-agent_0.1.0_*.deb
test "$#" -eq 1
BASE_PACKAGE=$1
BASE_SHA=$(sha256sum "$BASE_PACKAGE" | awk '{print $1}')
sh scripts/linux/install-agent.sh "$BASE_PACKAGE" "$BASE_SHA" </dev/null
/usr/lib/wto-agent/venv/bin/python -c \
    'import pydantic; assert int(pydantic.__version__.split(".", 1)[0]) == 2'
/usr/lib/wto-agent/venv/bin/python -m pip check
/usr/bin/wto-agent --help >/dev/null
test "$(stat -c %a /var/lib/wto-agent)" = 700
test "$(stat -c %a /var/lib/wto-agent-capture)" = 700
if [ "$(python3 -c 'import pydantic; print(pydantic.__version__)')" != "$GLOBAL_PYDANTIC" ]; then
    echo "DEB modified the distribution Pydantic runtime" >&2
    exit 3
fi

mv -- /usr/bin/systemctl /usr/bin/systemctl.real
install -d -m 0700 /run/wto-runtime-systemctl /run/systemd/system
cat > /usr/bin/systemctl <<'EOF'
#!/bin/sh
set -eu

STATE_ROOT=/run/wto-runtime-systemctl

select_unit() {
    UNIT=$1
    case "$UNIT" in
        wto-agent.service)
            PID_FILE=$STATE_ROOT/endpoint.pid
            RUNTIME_DIRECTORY=/run/wto-agent
            ;;
        wto-agent-capture.service)
            PID_FILE=$STATE_ROOT/capture.pid
            RUNTIME_DIRECTORY=/run/wto-agent-capture
            ;;
        *) exit 4 ;;
    esac
}

unit_is_active() {
    if [ ! -f "$PID_FILE" ]; then return 1; fi
    PID=$(cat "$PID_FILE")
    case "$PID" in *[!0-9]*|'') return 1 ;; esac
    if [ ! -r "/proc/$PID/stat" ]; then return 1; fi
    PROCESS_STATE=$(awk '{print $3}' "/proc/$PID/stat")
    [ "$PROCESS_STATE" != Z ] && kill -0 "$PID" 2>/dev/null
}

COMMAND=${1:-}
case "$COMMAND" in
    daemon-reload)
        exit 0
        ;;
    show)
        select_unit "$2"
        case "$3" in
            --property=LoadState)
                if [ -f "/lib/systemd/system/$2" ]; then printf 'loaded\n'; else printf 'not-found\n'; fi
                ;;
            --property=ActiveState)
                if unit_is_active; then printf 'active\n'; else printf 'inactive\n'; fi
                ;;
            --property=MainPID)
                if unit_is_active; then cat "$PID_FILE"; else printf '0\n'; fi
                ;;
            *) exit 4 ;;
        esac
        ;;
    start)
        select_unit "$2"
        if ! unit_is_active; then
            install -d -m 0700 "$RUNTIME_DIRECTORY"
            nohup /bin/sleep infinity >/dev/null 2>&1 &
            printf '%s\n' "$!" > "$PID_FILE"
        fi
        ;;
    stop)
        select_unit "$2"
        if unit_is_active; then
            PID=$(cat "$PID_FILE")
            kill "$PID"
            ATTEMPTS=0
            while unit_is_active && [ "$ATTEMPTS" -lt 100 ]; do
                /bin/sleep 0.01
                ATTEMPTS=$((ATTEMPTS + 1))
            done
            if unit_is_active; then
                kill -9 "$PID"
            fi
        fi
        rm -f -- "$PID_FILE"
        rm -rf -- "$RUNTIME_DIRECTORY"
        ;;
    is-active)
        if [ "${2:-}" = --quiet ]; then select_unit "$3"; else select_unit "$2"; fi
        unit_is_active
        ;;
    *) exit 4 ;;
esac
EOF
chmod 0755 /usr/bin/systemctl
cleanup_runtime_systemctl() {
    /usr/bin/systemctl stop wto-agent.service >/dev/null 2>&1 || true
    /usr/bin/systemctl stop wto-agent-capture.service >/dev/null 2>&1 || true
    rm -f -- /usr/bin/systemctl
    mv -- /usr/bin/systemctl.real /usr/bin/systemctl
}
trap cleanup_runtime_systemctl EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p /etc/systemd/system/wto-agent.service.d
cat > /etc/systemd/system/wto-agent.service.d/runtime-test.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/bin/sleep infinity
Restart=no
EOF
systemctl daemon-reload
systemctl start wto-agent.service
test "$(systemctl show wto-agent.service --property=ActiveState --value)" = active
INITIAL_PID=$(systemctl show wto-agent.service --property=MainPID --value)
test "$INITIAL_PID" -gt 1

chmod 0755 /var/lib/wto-agent /var/lib/wto-agent-capture
printf '%s\n' legacy-state > /var/lib/wto-agent/upgrade-sentinel
chown wto-agent:wto-agent /var/lib/wto-agent/upgrade-sentinel
chmod 0600 /var/lib/wto-agent/upgrade-sentinel
sed -i 's#https://orchestrator.example#https://local-config.example#' \
    /etc/wto-agent/wto-agent.toml
rm -- /etc/wto-agent/capture-node.toml
set -- "$UPGRADE_DIR"/wto-agent_0.1.1_*.deb
test "$#" -eq 1
READ_ONLY_UPGRADE_PACKAGE=$1
REPACK_ROOT=$(mktemp -d /tmp/wto-upgrade-root.XXXXXX)
UPGRADE_PACKAGE=/tmp/wto-agent-upgrade-with-new-defaults.deb
dpkg-deb --raw-extract "$READ_ONLY_UPGRADE_PACKAGE" "$REPACK_ROOT"
sed -i 's#https://orchestrator.example#https://new-default.example#' \
    "$REPACK_ROOT/etc/wto-agent/wto-agent.toml" \
    "$REPACK_ROOT/etc/wto-agent/capture-node.toml"
test "$(grep -Fxc /etc/wto-agent/wto-agent.toml "$REPACK_ROOT/DEBIAN/conffiles")" -eq 1
test "$(grep -Fxc /etc/wto-agent/capture-node.toml "$REPACK_ROOT/DEBIAN/conffiles")" -eq 1
test "$(wc -l < "$REPACK_ROOT/DEBIAN/conffiles")" -eq 2
dpkg-deb --build --root-owner-group "$REPACK_ROOT" "$UPGRADE_PACKAGE" >/dev/null
UPGRADE_SHA=$(sha256sum "$UPGRADE_PACKAGE" | awk '{print $1}')
timeout 120 sh scripts/linux/install-agent.sh "$UPGRADE_PACKAGE" "$UPGRADE_SHA" </dev/null
test "$(stat -c %a /var/lib/wto-agent)" = 700
test "$(stat -c %a /var/lib/wto-agent-capture)" = 700
test "$(stat -c %u /var/lib/wto-agent)" = "$(id -u wto-agent)"
test "$(stat -c %g /var/lib/wto-agent)" = "$(id -g wto-agent)"
test "$(stat -c %u /var/lib/wto-agent-capture)" = "$(id -u wto-capture)"
test "$(stat -c %g /var/lib/wto-agent-capture)" = "$(id -g wto-capture)"
test "$(cat /var/lib/wto-agent/upgrade-sentinel)" = legacy-state
grep -F 'server_url = "https://local-config.example"' /etc/wto-agent/wto-agent.toml
test ! -e /etc/wto-agent/capture-node.toml
test "$(systemctl show wto-agent.service --property=ActiveState --value)" = active
UPGRADED_PID=$(systemctl show wto-agent.service --property=MainPID --value)
test "$UPGRADED_PID" -gt 1
test "$UPGRADED_PID" != "$INITIAL_PID"
test ! -r "/proc/$INITIAL_PID/stat"
test ! -e /run/wto-agent-package-maintainer/upgrade-state
sh scripts/linux/install-agent.sh "$BASE_PACKAGE" "$BASE_SHA" </dev/null
dpkg --remove wto-agent
! systemctl is-active --quiet wto-agent.service
test ! -r "/proc/$UPGRADED_PID/stat"
