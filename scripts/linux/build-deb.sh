#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
VERSION=${WTO_AGENT_VERSION:-0.1.0}
OUTPUT=${1:-"$ROOT/packages/linux"}

if ! printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$'; then
    echo "invalid package version" >&2
    exit 2
fi
if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "dpkg-deb is required" >&2
    exit 3
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required" >&2
    exit 3
fi
WHEELHOUSE_SOURCE=${WTO_AGENT_WHEELHOUSE:-/opt/wto-wheelhouse}
if [ ! -d "$WHEELHOUSE_SOURCE" ]; then
    echo "a prebuilt Linux wheelhouse is required at $WHEELHOUSE_SOURCE" >&2
    exit 3
fi
ARCH=$(dpkg --print-architecture)

mkdir -p -- "$OUTPUT"
OUTPUT=$(CDPATH= cd -- "$OUTPUT" && pwd -P)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/wto-agent-deb.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT HUP INT TERM
STAGE="$WORK/root"
mkdir -p -- \
    "$STAGE/DEBIAN" \
    "$STAGE/usr/bin" \
    "$STAGE/usr/lib/wto-agent/runtime/wheelhouse" \
    "$STAGE/usr/share/doc/wto-agent/phase07" \
    "$STAGE/lib/systemd/system" \
    "$STAGE/etc/wto-agent"

AGENT_WHEELS="$WORK/agent-wheels"
mkdir -p -- "$AGENT_WHEELS"
python3 -m pip wheel \
    --no-index \
    --no-deps \
    --no-build-isolation \
    --wheel-dir "$AGENT_WHEELS" \
    "$ROOT/agents/desktop" >/dev/null
set -- "$AGENT_WHEELS"/wto_desktop_agent-*.whl
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "the build must produce exactly one desktop agent wheel" >&2
    exit 4
fi
install -m 0644 "$1" "$STAGE/usr/lib/wto-agent/runtime/wheelhouse/"
find "$WHEELHOUSE_SOURCE" -maxdepth 1 -type f -name '*.whl' -exec \
    install -m 0644 {} "$STAGE/usr/lib/wto-agent/runtime/wheelhouse/" \;
install -m 0644 \
    "$ROOT/agents/desktop/requirements-linux-runtime.lock" \
    "$STAGE/usr/lib/wto-agent/runtime/requirements-linux-runtime.lock"
install -m 0755 "$ROOT/agents/desktop/packaging/linux/bin/wto-agent" "$STAGE/usr/bin/wto-agent"
install -m 0755 \
    "$ROOT/agents/desktop/packaging/linux/bin/wto-agent-package-lifecycle" \
    "$STAGE/usr/lib/wto-agent/package-lifecycle"
install -m 0644 "$ROOT/agents/desktop/packaging/linux/systemd/wto-agent.service" "$STAGE/lib/systemd/system/wto-agent.service"
install -m 0644 "$ROOT/agents/desktop/packaging/linux/systemd/wto-agent-capture.service" "$STAGE/lib/systemd/system/wto-agent-capture.service"
install -m 0640 "$ROOT/agents/desktop/packaging/linux/config/wto-agent.toml" "$STAGE/etc/wto-agent/wto-agent.toml"
install -m 0640 "$ROOT/agents/desktop/packaging/linux/config/capture-node.toml" "$STAGE/etc/wto-agent/capture-node.toml"
cp -a -- "$ROOT/docs/phase07/." "$STAGE/usr/share/doc/wto-agent/phase07/"
find "$STAGE/usr/share/doc/wto-agent/phase07" -type d -exec chmod 0755 {} +
find "$STAGE/usr/share/doc/wto-agent/phase07" -type f -exec chmod 0644 {} +

sed -e "s/@VERSION@/$VERSION/g" -e "s/@ARCH@/$ARCH/g" \
    "$ROOT/agents/desktop/packaging/linux/debian/control.in" > "$STAGE/DEBIAN/control"
for script in postinst prerm postrm; do
    install -m 0755 "$ROOT/agents/desktop/packaging/linux/debian/$script" "$STAGE/DEBIAN/$script"
done
install -m 0644 "$ROOT/agents/desktop/packaging/linux/debian/conffiles" "$STAGE/DEBIAN/conffiles"

(
    cd "$STAGE"
    find usr/lib/wto-agent usr/bin lib/systemd/system -type f -print0 \
        | sort -z \
        | xargs -0 sha256sum
) > "$STAGE/usr/share/doc/wto-agent/SHA256SUMS"

EPOCH=${SOURCE_DATE_EPOCH:-0}
find "$STAGE" -exec touch -h -d "@$EPOCH" {} +
PACKAGE="$OUTPUT/wto-agent_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group --uniform-compression -Zxz "$STAGE" "$PACKAGE" >/dev/null
sha256sum "$PACKAGE" > "$PACKAGE.sha256"
printf '%s\n' "$PACKAGE"
