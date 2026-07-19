#!/bin/sh
set -eu

PACKAGE=${1:-}
EXPECTED_SHA256=${2:-}
if [ -z "$PACKAGE" ] || [ "$(id -u)" -ne 0 ]; then
    echo "usage (as root): install-agent.sh PACKAGE.deb EXPECTED_SHA256" >&2
    exit 2
fi
if [ -z "$EXPECTED_SHA256" ] || \
    ! printf '%s' "$EXPECTED_SHA256" | /usr/bin/grep -Eq '^[0-9a-f]{64}$'; then
    echo "a lowercase SHA-256 approval is required" >&2
    exit 4
fi
umask 077
STAGE_DIR=$(/usr/bin/mktemp -d /run/wto-agent-package-installer.XXXXXX)
STAGED_PACKAGE=$STAGE_DIR/package.deb
cleanup_staging() {
    if [ -z "${STAGE_DIR:-}" ] || [ -L "$STAGE_DIR" ] || [ ! -d "$STAGE_DIR" ]; then
        return
    fi
    if [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$STAGE_DIR")" != "0:0:700" ]; then
        echo "package staging directory became unsafe; refusing cleanup" >&2
        return
    fi
    /bin/rm -f -- "$STAGED_PACKAGE"
    /usr/bin/rmdir -- "$STAGE_DIR" 2>/dev/null || true
}
trap cleanup_staging EXIT
trap 'exit 5' HUP INT TERM
if [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$STAGE_DIR")" != "0:0:700" ]; then
    echo "package staging directory is unsafe" >&2
    exit 3
fi
/usr/bin/python3 -I -c '
import os
import stat
import sys

source, destination = sys.argv[1:]
flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
before = os.lstat(source)
source_fd = os.open(source, flags)
try:
    opened = os.fstat(source_fd)
    if not os.path.samestat(before, opened):
        raise RuntimeError("package source identity changed before open")
    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
        raise RuntimeError("package source must be a singly-linked regular file")
    destination_fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        while True:
            block = os.read(source_fd, 1024 * 1024)
            if not block:
                break
            view = memoryview(block)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        os.fsync(destination_fd)
        staged = os.fstat(destination_fd)
        expected_mode = stat.S_IFREG | 0o600
        if (
            stat.S_IFMT(staged.st_mode) != stat.S_IFREG
            or stat.S_IMODE(staged.st_mode) != stat.S_IMODE(expected_mode)
            or staged.st_uid != os.geteuid()
            or staged.st_gid != os.getegid()
            or staged.st_nlink != 1
        ):
            raise RuntimeError("staged package metadata is unsafe")
    finally:
        os.close(destination_fd)
    after = os.lstat(source)
    if not os.path.samestat(opened, after):
        raise RuntimeError("package source identity changed during staging")
finally:
    os.close(source_fd)
directory_fd = os.open(os.path.dirname(destination), os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
' "$PACKAGE" "$STAGED_PACKAGE"
if [ -L "$STAGED_PACKAGE" ] || [ ! -f "$STAGED_PACKAGE" ] || \
    [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$STAGED_PACKAGE")" != "0:0:600:1" ]; then
    echo "staged package is unsafe" >&2
    exit 3
fi
ACTUAL=$(/usr/bin/sha256sum "$STAGED_PACKAGE" | /usr/bin/awk '{print $1}')
if [ "$ACTUAL" != "$EXPECTED_SHA256" ]; then
    echo "package integrity check failed" >&2
    exit 5
fi
/usr/bin/dpkg-deb --info "$STAGED_PACKAGE" >/dev/null
DEBIAN_FRONTEND=noninteractive \
    /usr/bin/dpkg --force-confdef --force-confold --install -- "$STAGED_PACKAGE" </dev/null
echo "installed but not started; edit configuration and enroll before starting the unit"
