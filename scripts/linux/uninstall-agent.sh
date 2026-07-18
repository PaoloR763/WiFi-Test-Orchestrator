#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall requires root" >&2
    exit 2
fi
case "${1:-}" in
    "") dpkg --remove wto-agent ;;
    --purge-data) dpkg --purge wto-agent ;;
    *) echo "usage: uninstall-agent.sh [--purge-data]" >&2; exit 3 ;;
esac
