#!/bin/sh
# Runs before package files are removed. On a clean uninstall ("remove" on
# Debian) stop and disable the unit; on upgrades we leave it alone so the
# service keeps running across version changes.
set -e

case "$1" in
    remove|purge|0)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop tg-proxy.service    >/dev/null 2>&1 || true
            systemctl disable tg-proxy.service >/dev/null 2>&1 || true
        fi
        ;;
esac

exit 0
