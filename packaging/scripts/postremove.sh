#!/bin/sh
# Runs after package files are removed. Reload systemd unconditionally; on a
# full purge, drop the service account and group too. The "$1" argument
# carries the deb action ("purge"/"remove"/"upgrade") or the rpm action
# integer (0 = uninstall).
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

case "$1" in
    purge|0)
        if getent passwd tg-proxy >/dev/null; then
            userdel tg-proxy >/dev/null 2>&1 || true
        fi
        if getent group tg-proxy >/dev/null; then
            groupdel tg-proxy >/dev/null 2>&1 || true
        fi
        ;;
esac

exit 0
