#!/bin/sh
# Runs after the package is unpacked. Creates the tg-proxy system user/group,
# seeds /etc/tg-proxy/config.yaml from the example on first install, and
# reloads systemd so the unit file becomes visible to systemctl.
set -e

USER=tg-proxy
GROUP=tg-proxy
CONF_DIR=/etc/tg-proxy
CONF=$CONF_DIR/config.yaml
EXAMPLE=$CONF_DIR/config.example.yaml

if ! getent group "$GROUP" >/dev/null; then
    groupadd --system "$GROUP"
fi

if ! getent passwd "$USER" >/dev/null; then
    useradd --system \
            --gid "$GROUP" \
            --no-create-home \
            --home-dir /nonexistent \
            --shell /usr/sbin/nologin \
            --comment "tg-proxy service account" \
            "$USER"
fi

if [ ! -e "$CONF" ] && [ -e "$EXAMPLE" ]; then
    cp "$EXAMPLE" "$CONF"
fi

if [ -d "$CONF_DIR" ]; then
    chown -R root:"$GROUP" "$CONF_DIR"
    chmod 750 "$CONF_DIR"
    [ -e "$CONF" ] && chmod 640 "$CONF"
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

cat <<EOF

tg-proxy installed.

  Edit:   $CONF
  Start:  systemctl enable --now tg-proxy
  Logs:   journalctl -u tg-proxy -f

EOF

exit 0
