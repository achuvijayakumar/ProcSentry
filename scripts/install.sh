#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/procsentry}"
CONFIG_PATH="${CONFIG_PATH:-/etc/procsentry.yml}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "install.sh must be run as root" >&2
  exit 1
fi

command -v python3.12 >/dev/null || {
  echo "python3.12 is required" >&2
  exit 1
}

mkdir -p "$APP_DIR" /var/lib/procsentry
chown root:root /var/lib/procsentry
python3.12 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install "$APP_DIR"

if [[ ! -f "$CONFIG_PATH" ]]; then
  install -Dm644 "$APP_DIR/config/production.example.yml" "$CONFIG_PATH"
fi
install -Dm644 "$APP_DIR/systemd/procsentry.service" /etc/systemd/system/procsentry.service
install -Dm644 "$APP_DIR/systemd/procsentry.logrotate" /etc/logrotate.d/procsentry
systemctl daemon-reload
systemctl enable --now procsentry.service

echo "ProcSentry installed. Dashboard: http://$(hostname -I | awk '{print $1}'):8080"
