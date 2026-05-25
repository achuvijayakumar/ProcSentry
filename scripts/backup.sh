#!/usr/bin/env bash
set -euo pipefail

DB_PATH="${DB_PATH:-/var/lib/procsentry/procsentry.db}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/procsentry}"
mkdir -p "$BACKUP_DIR"
sqlite3 "$DB_PATH" ".backup '$BACKUP_DIR/procsentry-$(date +%Y%m%d-%H%M%S).db'"
find "$BACKUP_DIR" -type f -name 'procsentry-*.db' -mtime +14 -delete

