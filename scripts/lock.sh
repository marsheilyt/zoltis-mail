#!/usr/bin/env bash
# Stop Zoltis Mail and lock its encrypted storage (e.g. before maintenance or a planned shutdown).
#   sudo ./scripts/lock.sh        start again with: sudo ./scripts/unlock.sh
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $EUID -eq 0 ]] || { echo "error: run as root (sudo)" >&2; exit 1; }
set -a; [[ -f .env ]] && . ./.env; set +a
MNT=${ZOLTIS_VAULT_DIR:-/srv/zoltis-vault}
docker compose stop
if mountpoint -q "$MNT"; then sync; umount "$MNT"; fi
[[ -e /dev/mapper/zoltis-vault ]] && cryptsetup close zoltis-vault
echo "Zoltis Mail stopped and storage locked."
