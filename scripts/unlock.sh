#!/usr/bin/env bash
# Unlock Zoltis Mail's encrypted storage after a reboot and start mail again.
#   sudo ./scripts/unlock.sh
# (Only needed if you ran scripts/encrypt-storage.sh.)
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $EUID -eq 0 ]] || { echo "error: run as root (sudo)" >&2; exit 1; }
set -a; [[ -f .env ]] && . ./.env; set +a
IMG=${ZOLTIS_VAULT_IMG:-/var/lib/zoltis-vault.img}
MNT=${ZOLTIS_VAULT_DIR:-/srv/zoltis-vault}
MAPPER=zoltis-vault
[[ -f "$IMG" ]] || { echo "error: no encrypted storage at $IMG (run scripts/encrypt-storage.sh first)" >&2; exit 1; }

if ! mountpoint -q "$MNT"; then
  [[ -e /dev/mapper/$MAPPER ]] || cryptsetup open "$IMG" "$MAPPER"   # asks for the passphrase
  fsck.ext4 -p "/dev/mapper/$MAPPER" >/dev/null || true
  mount -o noatime "/dev/mapper/$MAPPER" "$MNT"
fi
echo "Storage unlocked: $(df -h "$MNT" | awk 'NR==2 {print $3" used of "$2}')"
docker compose up -d
echo "Zoltis Mail is running. Mail that other servers queued while it was locked arrives over the next minutes."
