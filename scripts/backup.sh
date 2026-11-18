#!/usr/bin/env bash
# Back up all Zoltis Mail data (mailboxes, accounts, DKIM keys, certificates, .env) to ./backups/
#
# The backup is ENCRYPTED with a passphrase you choose (AES-256, GnuPG with integrity check;
# OpenSSL AES-256 + PBKDF2 if gpg isn't installed), so a copied backup file is useless without it.
#
#   ./scripts/backup.sh                          asks for a passphrase
#   BACKUP_PASSPHRASE=... ./scripts/backup.sh    for cron jobs (keep that file root-only)
#   ./scripts/backup.sh --no-encrypt             plain .tar.gz (not recommended)
#
# Restore: ./scripts/restore.sh backups/zoltis-YYYYmmdd-HHMM.tar.gz.gpg
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
mkdir -p backups
STAMP=$(date +%Y%m%d-%H%M)
PROJECT=$(docker compose config --format json 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin)['name'])" 2>/dev/null || echo zoltis-mail)
VOLS="zoltis-data mailconf vmail caddy-data"
ENCRYPT=yes
[[ "${1:-}" == "--no-encrypt" ]] && ENCRYPT=no

if [[ $ENCRYPT == yes && -z "${BACKUP_PASSPHRASE:-}" ]]; then
  read -r -s -p "Backup passphrase (12+ characters): " BACKUP_PASSPHRASE; echo
  read -r -s -p "Repeat passphrase: " P2; echo
  [[ "$BACKUP_PASSPHRASE" == "$P2" ]] || { echo "Passphrases don't match."; exit 1; }
fi
[[ $ENCRYPT == no || ${#BACKUP_PASSPHRASE} -ge 12 ]] || { echo "Use at least 12 characters."; exit 1; }

ARGS=""; for v in $VOLS; do ARGS="$ARGS -v ${PROJECT}_${v}:/backup/${v}:ro"; done
ARGS="$ARGS -v $PWD/.env:/backup/env/dot-env:ro"
echo "Backing up volumes: $VOLS (+ .env)"
# Make sure the backup fits: a full disk stops Postfix and Dovecot from accepting mail.
NEED=$(docker run --rm $ARGS debian:bookworm-slim du -sm /backup | awk '{print $1}')
FREE=$(df -Pm backups | awk 'NR==2 {print $4}')
EST=$(( NEED * 7 / 10 + 500 ))   # mail usually compresses to well under 70%, +500 MB safety margin
if (( FREE < EST )) && [[ "${BACKUP_FORCE:-}" != 1 ]]; then
  echo "error: the backup needs about ${EST} MB but only ${FREE} MB is free on this disk." >&2
  echo "       Delete old files in backups/ (copy them off the server first), or run with BACKUP_FORCE=1." >&2
  exit 1
fi
stream() { docker run --rm $ARGS debian:bookworm-slim tar czf - -C /backup .; }

if [[ $ENCRYPT == no ]]; then
  OUT="backups/zoltis-${STAMP}.tar.gz"
  stream > "$OUT"
elif command -v gpg >/dev/null 2>&1; then
  OUT="backups/zoltis-${STAMP}.tar.gz.gpg"
  stream | gpg --batch --yes --symmetric --cipher-algo AES256 --s2k-mode 3 --s2k-digest-algo SHA512 \
    --s2k-count 65011712 --compress-algo none --pinentry-mode loopback \
    --passphrase-fd 3 -o "$OUT" 3<<<"$BACKUP_PASSPHRASE"
else
  OUT="backups/zoltis-${STAMP}.tar.gz.enc"
  stream | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 600000 -md sha512 -pass fd:3 -out "$OUT" 3<<<"$BACKUP_PASSPHRASE"
  sha256sum "$OUT" > "$OUT.sha256"
fi
chmod 600 "$OUT"*
echo "Saved $OUT"
[[ $ENCRYPT == yes ]] && echo "Keep the passphrase safe: without it this backup can't be restored."
echo "Copy it off this server."
