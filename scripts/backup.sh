#!/usr/bin/env bash
# Back up all Zoltis Mail data (mailboxes, accounts, DKIM keys, certificates) to ./backups/
# Restore: ./scripts/restore.sh backups/zoltis-YYYYmmdd-HHMM.tar.gz
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p backups
STAMP=$(date +%Y%m%d-%H%M)
PROJECT=$(docker compose config --format json 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin)['name'])" 2>/dev/null || echo zoltis-mail)
VOLS="zoltis-data mailconf vmail caddy-data"
ARGS=""; for v in $VOLS; do ARGS="$ARGS -v ${PROJECT}_${v}:/backup/${v}:ro"; done
echo "Backing up volumes: $VOLS"
# Make sure the backup fits: a full disk stops Postfix and Dovecot from accepting mail.
NEED=$(docker run --rm $ARGS debian:bookworm-slim du -sm /backup | awk '{print $1}')
FREE=$(df -Pm backups | awk 'NR==2 {print $4}')
EST=$(( NEED * 7 / 10 + 500 ))   # mail usually compresses to well under 70%, +500 MB safety margin
if (( FREE < EST )) && [[ "${BACKUP_FORCE:-}" != 1 ]]; then
  echo "error: the backup needs about ${EST} MB but only ${FREE} MB is free on this disk." >&2
  echo "       Delete old files in backups/ (copy them off the server first), or run with BACKUP_FORCE=1." >&2
  exit 1
fi
docker run --rm $ARGS -v "$PWD/backups:/out" debian:bookworm-slim \
  tar czf "/out/zoltis-${STAMP}.tar.gz" -C /backup .
cp .env "backups/zoltis-${STAMP}.env"
chmod 600 "backups/zoltis-${STAMP}".*
echo "Saved backups/zoltis-${STAMP}.tar.gz (+ .env). Copy it off this server."
