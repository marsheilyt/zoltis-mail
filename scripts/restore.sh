#!/usr/bin/env bash
# Restore a backup made by backup.sh into a fresh install (stops the stack first).
# Accepts .tar.gz.gpg (encrypted), .tar.gz.enc (encrypted, OpenSSL) or .tar.gz (plain).
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
FILE=${1:?usage: scripts/restore.sh backups/zoltis-YYYYmmdd-HHMM.tar.gz.gpg}
[[ -f "$FILE" ]] || { echo "No such file: $FILE"; exit 1; }
read -r -p "This replaces ALL current mail data with $FILE. Type RESTORE to continue: " a
[[ $a == RESTORE ]] || { echo "Cancelled."; exit 1; }
PROJECT=$(docker compose config --format json | python3 -c "import json,sys;print(json.load(sys.stdin)['name'])")

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
case "$FILE" in
  *.gpg|*.enc)
    [[ -n "${BACKUP_PASSPHRASE:-}" ]] || { read -r -s -p "Backup passphrase: " BACKUP_PASSPHRASE; echo; }
    if [[ "$FILE" == *.gpg ]]; then
      gpg --batch --quiet --pinentry-mode loopback --passphrase-fd 3 -d -o "$TMP/in.tar.gz" "$FILE" 3<<<"$BACKUP_PASSPHRASE" \
        || { echo "Wrong passphrase or damaged backup."; exit 1; }
    else
      [[ -f "$FILE.sha256" ]] && { sha256sum -c "$FILE.sha256" >/dev/null || { echo "Backup file is damaged (checksum mismatch)."; exit 1; }; }
      openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -md sha512 -pass fd:3 -in "$FILE" -out "$TMP/in.tar.gz" 3<<<"$BACKUP_PASSPHRASE" \
        || { echo "Wrong passphrase or damaged backup."; exit 1; }
    fi
    IN="$TMP/in.tar.gz" ;;
  *) IN="$(realpath "$FILE")" ;;
esac
gzip -t "$IN" || { echo "Backup archive is damaged."; exit 1; }

docker compose down
ARGS=""; for v in zoltis-data mailconf vmail caddy-data; do docker volume create "${PROJECT}_${v}" >/dev/null; ARGS="$ARGS -v ${PROJECT}_${v}:/backup/${v}"; done
docker run --rm $ARGS -v "$IN:/in.tar.gz:ro" -v "$TMP:/envout" debian:bookworm-slim \
  sh -c 'for d in /backup/zoltis-data /backup/mailconf /backup/vmail /backup/caddy-data; do find "$d" -mindepth 1 -delete; done
         tar xzf /in.tar.gz -C /backup --exclude=./env
         tar xzf /in.tar.gz -C /envout ./env/dot-env 2>/dev/null || true'
if [[ -f "$TMP/env/dot-env" ]]; then
  cp "$TMP/env/dot-env" .env.from-backup; chmod 600 .env.from-backup
  echo "The backup's settings were saved to .env.from-backup (compare with .env if this is a new server)."
fi
docker compose up -d
echo "Restored."
