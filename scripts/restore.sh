#!/usr/bin/env bash
# Restore a backup made by backup.sh into a fresh install (stops the stack first).
set -euo pipefail
cd "$(dirname "$0")/.."
FILE=${1:?usage: scripts/restore.sh backups/zoltis-YYYYmmdd-HHMM.tar.gz}
read -r -p "This replaces ALL current mail data with $FILE. Type RESTORE to continue: " a
[[ $a == RESTORE ]] || { echo "Cancelled."; exit 1; }
PROJECT=$(docker compose config --format json | python3 -c "import json,sys;print(json.load(sys.stdin)['name'])")
docker compose down
ARGS=""; for v in zoltis-data mailconf vmail caddy-data; do docker volume create "${PROJECT}_${v}" >/dev/null; ARGS="$ARGS -v ${PROJECT}_${v}:/backup/${v}"; done
docker run --rm $ARGS -v "$(realpath "$FILE"):/in.tar.gz:ro" debian:bookworm-slim \
  sh -c 'for d in /backup/*; do find "$d" -mindepth 1 -delete; done; tar xzf /in.tar.gz -C /backup'
docker compose up -d
echo "Restored."
