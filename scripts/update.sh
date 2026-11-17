#!/usr/bin/env bash
# Update Zoltis Mail to the latest version from GitHub. Data and settings are kept.
set -euo pipefail
cd "$(dirname "$0")/.."
git pull --ff-only
docker compose up -d --build
docker image prune -f >/dev/null
echo "Zoltis Mail updated: $(docker compose exec -T web zoltis version)"
