#!/usr/bin/env bash
# Encrypt Zoltis Mail's stored data at rest (LUKS2, AES-256-XTS).
#
# Moves the mailboxes (vmail), queued mail (postfix-spool), accounts/settings (zoltis-data) and
# DKIM keys / password hashes (mailconf) into an encrypted container file on this server.
# Everything works as before while it is unlocked. After a reboot, mail stays offline until you run
#     sudo ./scripts/unlock.sh
# (other servers keep retrying delivery for ~5 days, so incoming mail is delayed, not lost).
#
#   sudo ./scripts/encrypt-storage.sh              one-time setup (asks for size + passphrase)
#   sudo ./scripts/encrypt-storage.sh --size 12    container size in GB
#   sudo ./scripts/encrypt-storage.sh --grow 5     add 5 GB to an existing (unlocked) container
#
# IF YOU LOSE THE PASSPHRASE THE MAIL IS GONE. Keep it in a password manager and keep
# encrypted backups (./scripts/backup.sh) off the server.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077

IMG=${ZOLTIS_VAULT_IMG:-/var/lib/zoltis-vault.img}
MNT=${ZOLTIS_VAULT_DIR:-/srv/zoltis-vault}
MAPPER=zoltis-vault
VOLS="vmail postfix-spool zoltis-data mailconf"
die() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

[[ $EUID -eq 0 ]] || die "run as root (sudo)"
PROJECT=$(docker compose config --format json 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin)['name'])" 2>/dev/null || echo zoltis-mail)

# ------------------------------------------------------------------ --grow
if [[ "${1:-}" == "--grow" ]]; then
  ADD=${2:?usage: --grow <GB>}; [[ $ADD =~ ^[0-9]+$ ]] || die "size must be a whole number of GB"
  mountpoint -q "$MNT" || die "storage is locked; run ./scripts/unlock.sh first"
  FREE=$(df -Pk "$(dirname "$IMG")" | awk 'NR==2 {print int($4/1048576)}')
  (( ADD + 2 <= FREE )) || die "only ${FREE} GB free on the disk"
  fallocate -l "$(( $(stat -c %s "$IMG") + ADD * 1073741824 ))" "$IMG"
  LOOP=$(cryptsetup status "$MAPPER" | awk '/device:/ {print $2}')
  losetup -c "$LOOP"
  cryptsetup resize "$MAPPER"   # may ask for the passphrase
  resize2fs "/dev/mapper/$MAPPER"
  df -h "$MNT"; exit 0
fi

# ------------------------------------------------------------------ checks
[[ -e "$IMG" ]] && die "$IMG already exists: storage is already encrypted (use ./scripts/unlock.sh)"
command -v cryptsetup >/dev/null || { info "installing cryptsetup"; apt-get update -qq && apt-get install -y -qq cryptsetup >/dev/null; }
command -v cryptsetup >/dev/null || die "cryptsetup is required (apt install cryptsetup)"
for v in $VOLS; do
  docker volume inspect "${PROJECT}_${v}" >/dev/null 2>&1 || docker volume create "${PROJECT}_${v}" >/dev/null
done

SIZE=""
[[ "${1:-}" == "--size" ]] && SIZE=${2:?usage: --size <GB>}
USED_MB=0
for v in $VOLS; do
  m=$(docker run --rm -v "${PROJECT}_${v}:/d:ro" debian:bookworm-slim du -sm /d | awk '{print $1}')
  USED_MB=$(( USED_MB + m ))
done
FREE_GB=$(df -Pk "$(dirname "$IMG")" | awk 'NR==2 {print int($4/1048576)}')
# The old copies are deleted after the move, so their space comes back. Keep 3 GB for images/logs/backups.
AVAIL_GB=$(( FREE_GB + USED_MB / 1024 - 3 ))
NEED_GB=$(( USED_MB * 3 / 2 / 1024 + 1 ))
if [[ -z $SIZE ]]; then
  SIZE=$(( AVAIL_GB * 7 / 10 ))
  (( SIZE > FREE_GB - 1 )) && SIZE=$(( FREE_GB - 1 ))   # old copies still exist during the move
  (( SIZE < NEED_GB )) && SIZE=$NEED_GB
  echo "Current data: ${USED_MB} MB. Free disk: ${FREE_GB} GB."
  read -r -p "Encrypted storage size in GB [${SIZE}]: " ans; SIZE=${ans:-$SIZE}
fi
[[ $SIZE =~ ^[0-9]+$ ]] || die "size must be a whole number of GB"
(( SIZE >= NEED_GB )) || die "${SIZE} GB is too small for ${USED_MB} MB of data (need ${NEED_GB}+ GB)"
(( SIZE + 1 <= FREE_GB )) || die "not enough free disk for ${SIZE} GB (free: ${FREE_GB} GB; the old copies are only deleted after the move)"

cat <<EOF

This will:
  1. stop Zoltis Mail (mail is offline for a few minutes; senders retry automatically)
  2. create a ${SIZE} GB encrypted container at ${IMG}
  3. move ${VOLS// /, } into it and delete the unencrypted copies
After every reboot you must run:  sudo ./scripts/unlock.sh

Make a backup first if you don't have a recent one:  ./scripts/backup.sh
If you lose the passphrase, the mail cannot be recovered.
EOF
read -r -p "Type ENCRYPT to continue: " ok; [[ $ok == ENCRYPT ]] || die "cancelled"

# ------------------------------------------------------------------ create container
info "stopping Zoltis Mail"
docker compose down
info "allocating ${SIZE} GB"
fallocate -l "${SIZE}G" "$IMG"; chmod 600 "$IMG"
# argon2id capped at 256 MB so unlocking works on 1 GB servers
cryptsetup luksFormat --batch-mode --verify-passphrase --type luks2 --cipher aes-xts-plain64 \
  --key-size 512 --pbkdf argon2id --pbkdf-memory 262144 "$IMG" \
  || { rm -f "$IMG"; die "luksFormat failed (nothing was changed; start again with: docker compose up -d)"; }
cryptsetup open "$IMG" "$MAPPER"
mkfs.ext4 -q -L zoltis-vault -m 1 "/dev/mapper/$MAPPER"
mkdir -p "$MNT"
# While locked, the empty mount point is immutable, so nothing can write mail to the plain disk.
chattr +i "$MNT" 2>/dev/null || echo "warning: couldn't make $MNT immutable"
mount -o noatime "/dev/mapper/$MAPPER" "$MNT"
chmod 700 "$MNT"

# ------------------------------------------------------------------ move data
for v in $VOLS; do
  info "moving $v"
  mkdir -p "$MNT/$v"
  docker run --rm -v "${PROJECT}_${v}:/from:ro" -v "$MNT/$v:/to" debian:bookworm-slim cp -a /from/. /to/
  a=$(docker run --rm -v "${PROJECT}_${v}:/d:ro" debian:bookworm-slim sh -c 'find /d | wc -l; du -sb /d | cut -f1' | tr '\n' ' ')
  b=$(docker run --rm -v "$MNT/$v:/d:ro" debian:bookworm-slim sh -c 'find /d | wc -l; du -sb /d | cut -f1' | tr '\n' ' ')
  [[ ${a%% *} == "${b%% *}" ]] || die "copy of $v looks incomplete ($a vs $b). Old data untouched; the copy is in $MNT/$v"
done
# Only now drop the unencrypted volumes and recreate them (same names, so compose, backup.sh
# and restore.sh keep working) as bind mounts into the encrypted storage.
for v in $VOLS; do
  docker volume rm "${PROJECT}_${v}" >/dev/null
  docker volume create --driver local -o type=none -o o=bind -o "device=$MNT/$v" \
    --label "com.docker.compose.project=${PROJECT}" --label "com.docker.compose.volume=${v}" \
    "${PROJECT}_${v}" >/dev/null
done

grep -q '^ZOLTIS_VAULT_IMG=' .env 2>/dev/null || printf '\n# Encrypted storage (scripts/encrypt-storage.sh)\nZOLTIS_VAULT_IMG=%s\nZOLTIS_VAULT_DIR=%s\n' "$IMG" "$MNT" >> .env
cryptsetup luksHeaderBackup "$IMG" --header-backup-file "./luks-header-$(date +%Y%m%d).img"

info "starting Zoltis Mail"
docker compose up -d
cat <<EOF

Done. Mail data is now encrypted at rest in ${IMG}.
 * After every reboot:      sudo ./scripts/unlock.sh
 * Before maintenance:      sudo ./scripts/lock.sh   (stops mail and locks the data)
 * Add a 2nd passphrase:    sudo cryptsetup luksAddKey ${IMG}
 * Copy ./luks-header-*.img OFF the server, then delete it here. If the container's header gets
   damaged, it is the only way back in (it is useless without your passphrase).
Note: data that was stored unencrypted before may still exist in the disk's free space.
EOF
