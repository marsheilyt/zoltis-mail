#!/bin/bash
# Zoltis Mail - Dovecot container entrypoint.
set -euo pipefail
: "${MAIL_HOST:?set MAIL_HOST}"
: "${WEB_IP:=172.28.0.10}"
CONF=/zoltis-conf
TLS=/etc/dovecot/tls
log() { echo "[dovecot-entrypoint] $*"; }

mkdir -p "$TLS" /etc/dovecot/zoltis /var/vmail
chown vmail:vmail /var/vmail
sed -e "s/__WEB_IP__/${WEB_IP}/" -e "s/__MAIL_HOST__/${MAIL_HOST}/" /etc/dovecot/dovecot.conf.tmpl > /etc/dovecot/dovecot.conf

install_cert() {
  local crt key
  crt=$(find /caddy -path "*/${MAIL_HOST}/${MAIL_HOST}.crt" 2>/dev/null | head -1 || true)
  key="${crt%.crt}.key"
  if [[ -n "$crt" && -f "$key" ]]; then
    if ! cmp -s "$crt" "$TLS/fullchain.pem" 2>/dev/null; then
      cp "$crt" "$TLS/fullchain.pem"; cp "$key" "$TLS/privkey.pem"; chmod 600 "$TLS/privkey.pem"
      log "installed Let's Encrypt certificate for ${MAIL_HOST}"; return 0
    fi
    return 1
  fi
  if [[ ! -f "$TLS/fullchain.pem" ]]; then
    log "no certificate yet for ${MAIL_HOST}; using a temporary self-signed one"
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=${MAIL_HOST}" \
      -keyout "$TLS/privkey.pem" -out "$TLS/fullchain.pem" 2>/dev/null
    chmod 600 "$TLS/privkey.pem"
  fi
  return 1
}

SERIAL=""
sync_conf() {
  [[ -f "$CONF/serial" ]] || return 1
  local s; s=$(cat "$CONF/serial")
  [[ "$s" == "$SERIAL" ]] && return 1
  for f in users master-users app-passwords; do
    install -m 0640 -o root -g dovecot "$CONF/dovecot/$f" "/etc/dovecot/zoltis/$f.new" 2>/dev/null || install -m 0640 -o root -g dovecot /dev/null "/etc/dovecot/zoltis/$f.new"
    mv "/etc/dovecot/zoltis/$f.new" "/etc/dovecot/zoltis/$f"   # passwd-file is re-read automatically
  done
  SERIAL="$s"
  echo "$s" > "$CONF/applied.dovecot" 2>/dev/null || true
  return 0
}

install_cert || true
for f in users master-users app-passwords; do [[ -f /etc/dovecot/zoltis/$f ]] || install -m 0640 -o root -g dovecot /dev/null /etc/dovecot/zoltis/$f; done
for i in $(seq 1 60); do [[ -f "$CONF/serial" ]] && break; log "waiting for the web container to render config..."; sleep 2; done
sync_conf || true
dovecot -F &
DV_PID=$!
trap 'dovecot stop; exit 0' TERM INT

TICK=0
while kill -0 "$DV_PID" 2>/dev/null; do
  sleep 5
  if sync_conf; then log "accounts updated"; fi
  TICK=$((TICK + 1))
  if (( TICK % 720 == 0 )) && install_cert; then doveadm reload || true; fi
done
