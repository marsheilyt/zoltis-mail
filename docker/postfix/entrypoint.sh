#!/bin/bash
# Zoltis Mail - Postfix + OpenDKIM container entrypoint.
# Reads the files the web container renders into /zoltis-conf and reloads when they change.
set -euo pipefail

: "${MAIL_HOST:?set MAIL_HOST (e.g. mail.example.com)}"
CONF=/zoltis-conf
TLS=/etc/postfix/tls
log() { echo "[postfix-entrypoint] $*"; }

# ------------------------------------------------------------------ TLS certificate
find_cert() {
  CRT=$(find /caddy -path "*/${MAIL_HOST}/${MAIL_HOST}.crt" 2>/dev/null | head -1 || true)
  KEY="${CRT%.crt}.key"
}
install_cert() {
  find_cert
  if [[ -n "${CRT}" && -f "${KEY}" ]]; then
    if ! cmp -s "$CRT" "$TLS/fullchain.pem" 2>/dev/null; then
      cp "$CRT" "$TLS/fullchain.pem"; cp "$KEY" "$TLS/privkey.pem"; chmod 600 "$TLS/privkey.pem"
      log "installed Let's Encrypt certificate for ${MAIL_HOST}"
      return 0
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

# ------------------------------------------------------------------ main.cf
configure() {
  local plimit=${POSTFIX_PROCESS_LIMIT:-100}
  [[ "$plimit" =~ ^[0-9]+$ ]] && (( plimit >= 5 )) || plimit=100
  local climit=$(( plimit / 2 > 5 ? plimit / 2 : 5 ))
  postconf -e \
    "default_process_limit = ${plimit}" \
    "smtpd_client_connection_count_limit = ${climit}" \
    "myhostname = ${MAIL_HOST}" \
    "myorigin = ${MAIL_HOST}" \
    "mydestination = localhost" \
    "mynetworks = 127.0.0.0/8" \
    "inet_interfaces = all" \
    "inet_protocols = ipv4" \
    "smtpd_banner = \$myhostname ESMTP" \
    "biff = no" "append_dot_mydomain = no" "readme_directory = no" \
    "compatibility_level = 3.6" \
    "maillog_file = /dev/stdout" \
    "virtual_mailbox_domains = hash:/etc/postfix/zoltis/domains" \
    "virtual_mailbox_maps = hash:/etc/postfix/zoltis/mailboxes" \
    "virtual_alias_maps = hash:/etc/postfix/zoltis/aliases" \
    "smtpd_sender_login_maps = hash:/etc/postfix/zoltis/senders" \
    "virtual_transport = lmtp:inet:dovecot:24" \
    "smtpd_sasl_type = dovecot" \
    "smtpd_sasl_path = inet:dovecot:12345" \
    "smtpd_sasl_auth_enable = no" \
    "smtpd_tls_cert_file = ${TLS}/fullchain.pem" \
    "smtpd_tls_key_file = ${TLS}/privkey.pem" \
    "smtpd_tls_security_level = may" \
    "smtpd_tls_auth_only = yes" \
    "smtpd_tls_mandatory_protocols = >=TLSv1.2" \
    "smtpd_tls_protocols = >=TLSv1.2" \
    "smtpd_tls_mandatory_ciphers = high" \
    "smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CBC3-SHA, KRB5-DES, CBC3-SHA" \
    "tls_preempt_cipherlist = yes" \
    "tls_ssl_options = NO_COMPRESSION NO_RENEGOTIATION" \
    "smtpd_tls_received_header = yes" \
    "smtpd_tls_loglevel = 1" \
    "smtp_tls_loglevel = 1" \
    "smtp_tls_note_starttls_offer = yes" \
    "smtp_tls_mandatory_protocols = >=TLSv1.2" \
    "smtp_tls_mandatory_ciphers = high" \
    "smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache" \
    "smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache" \
    "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt" \
    "smtpd_helo_required = yes" \
    "disable_vrfy_command = yes" \
    "smtpd_client_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_rbl_client zen.spamhaus.org=127.0.0.[2..11], reject_rbl_client bl.spamcop.net" \
    "smtpd_helo_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname" \
    "smtpd_sender_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_non_fqdn_sender, reject_unknown_sender_domain" \
    "smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination" \
    "smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, reject_non_fqdn_recipient, check_policy_service inet:dovecot:12340" \
    "message_size_limit = 36700160" \
    "mailbox_size_limit = 0" \
    "milter_default_action = accept" \
    "milter_protocol = 6" \
    "smtpd_milters = inet:127.0.0.1:8891" \
    "non_smtpd_milters = inet:127.0.0.1:8891"
  # No chroot: service names (dovecot) must resolve through Docker's DNS.
  postconf -F '*/*/chroot = n'
  # Debian's master.cf has postlog commented on some versions; maillog_file needs it.
  grep -q '^postlog' /etc/postfix/master.cf || \
    printf 'postlog   unix-dgram n  -       n       -       1       postlogd\n' >> /etc/postfix/master.cf
}

# ------------------------------------------------------------------ outgoing encryption policy
# DANE: verify receiving servers through DNSSEC-signed TLSA records (needs a validating resolver).
# MTA-STS: enforce TLS + certificate checks for domains that publish a policy (Gmail, Outlook, ...).
# Everything else: opportunistic TLS. Each layer falls back safely if its helper isn't running.
start_unbound() {
  unbound-anchor -a /var/lib/unbound/root.key >/dev/null 2>&1 || true
  chown unbound:unbound /var/lib/unbound/root.key 2>/dev/null || true
  unbound -d -c /etc/unbound/zoltis.conf &
  UB_PID=$!
}
start_sts() { mta-sts-daemon -c /etc/mta-sts-daemon.yml >/dev/null 2>&1 & STS_PID=$!; }
outbound_policy() {
  local dane=no sts=no
  [[ -f /etc/resolv.conf.docker ]] || cp /etc/resolv.conf /etc/resolv.conf.docker
  start_unbound
  for i in $(seq 1 15); do
    if dig +short +time=2 @127.0.0.1 dovecot A >/dev/null 2>&1 && \
       dig +dnssec +time=3 @127.0.0.1 isc.org SOA 2>/dev/null | grep -q " ad[ ;]"; then dane=yes; break; fi
    sleep 1
  done
  if [[ $dane == yes ]]; then
    printf 'nameserver 127.0.0.1\noptions edns0 trust-ad\n' > /etc/resolv.conf
    postconf -e "smtp_dns_support_level = dnssec" "smtp_tls_security_level = dane"
  else
    cp /etc/resolv.conf.docker /etc/resolv.conf
    postconf -e "smtp_dns_support_level = enabled" "smtp_tls_security_level = may"
  fi
  start_sts
  for i in $(seq 1 10); do nc -z 127.0.0.1 8461 2>/dev/null && { sts=yes; break; }; sleep 1; done
  if [[ $sts == yes ]]; then
    postconf -e "smtp_tls_policy_maps = socketmap:inet:127.0.0.1:8461:postfix"
  else
    postconf -e "smtp_tls_policy_maps ="
  fi
  log "outgoing encryption: DANE=${dane} MTA-STS=${sts} (otherwise opportunistic TLS)"
}

# ------------------------------------------------------------------ sync from web container
SERIAL=""
sync_conf() {
  [[ -f "$CONF/serial" ]] || return 1
  local s; s=$(cat "$CONF/serial")
  [[ "$s" == "$SERIAL" ]] && return 1
  for f in domains mailboxes aliases senders; do
    touch "$CONF/postfix/$f" 2>/dev/null || true
    cp "$CONF/postfix/$f" "/etc/postfix/zoltis/$f" 2>/dev/null || : > "/etc/postfix/zoltis/$f"
    postmap "hash:/etc/postfix/zoltis/$f"
  done
  rm -rf /etc/opendkim/keys.new && mkdir -p /etc/opendkim/keys.new
  cp "$CONF"/dkim/keys/*.private /etc/opendkim/keys.new/ 2>/dev/null || true
  rm -rf /etc/opendkim/keys && mv /etc/opendkim/keys.new /etc/opendkim/keys
  cp "$CONF/dkim/KeyTable" /etc/opendkim/KeyTable 2>/dev/null || : > /etc/opendkim/KeyTable
  cp "$CONF/dkim/SigningTable" /etc/opendkim/SigningTable 2>/dev/null || : > /etc/opendkim/SigningTable
  chown -R opendkim:opendkim /etc/opendkim; chmod 700 /etc/opendkim/keys; chmod 600 /etc/opendkim/keys/* 2>/dev/null || true
  SERIAL="$s"
  echo "$s" > "$CONF/applied.postfix" 2>/dev/null || true
  return 0
}

start_opendkim() {
  [[ -n "${DKIM_PID:-}" ]] && kill "$DKIM_PID" 2>/dev/null && wait "$DKIM_PID" 2>/dev/null || true
  rm -f /run/opendkim/opendkim.pid
  opendkim -f -x /etc/opendkim.conf &
  DKIM_PID=$!
}

mkdir -p "$TLS" /etc/postfix/zoltis
install_cert || true
configure
outbound_policy
for i in $(seq 1 60); do [[ -f "$CONF/serial" ]] && break; log "waiting for the web container to render config..."; sleep 2; done
sync_conf || true
start_opendkim
postfix check || true
postfix start-fg &
PF_PID=$!
trap 'postfix stop; kill $DKIM_PID ${UB_PID:-} ${STS_PID:-} 2>/dev/null; exit 0' TERM INT

TICK=0
while kill -0 "$PF_PID" 2>/dev/null; do
  sleep 5
  if sync_conf; then
    log "configuration changed: reloading postfix and opendkim"
    postfix reload || true
    start_opendkim
  fi
  TICK=$((TICK + 1))
  if (( TICK % 720 == 0 )); then   # hourly: pick up renewed certificates
    if install_cert; then postfix reload || true; fi
  fi
  kill -0 "$DKIM_PID" 2>/dev/null || start_opendkim
  if [[ -n "${STS_PID:-}" ]] && ! kill -0 "$STS_PID" 2>/dev/null; then log "restarting MTA-STS resolver"; start_sts; fi
  if [[ -n "${UB_PID:-}" ]] && ! kill -0 "$UB_PID" 2>/dev/null; then
    log "DNS resolver stopped: falling back to opportunistic TLS"; cp /etc/resolv.conf.docker /etc/resolv.conf
    postconf -e "smtp_dns_support_level = enabled" "smtp_tls_security_level = may"; postfix reload || true; UB_PID=""
  fi
done
