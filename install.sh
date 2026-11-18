#!/usr/bin/env bash
# =============================================================================
#  Zoltis Mail - Community Edition installer (Docker)
#
#    git clone https://github.com/marsheilyt/zoltis-mail.git
#    cd zoltis-mail && sudo ./install.sh
#
#  Works on Ubuntu 22.04/24.04, Debian 12 and any Linux server with Docker.
#  Re-run any time; your .env and data volumes are kept.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

g=$'\e[32m'; y=$'\e[33m'; r=$'\e[31m'; b=$'\e[1m'; n=$'\e[0m'
info() { echo "${g}==>${n} $*"; }
warn() { echo "${y}warning:${n} $*"; }
die()  { echo "${r}error:${n} $*" >&2; exit 1; }
ask()  { local q=$1 def=${2:-} a; read -r -p "$q${def:+ [$def]}: " a </dev/tty || true; echo "${a:-$def}"; }
yes_no() { local a; read -r -p "$1 [y/N]: " a </dev/tty || true; [[ $a =~ ^[Yy] ]]; }
yes_def() { local a; read -r -p "$1 [Y/n]: " a </dev/tty || true; [[ ! $a =~ ^[Nn] ]]; }

[[ $(uname -s) == Linux ]] || die "Zoltis Mail runs on a Linux server."
SUDO=""; [[ $EUID -ne 0 ]] && SUDO="sudo"

echo "${b}Zoltis Mail - Community Edition${n}  (up to 10 accounts, 720 MB each)"
echo

# ------------------------------------------------------------------ DNS first (Cloudflare)
# Let's Encrypt certificates and mail delivery need DNS that already works, so the domain
# should be on Cloudflare (or another DNS provider) and resolving before we install.
if [[ ! -f .env && "${ZOLTIS_DNS_READY:-}" != 1 ]]; then
  SRV_IP=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || echo "<this server's IP>")
  echo "${b}Before you install: connect your domain to Cloudflare${n} (recommended, free plan)"
  echo "  1. At dash.cloudflare.com click 'Add a domain' and choose the Free plan."
  echo "  2. At your registrar, replace the nameservers with the two Cloudflare shows you."
  echo "     Namecheap: Domain List > Manage > Nameservers > Custom DNS."
  echo "  3. ${b}Wait about 30 minutes${n}, until Cloudflare shows the domain as 'Active' (it emails you)."
  echo "  4. In Cloudflare > DNS > Records, add two A records with Proxy status ${b}DNS only (grey cloud)${n}:"
  echo "        A   webmail   ${SRV_IP}"
  echo "        A   mail      ${SRV_IP}"
  echo "     Delete old MX records, and turn off Cloudflare Email Routing."
  echo "  The mail records (MX, SPF, DKIM, DMARC) are generated for you after install:"
  echo "  Admin console > Setup guide shows each one exactly as Cloudflare asks for it."
  echo
  if ! yes_no "Is your domain active on Cloudflare (or another DNS provider) with these two A records?"; then
    echo
    info "Do the steps above, wait about 30 minutes, then run ${b}sudo ./install.sh${n} again."
    exit 0
  fi
fi

# ------------------------------------------------------------------ Docker
if ! command -v docker >/dev/null; then
  warn "Docker is not installed."
  if yes_no "Install Docker now using the official script from get.docker.com?"; then
    curl -fsSL https://get.docker.com | $SUDO sh
    $SUDO systemctl enable --now docker
  else
    die "Install Docker first: https://docs.docker.com/engine/install/"
  fi
fi
DC="docker compose"
$SUDO docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (docker compose version)."
[[ -n "$SUDO" ]] && ! docker info >/dev/null 2>&1 && DC="$SUDO docker compose"

# ------------------------------------------------------------------ preflight
for p in 25 80 443 465 587 993; do
  if command -v ss >/dev/null && ss -ltnH "sport = :$p" 2>/dev/null | grep -q .; then
    if ! $DC ps --format '{{.Ports}}' 2>/dev/null | grep -q ":$p->"; then
      warn "port $p is already in use by another program (an old Postfix/Dovecot/nginx?). Stop it before continuing."
    fi
  fi
done
if command -v timeout >/dev/null; then
  if ! timeout 6 bash -c 'exec 3<>/dev/tcp/gmail-smtp-in.l.google.com/25' 2>/dev/null; then
    warn "outgoing port 25 seems blocked by your hosting provider. You can receive mail, but sending to other"
    warn "servers will fail until they unblock it (many cloud providers do this on request)."
  fi
fi
MEM=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
# ClamAV antivirus only on servers with 4 GB RAM or more (a "4 GB" VPS reports about 3.8 GB).
AV_MIN_MB=3500
SWAP=$(awk '/SwapTotal/ {print int($2/1024)}' /proc/meminfo)
DISK=$(df -Pm . | awk 'NR==2 {print int($4/1024)}')
(( MEM < 900 )) && warn "This server has only ${MEM} MB RAM. 1 GB is the minimum; expect slowness."
(( DISK < 8 )) && warn "Only ${DISK} GB of free disk. 10 mailboxes x 720 MB need about 7.5 GB plus room for images and backups."

# ------------------------------------------------------------------ swap (small servers)
# A 1-2 GB VPS has no headroom: without swap a short memory spike makes the kernel
# kill Postfix, Dovecot or the web app. A swap file absorbs those spikes.
if (( MEM < 2500 && SWAP < 1000 )) && [[ ! -e /swapfile ]] && (( DISK >= 6 )); then
  info "This server has ${MEM} MB RAM and no swap."
  if yes_def "Add a 2 GB swap file (recommended so mail services aren't killed when memory runs short)?"; then
    $SUDO fallocate -l 2G /swapfile 2>/dev/null || $SUDO dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    $SUDO chmod 600 /swapfile
    $SUDO mkswap /swapfile >/dev/null
    if $SUDO swapon /swapfile 2>/dev/null; then
      grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' | $SUDO tee -a /etc/fstab >/dev/null
      echo 'vm.swappiness=10' | $SUDO tee /etc/sysctl.d/99-zoltis-mail.conf >/dev/null
      $SUDO sysctl -q -p /etc/sysctl.d/99-zoltis-mail.conf || true
      info "2 GB swap enabled."
    else
      $SUDO rm -f /swapfile
      warn "This VPS doesn't allow swap (common on OpenVZ/LXC). Keep antivirus off."
    fi
  fi
fi

# ------------------------------------------------------------------ .env
if [[ ! -f .env ]]; then
  info "Let's configure your server"
  IP=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)
  WEB=$(ask "Webmail address (e.g. webmail.yourcompany.com)")
  [[ -n "$WEB" ]] || die "webmail address is required"
  DOMAIN=${WEB#*.}
  MAILH=$(ask "Mail server name" "mail.$DOMAIN")
  IP=$(ask "This server's public IPv4 address" "$IP")
  EMAIL=$(ask "Email for Let's Encrypt certificate notices" "admin@$DOMAIN")
  NAME="Zoltis Mail"   # Community Edition: the Zoltis Mail name and logo can't be changed
  PLIMIT=100
  (( MEM < 2500 )) && PLIMIT=20
  if (( MEM >= AV_MIN_MB )); then
    AV=true; PROF=antivirus
    info "ClamAV antivirus is on (this server has ${MEM} MB RAM)."
  else
    AV=false; PROF=
    info "ClamAV antivirus is off: it's only enabled on servers with 4 GB RAM or more (this one has ${MEM} MB)."
    info "The risky-attachment blocker still stops programs, macros and disguised files."
  fi
  TOKEN=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-8 | tr a-f A-F)
  cat > .env <<EOF
WEB_HOST=$WEB
MAIL_HOST=$MAILH
PUBLIC_IP=$IP
ACME_EMAIL=$EMAIL
APP_NAME=$NAME
ANTIVIRUS=$AV
COMPOSE_PROFILES=$PROF
POSTFIX_PROCESS_LIMIT=$PLIMIT
SETUP_TOKEN=$TOKEN
LICENSE_REQUIRED=true
LICENSE_KEY=
TZ=$(cat /etc/timezone 2>/dev/null || echo UTC)
EOF
  chmod 600 .env
  info "Saved settings to .env"
fi
set -a; . ./.env; set +a
if (( MEM < 2500 )) && ! grep -q '^POSTFIX_PROCESS_LIMIT=' .env; then
  echo "POSTFIX_PROCESS_LIMIT=20" >> .env; POSTFIX_PROCESS_LIMIT=20
fi
if (( MEM < AV_MIN_MB )) && [[ "${ANTIVIRUS:-}" == true ]]; then
  # Below 4 GB RAM antivirus stays off, also on servers installed with an older version.
  sed -i -e 's/^ANTIVIRUS=.*/ANTIVIRUS=false/' -e 's/^COMPOSE_PROFILES=.*/COMPOSE_PROFILES=/' .env
  ANTIVIRUS=false; COMPOSE_PROFILES=
  warn "ClamAV antivirus turned off: it's only enabled on servers with 4 GB RAM or more (this one has ${MEM} MB)."
fi

# ------------------------------------------------------------------ DNS check
ip2int() { local IFS=.; read -r a b c d <<<"$1"; echo $(( (a << 24) + (b << 16) + (c << 8) + d )); }
is_cloudflare_ip() {   # Cloudflare's published proxy ranges (cloudflare.com/ips-v4)
  local ip; ip=$(ip2int "$1")
  for net in 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 \
             190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 \
             104.24.0.0/14 172.64.0.0/13 131.0.72.0/22; do
    local base=${net%/*} bits=${net#*/}
    local mask=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
    (( (ip & mask) == ($(ip2int "$base") & mask) )) && return 0
  done
  return 1
}
DNS_OK=true
echo
info "Checking DNS for ${WEB_HOST} and ${MAIL_HOST}..."
for host in "$WEB_HOST" "$MAIL_HOST"; do
  got=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1 {print $1}' || true)
  if [[ -z "$got" ]]; then
    warn "$host doesn't resolve yet. Add an A record:  $host -> ${PUBLIC_IP:-<server IP>}  (DNS only)"; DNS_OK=false
  elif [[ -n "${PUBLIC_IP:-}" && "$got" != "$PUBLIC_IP" ]]; then
    if is_cloudflare_ip "$got"; then
      warn "$host goes through Cloudflare's proxy (orange cloud). Mail can't pass through it."
      warn "  In Cloudflare > DNS > Records, click the record and set Proxy status to 'DNS only' (grey cloud)."
    else
      warn "$host points to $got, not this server (${PUBLIC_IP}). Fix the A record."
    fi
    DNS_OK=false
  else
    echo "   ${g}ok${n}  $host -> $got"
  fi
done
if [[ $DNS_OK != true ]]; then
  echo "   New records can take a few minutes to show up (up to ~30 minutes after moving to Cloudflare)."
  echo "   You can continue now: HTTPS certificates are requested again automatically once DNS is right."
  yes_no "Continue installing anyway?" || { info "Fix the DNS records, wait a few minutes, then run ${b}sudo ./install.sh${n} again."; exit 0; }
fi
echo

# ------------------------------------------------------------------ start
info "Building and starting containers (first run takes a few minutes)..."
$DC up -d --build
# Build cache isn't needed after the first build; reclaim the disk space on small servers.
(( DISK < 40 )) && $SUDO docker builder prune -f >/dev/null 2>&1 || true

info "Waiting for the web app..."
for i in $(seq 1 60); do
  if $DC exec -T web python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')" >/dev/null 2>&1; then break; fi
  sleep 2
done
CODE=$($DC exec -T web zoltis setup-code 2>/dev/null | tail -1 || true)

echo
echo "${g}${b}Zoltis Mail is running.${n}"
echo "  Open:          https://${WEB_HOST}"
if [[ -n "$CODE" && "$CODE" != Setup* ]]; then
  echo "  Setup code:    ${b}${CODE}${n}   (create your admin account on the first screen)"
fi
echo "  Then:          Admin console -> ${b}Setup guide${n}: every DNS record (MX, SPF, DKIM, DMARC) ready to copy into"
echo "                 Cloudflare, plus reverse DNS, port 25 and mail app settings."
echo "  Reverse DNS:   ask your hosting provider to set the PTR of ${PUBLIC_IP:-your IP} to ${MAIL_HOST}"
echo "  Logs:          $DC logs -f"
echo "  Update:        ./scripts/update.sh      Backup: ./scripts/backup.sh"
[[ "${ANTIVIRUS}" == true ]] && echo "  Antivirus:     ClamAV downloads its virus database on first start (~5 min); attachments wait until it's ready."
echo
