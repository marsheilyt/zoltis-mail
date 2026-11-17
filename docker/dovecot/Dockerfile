# Zoltis Mail - Dovecot 2.3 (IMAP, LMTP delivery, quotas)
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      dovecot-imapd dovecot-lmtpd ca-certificates openssl netcat-openbsd \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 5000 vmail && useradd -u 5000 -g vmail -d /var/vmail -s /usr/sbin/nologin vmail \
 && rm -rf /etc/dovecot/conf.d /etc/dovecot/dovecot.conf
COPY dovecot.conf /etc/dovecot/dovecot.conf.tmpl
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
EXPOSE 993
VOLUME ["/var/vmail"]
HEALTHCHECK --interval=30s --timeout=5s CMD nc -z 127.0.0.1 143 || exit 1
ENTRYPOINT ["/entrypoint.sh"]
