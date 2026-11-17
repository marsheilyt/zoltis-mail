# Zoltis Mail - Postfix (SMTP in/out, submission) + OpenDKIM (signing)
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      postfix opendkim opendkim-tools ca-certificates openssl netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*
COPY master.cf.append /etc/postfix/master.cf.append
COPY opendkim.conf /etc/opendkim.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh && cat /etc/postfix/master.cf.append >> /etc/postfix/master.cf \
 && mkdir -p /etc/postfix/zoltis /etc/postfix/tls /etc/opendkim/keys /run/opendkim \
 && chown -R opendkim:opendkim /etc/opendkim /run/opendkim
EXPOSE 25 465 587
HEALTHCHECK --interval=30s --timeout=5s CMD nc -z 127.0.0.1 25 || exit 1
ENTRYPOINT ["/entrypoint.sh"]
