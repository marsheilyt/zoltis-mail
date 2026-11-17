# Zoltis Mail web app + admin console (Python standard library only)
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 1000 --home /var/lib/zoltis zoltis \
 && mkdir -p /var/lib/zoltis/mailconf && chown -R zoltis:zoltis /var/lib/zoltis
WORKDIR /opt/zoltis
COPY zoltis ./zoltis
COPY web ./web
COPY config/zoltis.ini.example ./zoltis.ini.example
RUN printf '#!/bin/sh\ncd /opt/zoltis && exec python3 -m zoltis "$@"\n' > /usr/local/bin/zoltis && chmod 755 /usr/local/bin/zoltis
ENV ZOLTIS_SERVER_LISTEN=0.0.0.0 ZOLTIS_SERVER_PORT=8080 PYTHONUNBUFFERED=1
USER zoltis
EXPOSE 8080
VOLUME ["/var/lib/zoltis", "/var/lib/zoltis/mailconf"]
HEALTHCHECK --interval=30s --timeout=3s CMD python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')" || exit 1
CMD ["python3", "-m", "zoltis", "serve"]
