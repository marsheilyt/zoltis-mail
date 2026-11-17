"""Configuration loading.

Order of precedence (highest first):
  1. Environment variables  ZOLTIS_<SECTION>_<KEY>   e.g. ZOLTIS_IMAP_HOST
  2. Config file given by --config or ZOLTIS_CONFIG
  3. /etc/zoltis/zoltis.ini
  4. Built-in defaults below
"""

from __future__ import annotations

import configparser
import os
from dataclasses import dataclass, field

DEFAULTS = {
    "server": {
        "listen": "127.0.0.1",
        "port": "8080",
        # Set to true when running behind HTTPS (nginx/caddy). Marks cookies Secure.
        "behind_https": "false",
        # Trust X-Forwarded-For from the reverse proxy for rate limiting/logging.
        "trust_proxy": "true",
        "session_hours": "12",
        "max_upload_mb": "25",
        "data_dir": "/var/lib/zoltis",
    },
    "imap": {
        # Use "auto" to derive host from the login email domain (mail.<domain>).
        "host": "localhost",
        "port": "993",
        # ssl | starttls | plain
        "security": "ssl",
        "verify_cert": "true",
        "timeout": "30",
    },
    "smtp": {
        "host": "localhost",
        "port": "587",
        # ssl | starttls | plain
        "security": "starttls",
        "verify_cert": "true",
        "auth": "true",
        "timeout": "30",
    },
    "branding": {
        "app_name": "Zoltis Mail",
        "company": "",
        "primary_color": "#0b57d0",
        # Restrict logins to these domains (comma separated). Empty = any.
        "allowed_domains": "",
        # Pre-filled domain on the login screen, e.g. example.com
        "default_domain": "",
    },
    "license": {
        "edition": "community",
        # Enterprise Edition license file.
        "key_file": "/etc/zoltis/license.key",
        # Community Edition: licensing portal that activates keys (blank = built-in default).
        # The key itself is entered on the setup screen, in Admin console > License,
        # with `zoltis license activate <KEY>`, or via the ZOLTIS_LICENSE_KEY env var.
        "server": "",
        "register_url": "",
        # Zoltis sign-up page linked from the admin console's Upgrade buttons.
        "upgrade_url": "",
        "timeout": "15",
    },
}


@dataclass
class Config:
    raw: dict = field(default_factory=dict)

    def get(self, section: str, key: str) -> str:
        env = os.environ.get(f"ZOLTIS_{section.upper()}_{key.upper()}")
        if env is not None:
            return env
        return self.raw.get(section, {}).get(key, DEFAULTS.get(section, {}).get(key, ""))

    def getint(self, section: str, key: str) -> int:
        return int(self.get(section, key))

    def getbool(self, section: str, key: str) -> bool:
        return self.get(section, key).strip().lower() in ("1", "true", "yes", "on")

    def getlist(self, section: str, key: str) -> list[str]:
        return [x.strip().lower() for x in self.get(section, key).split(",") if x.strip()]


def load(path: str | None = None) -> Config:
    raw: dict = {}
    candidates = [path, os.environ.get("ZOLTIS_CONFIG"), "/etc/zoltis/zoltis.ini"]
    for p in candidates:
        if p and os.path.isfile(p):
            cp = configparser.ConfigParser(interpolation=None)
            cp.read(p)
            raw = {s: dict(cp.items(s)) for s in cp.sections()}
            break
    return Config(raw)
