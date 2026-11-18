#!/usr/bin/env python3
"""Local demo of the full Community Edition without Docker.

Emulates the bundled Postfix + Dovecot (devmail reads the files Zoltis Mail renders)
and ClamAV, then runs the web app in bundled mode.

    python3 devtools/demo.py      -> http://127.0.0.1:8080
    First run shows the setup screen; the setup code and a demo license key
    (for example.com, from an in-process mock licensing portal) are printed below.
    Classic webmail-only demo user: demo@example.com / demo
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import devmail  # noqa: E402
import license_dev  # noqa: E402
from zoltis import licensing  # noqa: E402

port = int(os.environ.get("PORT", "8080"))
data = os.environ.get("ZOLTIS_SERVER_DATA_DIR") or tempfile.mkdtemp(prefix="zoltis-")
conf = os.path.join(data, "mailconf")
devmail.STORE.conf_dir = conf
devmail.start(11143, 11587)
devmail.start_clamd(13310)


def _copy_sample(user):
    """Give every new demo mailbox some sample mail so the UI isn't empty."""
    src = devmail.STORE.boxes.get("demo@example.com")
    if src and user != "demo@example.com":
        for m in src["INBOX"].msgs:
            devmail.STORE.boxes[user]["INBOX"].add(m.raw, set(m.flags), m.when)


devmail.STORE.on_new_mailbox = _copy_sample
env = {
    "ZOLTIS_SERVER_PORT": str(port), "ZOLTIS_SERVER_LISTEN": "127.0.0.1", "ZOLTIS_SERVER_DATA_DIR": data,
    "ZOLTIS_IMAP_HOST": "127.0.0.1", "ZOLTIS_IMAP_PORT": "11143", "ZOLTIS_IMAP_SECURITY": "plain",
    "ZOLTIS_SMTP_HOST": "127.0.0.1", "ZOLTIS_SMTP_PORT": "11587", "ZOLTIS_SMTP_SECURITY": "plain",
    "ZOLTIS_MAIL_SERVER_MODE": "bundled", "ZOLTIS_MAIL_SERVER_CONF_DIR": conf,
    "ZOLTIS_MAIL_SERVER_IMAP_HOST": "127.0.0.1", "ZOLTIS_MAIL_SERVER_IMAP_PORT": "11143",
    "ZOLTIS_MAIL_SERVER_SMTP_HOST": "127.0.0.1", "ZOLTIS_MAIL_SERVER_SMTP_PORT": "11587",
    "ZOLTIS_MAIL_SERVER_HOSTNAME": "mail.example.com", "ZOLTIS_MAIL_SERVER_PUBLIC_IP": "203.0.113.25",
    "ZOLTIS_SETUP_TOKEN": "DEMO1234",
    "ZOLTIS_INTEGRITY_ENFORCE": "false",               # a source checkout is never a signed release
    "ZOLTIS_MAIL_SERVER_INTERNAL_SECURITY": "plain",   # the emulated mail server has no TLS
    "ZOLTIS_ANTIVIRUS_ENABLED": "true", "ZOLTIS_ANTIVIRUS_SOCKET": "-", "ZOLTIS_ANTIVIRUS_HOST": "127.0.0.1",
    "ZOLTIS_ANTIVIRUS_PORT": "13310",
}
os.environ.update({k: v for k, v in env.items() if k not in os.environ})
# Demo licensing: a throwaway signing key trusted only by this process + a mock portal.
_seed_path = os.path.join(data, "demo-license.seed")   # stable across restarts of the same data dir
if not os.path.exists(_seed_path):
    with open(_seed_path, "w") as f:
        f.write(os.urandom(32).hex())
_seed = bytes.fromhex(open(_seed_path).read().strip())
licensing.TRUSTED_KEYS["demo"] = licensing.ed25519_public_key(_seed).hex()
os.environ["ZOLTIS_LICENSE_SERVER"] = license_dev.MockPortal(_seed, "demo", max_installs=100).serve()
_key = license_dev.issue_key(_seed, "demo", ["example.com"], customer="Demo Company", email="admin@example.com")
print(f"Demo: http://127.0.0.1:{port}   setup code: {os.environ['ZOLTIS_SETUP_TOKEN']}   data: {data}")
print(f"Demo license key (example.com):\n{_key}")
from zoltis.__main__ import main  # noqa: E402
main(["serve"])
