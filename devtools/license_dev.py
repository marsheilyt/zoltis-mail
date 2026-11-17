#!/usr/bin/env python3
"""License tooling for Zoltis staff, development and tests.

    python3 devtools/license_dev.py keygen
        New signing key pair. Put the PUBLIC key into zoltis/licensing.py
        (TRUSTED_KEYS) and keep the PRIVATE key only on the licensing portal.

    python3 devtools/license_dev.py issue --seed <hex> --kid k1 --domain acme.com [--domain ...]
                                          [--customer "Acme Ltd"] [--email a@acme.com] [--days 365]
        Issue a license key by hand (what the portal does on registration).

    python3 devtools/license_dev.py serve --seed <hex> --kid k1 [--port 8099]
        Run a mock licensing portal (POST /v1/activate, /v1/deactivate) for local testing.
        It's also a reference implementation of the API in docs/LICENSING.md.

NEVER ship a private key with the app.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zoltis import licensing as L  # noqa: E402


def keygen():
    seed = secrets.token_bytes(32)
    return seed.hex(), L.ed25519_public_key(seed).hex()


def issue_key(seed: bytes, kid: str, domains, customer="", email="", days=None, lid=None) -> str:
    now = int(time.time())
    payload = {"v": 1, "kid": kid, "lid": lid or "lic_" + secrets.token_hex(8), "edition": "community",
               "domains": sorted({d.lower() for d in domains}), "customer": customer, "email": email,
               "issued": now, "expires": now + days * 86400 if days else None}
    return L.encode_token(payload, seed, L.KEY_CONTEXT)


def issue_activation(seed: bytes, kid: str, lid: str, install_id: str, valid_days=30) -> str:
    now = int(time.time())
    return L.encode_token({"v": 1, "kid": kid, "lid": lid, "install_id": install_id, "status": "active",
                           "issued": now, "valid_until": now + valid_days * 86400}, seed, L.ACTIVATION_CONTEXT)


class MockPortal:
    """In-memory licensing portal. Policy: each key may be active on `max_installs` installs."""

    def __init__(self, seed: bytes, kid: str, max_installs=1, valid_days=30):
        self.seed, self.kid, self.max_installs, self.valid_days = seed, kid, max_installs, valid_days
        self.installs: dict[str, set] = {}   # lid -> install ids
        self.revoked: set[str] = set()
        self.calls: list[tuple] = []
        self.down = False

    def handle(self, path, body):
        self.calls.append((path, body))
        if self.down:
            return 503, {"error": "maintenance"}
        try:
            info = L.decode_token(body.get("license_key", ""), L.KEY_CONTEXT, {self.kid: L.ed25519_public_key(self.seed).hex()})
        except L.LicenseError as e:
            return 400, {"error": str(e), "code": "invalid"}
        lid, ins = info["lid"], str(body.get("install_id") or "")
        if path == "/v1/deactivate":
            self.installs.get(lid, set()).discard(ins)
            return 200, {"ok": True}
        if path != "/v1/activate":
            return 404, {"error": "not found"}
        if lid in self.revoked:
            return 403, {"error": "This license key has been revoked. Contact Zoltis support", "code": "revoked"}
        if info.get("expires") and time.time() > info["expires"]:
            return 403, {"error": "This license key has expired", "code": "expired"}
        if not ins.startswith("ins_"):
            return 400, {"error": "missing install_id", "code": "invalid"}
        used = self.installs.setdefault(lid, set())
        if ins not in used and len(used) >= self.max_installs:
            return 409, {"error": "This license key is already in use on another server. "
                                  "Release it on the licensing portal first", "code": "in_use"}
        used.add(ins)
        return 200, {"activation": issue_activation(self.seed, self.kid, lid, ins, self.valid_days)}

    def serve(self, host="127.0.0.1", port=0):
        portal = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                try:
                    body = json.loads(self.rfile.read(n) or b"{}")
                except ValueError:
                    body = {}
                status, out = portal.handle(self.path, body)
                data = json.dumps(out).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        httpd = ThreadingHTTPServer((host, port), H)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.httpd = httpd
        return f"http://{host}:{httpd.server_address[1]}"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    i = sub.add_parser("issue")
    s = sub.add_parser("serve")
    for p in (i, s):
        p.add_argument("--seed", required=True, help="private key (hex)")
        p.add_argument("--kid", default="k1")
    i.add_argument("--domain", action="append", required=True)
    i.add_argument("--customer", default="")
    i.add_argument("--email", default="")
    i.add_argument("--days", type=int)
    s.add_argument("--port", type=int, default=8099)
    s.add_argument("--max-installs", type=int, default=1)
    a = ap.parse_args(argv)
    if a.cmd == "keygen":
        priv, pub = keygen()
        print(f"private (keep secret, portal only): {priv}\npublic  (zoltis/licensing.py):     {pub}")
    elif a.cmd == "issue":
        print(issue_key(bytes.fromhex(a.seed), a.kid, a.domain, a.customer, a.email, a.days))
    else:
        url = MockPortal(bytes.fromhex(a.seed), a.kid, a.max_installs).serve(port=a.port)
        print(f"mock licensing portal on {url}  (set ZOLTIS_LICENSE_SERVER={url})")
        threading.Event().wait()


if __name__ == "__main__":
    main()
