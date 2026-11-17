"""Community Edition license keys.

Every install needs a license key before it can create email accounts or add
domains. Customers get a free key by registering on the Zoltis licensing
portal (SaaS). The flow:

  1. Registration on the portal issues a *license key* naming the customer's
     mail domain(s). The key is signed with Zoltis' private Ed25519 key, so the
     app can check it offline and nobody can forge or edit one (e.g. add a
     domain).
  2. The admin enters the key (setup screen, admin console, CLI or the
     ZOLTIS_LICENSE_KEY env var). The app sends it once to the portal's
     /v1/activate endpoint together with this install's random install ID.
     The portal answers with a signed *activation certificate* for that
     install, valid for a limited time (e.g. 30 days).
  3. The app re-activates in the background every day, which renews the
     certificate. If the portal revokes the key or refuses the install, the
     renewal fails and the certificate is dropped. If the portal is just
     unreachable, the current certificate keeps working until it expires.

Without an active license, existing mailboxes keep sending and receiving mail;
only creating accounts and adding domains is blocked.

Key / certificate wire format:  ZM1.<base64url(json payload)>.<base64url(signature)>
The signature covers  b"zoltis-license-v1\\n" + payload  (keys) or
b"zoltis-activation-v1\\n" + payload  (activation certificates).
See docs/LICENSING.md for the portal API contract.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import threading
import time
import urllib.error
import urllib.request

log = logging.getLogger("zoltis.license")

# Public halves of the Zoltis licensing signing keys, by key id ("kid").
# Generate a key pair with  python3 devtools/license_dev.py keygen  and paste the
# public key here. Keep the private key only on the licensing portal.
TRUSTED_KEYS: dict[str, str] = {
    # "k1": "<64 hex chars>",
}
# Placeholders: replace with the real portal URLs before release.
DEFAULT_SERVER = "https://licensing.zoltis.example"
DEFAULT_REGISTER_URL = "https://licensing.zoltis.example/register"
# Zoltis sign-up page for the paid managed plans (a separate product; Community only links to it).
DEFAULT_UPGRADE_URL = "https://licensing.zoltis.example/upgrade"

PREFIX = "ZM1"
KEY_CONTEXT = b"zoltis-license-v1\n"
ACTIVATION_CONTEXT = b"zoltis-activation-v1\n"
REFRESH_SECONDS = 24 * 3600
RETRY_SECONDS = 15 * 60


class LicenseError(Exception):
    """A key is malformed, forged, expired or was refused by the portal."""


# ---------------------------------------------------------------------------
# Ed25519 (RFC 8032), standard library only. Verification is what the app
# needs; signing is used by devtools/license_dev.py and the tests.
# ---------------------------------------------------------------------------
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)
_ZERO = (0, 1, 1, 0)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, p):
    q = _ZERO
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _same(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _compress(p):
    zi = _inv(p[2])
    x, y = p[0] * zi % _P, p[1] * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _h(*parts) -> int:
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def _expand(seed: bytes):
    if len(seed) != 32:
        raise ValueError("Ed25519 private key must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a = (a & ((1 << 254) - 8)) | (1 << 254)
    return a, h[32:]


def ed25519_public_key(seed: bytes) -> bytes:
    return _compress(_mul(_expand(seed)[0], _G))


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(seed)
    pub = _compress(_mul(a, _G))
    r = _h(prefix, msg) % _L
    big_r = _compress(_mul(r, _G))
    s = (r + _h(big_r, pub, msg) % _L * a) % _L
    return big_r + s.to_bytes(32, "little")


def ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(pub) != 32 or len(sig) != 64:
        return False
    a, r = _decompress(pub), _decompress(sig[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = _h(sig[:32], pub, msg) % _L
    return _same(_mul(s, _G), _add(r, _mul(k, a)))


# ---------------------------------------------------------------------------
# Signed tokens (keys and activation certificates)
# ---------------------------------------------------------------------------
def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def encode_token(payload: dict, seed: bytes, context: bytes) -> str:
    """Sign a payload. Used by the licensing portal (and devtools/tests), never by the app."""
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return f"{PREFIX}.{_b64e(body)}.{_b64e(ed25519_sign(seed, context + body))}"


def decode_token(token: str, context: bytes, keys: dict | None = None) -> dict:
    """Check the signature and return the payload. Raises LicenseError."""
    keys = TRUSTED_KEYS if keys is None else keys
    token = "".join((token or "").split())  # tolerate line breaks/spaces from copy-paste
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        raise LicenseError("That doesn't look like a Zoltis Mail license key")
    try:
        body, sig = _b64d(parts[1]), _b64d(parts[2])
        payload = json.loads(body)
    except (ValueError, TypeError):
        raise LicenseError("The license key is damaged. Copy it again from the licensing portal")
    if not isinstance(payload, dict):
        raise LicenseError("The license key is damaged")
    pub = keys.get(str(payload.get("kid", "")))
    if not pub:
        raise LicenseError("The license key was signed with an unknown key. Update Zoltis Mail or get a new key")
    if not ed25519_verify(bytes.fromhex(pub), context + body, sig):
        raise LicenseError("The license key is not genuine (signature check failed)")
    return payload


def parse_key(key: str, now: float | None = None) -> dict:
    p = decode_token(key, KEY_CONTEXT)
    domains = p.get("domains")
    if p.get("v") != 1 or not p.get("lid") or not isinstance(domains, list) or not domains:
        raise LicenseError("The license key is missing required information")
    p["domains"] = sorted({str(d).strip().lower().rstrip(".") for d in domains if str(d).strip()})
    if p.get("edition", "community") != "community":
        raise LicenseError("This key is not for the Community Edition")
    exp = p.get("expires")
    if exp and (now or time.time()) > float(exp):
        raise LicenseError("This license key has expired. Get a new one from the licensing portal")
    return p


# ---------------------------------------------------------------------------
# License state for one install
# ---------------------------------------------------------------------------
class LicenseRequired(Exception):
    """Raised when an action needs an active license that covers the domain."""


class LicenseManager:
    """Holds the key + activation certificate stored in the data directory."""

    def __init__(self, cfg, data_dir: str):
        self.cfg = cfg
        self.data_dir = data_dir
        self.lock = threading.RLock()
        self.key_path = os.path.join(data_dir, "license.key")
        self.cert_path = os.path.join(data_dir, "license.activation")
        self.install_id = self._install_id()
        self.key: str | None = None
        self.info: dict | None = None
        self.cert: dict | None = None
        self.problem: str | None = None   # last permanent problem, shown to admins
        self.last_check: float | None = None
        self._thread = None
        self._stamp = None
        self._load()

    # -- config / storage -------------------------------------------------
    @property
    def server(self) -> str:
        return (self.cfg.get("license", "server") or DEFAULT_SERVER).rstrip("/")

    @property
    def register_url(self) -> str:
        return self.cfg.get("license", "register_url") or DEFAULT_REGISTER_URL

    @property
    def upgrade_url(self) -> str:
        """Zoltis sign-up page, pre-filled with this install's license so the portal can link
        the new subscription to the existing customer and domains."""
        from urllib.parse import urlencode
        base = self.cfg.get("license", "upgrade_url") or DEFAULT_UPGRADE_URL
        q = {"from": "community"}
        if self.info:
            q["license"] = self.info["lid"]
            q["domains"] = ",".join(self.info["domains"])
        return base + ("&" if "?" in base else "?") + urlencode(q)

    def _install_id(self) -> str:
        path = os.path.join(self.data_dir, "install.id")
        try:
            with open(path) as f:
                v = f.read().strip()
            if v:
                return v
        except OSError:
            pass
        v = "ins_" + secrets.token_hex(16)
        self._write(path, v)
        return v

    @staticmethod
    def _write(path, text):
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)

    def _file_stamp(self):
        out = []
        for p in (self.key_path, self.cert_path):
            try:
                st = os.stat(p)
                out.append((st.st_mtime_ns, st.st_size))
            except OSError:
                out.append(None)
        return tuple(out)

    def _reload_if_changed(self):
        """Pick up a key activated by the CLI (another process) without a restart."""
        stamp = self._file_stamp()
        if stamp != self._stamp:
            with self.lock:
                self.key = self.info = self.cert = None
                self.problem = None
                self._load()

    def _load(self):
        self._stamp = self._file_stamp()
        try:
            with open(self.key_path) as f:
                key = f.read().strip()
        except OSError:
            return
        try:
            self.info, self.key = parse_key(key), key
        except LicenseError as e:
            self.problem = str(e)
            self.key = key
            return
        try:
            with open(self.cert_path) as f:
                self.cert = self._check_cert(f.read().strip(), self.info)
        except OSError:
            pass
        except LicenseError as e:
            log.warning("stored license activation is not usable: %s", e)

    def _check_cert(self, token: str, info: dict, now: float | None = None) -> dict:
        c = decode_token(token, ACTIVATION_CONTEXT)
        if c.get("lid") != info["lid"] or c.get("install_id") != self.install_id:
            raise LicenseError("The activation belongs to a different key or server")
        if c.get("status", "active") != "active":
            raise LicenseError("The licensing portal reports this license as " + str(c.get("status")))
        c["_token"] = token
        return c

    # -- state ------------------------------------------------------------
    def _cert_valid(self, now=None) -> bool:
        return bool(self.cert) and (now or time.time()) < float(self.cert.get("valid_until") or 0)

    def state(self) -> str:
        self._reload_if_changed()
        if not self.key:
            return "missing"
        if not self.info:
            return "invalid"
        exp = self.info.get("expires")
        if exp and time.time() > float(exp):
            return "expired"
        if self._cert_valid():
            return "active"
        return "inactive" if self.cert is None else "lapsed"

    @property
    def active(self) -> bool:
        return self.state() == "active"

    @property
    def domains(self) -> list[str]:
        return list(self.info["domains"]) if self.info else []

    def covers(self, domain: str) -> bool:
        return (domain or "").lower().rstrip(".") in self.domains

    def require(self, domain: str | None = None):
        """Raise LicenseRequired unless new accounts/domains may be created (for `domain`)."""
        st = self.state()
        if st != "active":
            msg = {
                "missing": "Enter your license key before creating email accounts. "
                           f"Register for a free key at {self.register_url}",
                "invalid": f"The license key isn't valid ({self.problem}). Enter a new key in Admin console > License",
                "expired": "Your license key has expired. Enter a new key in Admin console > License",
                "inactive": "Your license key hasn't been activated yet. Open Admin console > License and activate it",
                "lapsed": "This server couldn't confirm its license with the licensing portal. "
                          "Check the server's internet connection, then click 'Check now' in Admin console > License",
            }[st]
            if self.problem and st in ("inactive", "lapsed"):
                msg = f"License not active: {self.problem}"
            raise LicenseRequired(msg)
        if domain is not None and not self.covers(domain):
            raise LicenseRequired(f"Your license covers {', '.join(self.domains)} only. "
                                  f"Add {domain} to your registration on the licensing portal, then enter the new key")

    def public(self, full: bool = False) -> dict:
        st = self.state()
        out = {"state": st, "active": self.active, "domains": self.domains, "register_url": self.register_url,
               "upgrade_url": self.upgrade_url}
        if full:
            info = self.info or {}
            out.update({
                "license_id": info.get("lid"), "customer": info.get("customer"), "email": info.get("email"),
                "issued": info.get("issued"), "expires": info.get("expires"), "install_id": self.install_id,
                "activated_until": (self.cert or {}).get("valid_until"), "last_check": self.last_check,
                "problem": self.problem, "server": self.server,
                "key_hint": (self.key[:10] + "…" + self.key[-6:]) if self.key else None,
            })
        return out

    # -- talking to the portal ------------------------------------------
    def _call(self, path: str, body: dict) -> dict:
        from . import __version__
        req = urllib.request.Request(self.server + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": f"ZoltisMail/{__version__}"})
        timeout = float(self.cfg.get("license", "timeout") or 15)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read() or b"{}")
            except ValueError:
                err = {}
            if 400 <= e.code < 500:
                raise LicenseError(err.get("error") or f"The licensing portal refused the key (HTTP {e.code})")
            raise ConnectionError(f"licensing portal error HTTP {e.code}")
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise ConnectionError(f"can't reach the licensing portal at {self.server}: {e}")

    def _activate_remote(self, key: str, info: dict) -> dict:
        import platform
        from . import __version__
        r = self._call("/v1/activate", {"license_key": key, "install_id": self.install_id,
                                        "app_version": __version__, "hostname": platform.node()})
        token = r.get("activation")
        if not token:
            raise ConnectionError("the licensing portal sent an unexpected answer")
        return self._check_cert(token, info)

    def activate(self, key: str) -> dict:
        """Check a new key, activate it with the portal and store it. Raises LicenseError."""
        key = "".join((key or "").split())
        info = parse_key(key)
        try:
            cert = self._activate_remote(key, info)
        except ConnectionError as e:
            raise LicenseError(f"The key is genuine, but activation failed: {e}. "
                               "The server needs internet access to activate its license")
        with self.lock:
            old = self.key
            self._write(self.key_path, key)
            self._write(self.cert_path, cert["_token"])
            self.key, self.info, self.cert, self.problem, self.last_check = key, info, cert, None, time.time()
            self._stamp = self._file_stamp()
        if old and old != key:
            self._deactivate_quietly(old)
        log.info("license %s activated for %s (valid until %s)", info["lid"], ", ".join(info["domains"]),
                 time.strftime("%Y-%m-%d", time.gmtime(float(cert.get("valid_until") or 0))))
        return self.public(full=True)

    def _deactivate_quietly(self, old_key):
        try:
            self._call("/v1/deactivate", {"license_key": old_key, "install_id": self.install_id})
        except Exception as e:  # noqa: BLE001  - best effort; the portal can expire it on its own
            log.info("could not release the previous license key: %s", e)

    def refresh(self) -> dict:
        """Renew the activation. Network trouble keeps the current certificate."""
        with self.lock:
            key, info = self.key, self.info
        if not key or not info:
            return self.public(full=True)
        try:
            cert = self._activate_remote(key, info)
        except LicenseError as e:  # revoked / refused: stop treating the install as licensed
            with self.lock:
                self.cert, self.problem, self.last_check = None, str(e), time.time()
                try:
                    os.remove(self.cert_path)
                except OSError:
                    pass
                self._stamp = self._file_stamp()
            log.error("license refused by the licensing portal: %s", e)
            raise
        with self.lock:
            self._write(self.cert_path, cert["_token"])
            self.cert, self.problem, self.last_check = cert, None, time.time()
            self._stamp = self._file_stamp()
        return self.public(full=True)

    # -- background renewal ---------------------------------------------
    def start(self):
        """Activate a key given in ZOLTIS_LICENSE_KEY and keep the activation renewed."""
        if self._thread:
            return
        self._thread = threading.Thread(target=self._loop, name="license", daemon=True)
        self._thread.start()

    def _loop(self):
        env_key = "".join((os.environ.get("ZOLTIS_LICENSE_KEY") or "").split())
        if env_key and env_key != self.key:
            try:
                self.activate(env_key)
            except LicenseError as e:
                self.problem = str(e)
                log.error("ZOLTIS_LICENSE_KEY could not be activated: %s", e)
        while True:
            wait = REFRESH_SECONDS
            if self.key and self.info and (self.last_check is None or time.time() - self.last_check >= REFRESH_SECONDS):
                try:
                    self.refresh()
                except LicenseError:
                    pass
                except ConnectionError as e:
                    log.warning("license renewal postponed: %s", e)
                    wait = RETRY_SECONDS
            if self.state() == "missing":
                log.warning("NO LICENSE KEY: creating email accounts is disabled. Register for a free key at %s",
                            self.register_url)
            time.sleep(wait)
