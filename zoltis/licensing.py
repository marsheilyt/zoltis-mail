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
# Zoltis Mail website: customers sign in, open My account -> License keys -> Community Edition, enter the
# server's IP address and copy the key. The licensing API that activates keys runs on its own host name.
SITE = "https://zoltismail.com"
DEFAULT_SERVER = "https://licensing.zoltismail.com"
DEFAULT_REGISTER_URL = SITE + "/account/licenses"
# Zoltis sign-up page for the paid managed plans (a separate product; Community only links to it).
DEFAULT_UPGRADE_URL = SITE + "/upgrade"
# From 2.3.0 every server needs a license key: GRACE_DAYS after it first starts on 2.3.0 or later.
GRACE_DAYS = 7
VALID_DAYS = 365   # a Community key is valid for one year from activation, then renewed (free) on zoltismail.com

PREFIX = "ZM1"
KEY_CONTEXT = b"zoltis-license-v1\n"
ACTIVATION_CONTEXT = b"zoltis-activation-v1\n"
REFRESH_SECONDS = 24 * 3600
# Subscription terms (sent by the licensing portal / ZOcc inside the signed activation certificate):
#   community : free, renewed once a year on the portal. The same key keeps working; only the
#               "paid_until" date moves. After that date no new accounts or domains until renewed.
#   managed   : monthly. "paid_until" is the invoice due date. If unpaid GRACE_DAYS after it,
#               the service is suspended: nobody can sign in (webmail, IMAP, SMTP) until ZOcc
#               sends status "active" again. Incoming mail keeps being stored, so nothing is lost.
GRACE_DAYS_MANAGED = 10
RENEW_WARN_DAYS = 30
SUSPENDED_MESSAGE = ("This mail service is suspended because the subscription payment is overdue. "
                     "Your mail is safe and new mail is still being received. To restore access, "
                     "contact Zoltis through the customer portal.")
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


def _norm_ip(ip) -> str | None:
    import ipaddress
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        return None


def parse_key(key: str, now: float | None = None) -> dict:
    p = decode_token(key, KEY_CONTEXT)
    domains = p.get("domains")
    if p.get("v") != 1 or not p.get("lid") or not isinstance(domains, list) or not domains:
        raise LicenseError("The license key is missing required information")
    p["domains"] = sorted({str(d).strip().lower().rstrip(".") for d in domains if str(d).strip()})
    ips = [x for x in (_norm_ip(i) for i in (p.get("ips") or [])) if x]
    if not ips:
        raise LicenseError("This key isn't tied to a server IP address. Get a new key on zoltismail.com "
                           "(My account > License keys > Community Edition) and enter this server's IP")
    p["ips"] = sorted(set(ips))
    if p.get("edition", "community") not in ("community", "managed"):
        raise LicenseError("This key is not for this edition of Zoltis Mail")
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
        # New on every start and never written to disk: a cloned data volume (same install_id) running on a
        # second server checks in with a different instance_id, so the portal can see two copies of one install.
        self.instance_id = os.urandom(8).hex()
        self.public_ip: str | None = None   # this server's public IP (set by the app from PUBLIC_IP)
        self.grace_start = self._grace_start()
        self.edition = "community"   # set by the app: "community" or "enterprise"; reported to the portal
        self.key: str | None = None
        self.info: dict | None = None
        self.cert: dict | None = None
        self.problem: str | None = None   # last permanent problem, shown to admins
        self.last_check: float | None = None
        self._thread = None
        self._stamp = None
        self.on_change = None   # called with (locked: bool) when the service gets suspended or restored
        self.integrity: dict = {}        # set by integrity.IntegrityMonitor; sent with every check-in
        self.integrity_locked = False    # core files changed (or not an official build) and enforcement on
        self._load()
        self._was_locked = self.locked

    # -- config / storage -------------------------------------------------
    @property
    def server(self) -> str:
        return (self.cfg.get("license", "server") or DEFAULT_SERVER).rstrip("/")

    @property
    def enabled(self) -> bool:
        """False (the default for now) turns license enforcement off: no key is needed, nothing
        is sent to the licensing portal, and accounts/domains can be created freely.
        Turn it on with [license] required = true or ZOLTIS_LICENSE_REQUIRED=true."""
        return self.cfg.getbool("license", "required")

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

    def _grace_start(self) -> float:
        """When this server first ran 2.3.0 or later: the 7-day registration period starts here."""
        path = os.path.join(self.data_dir, "license.grace")
        try:
            with open(path) as f:
                return float(f.read().strip())
        except (OSError, ValueError):
            now = float(int(time.time()))
            try:
                self._write(path, str(int(now)))
            except OSError:
                pass
            return now

    @property
    def grace_days(self) -> int:
        try:
            return max(0, int(self.cfg.get("license", "grace_days") or GRACE_DAYS))
        except ValueError:
            return GRACE_DAYS

    @property
    def grace_until(self) -> float:
        return self.grace_start + self.grace_days * 86400

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
        if c.get("ip") and _norm_ip(c["ip"]) not in info.get("ips", []):
            raise LicenseError("The activation is for a different server IP address")
        if c.get("status", "active") not in ("active", "overdue", "suspended"):
            raise LicenseError("The licensing portal reports this license as " + str(c.get("status")))
        c["_token"] = token
        return c

    # -- state ------------------------------------------------------------
    def _cert_valid(self, now=None) -> bool:
        return bool(self.cert) and (now or time.time()) < float(self.cert.get("valid_until") or 0)

    def billing(self, now: float | None = None) -> dict:
        """Subscription status from the signed activation certificate.

        status: ok | renew_soon | renewal_due (community)  ·  ok | overdue | suspended (managed)
        """
        now = now or time.time()
        c = self.cert or {}
        plan = c.get("plan") or (self.info or {}).get("edition") or "community"
        plan = "managed" if plan == "managed" else "community"
        paid_until = float(c["paid_until"]) if c.get("paid_until") else None
        grace = int(c.get("grace_days", GRACE_DAYS_MANAGED if plan == "managed" else 0))
        lock_at = paid_until + grace * 86400 if (plan == "managed" and paid_until) else None
        portal = c.get("status", "active")
        fresh = self._cert_valid(now)
        if plan == "managed":
            if portal == "suspended" or (lock_at and now >= lock_at and (portal == "overdue" or not fresh)):
                status = "suspended"
            elif portal == "overdue" or (paid_until and now > paid_until and not fresh):
                status = "overdue"
            else:
                status = "ok"
        else:
            if paid_until and now > paid_until:
                status = "renewal_due"
            elif paid_until and paid_until - now < RENEW_WARN_DAYS * 86400:
                status = "renew_soon"
            else:
                status = "ok"
        return {"plan": plan, "status": status, "paid_until": paid_until, "lock_at": lock_at,
                "days_left": int((paid_until - now) // 86400) if paid_until else None}

    @property
    def unpaid(self) -> bool:
        """Managed plan suspended for non-payment."""
        return bool(self.cert) and self.billing()["status"] == "suspended"

    @property
    def locked(self) -> bool:
        """True when all sign-ins are refused: unpaid managed plan, or modified program files."""
        return self.integrity_locked or self.unpaid

    @property
    def lock_message(self) -> str:
        from .integrity import MODIFIED_MESSAGE
        return MODIFIED_MESSAGE if self.integrity_locked else SUSPENDED_MESSAGE

    def _notify(self):
        locked = self.locked
        if locked != getattr(self, "_was_locked", False):
            self._was_locked = locked
            log.warning("mail service %s", ("LOCKED: program files were modified" if self.integrity_locked
                                             else "SUSPENDED for non-payment") if locked else "restored")
            if self.on_change:
                try:
                    self.on_change(locked)
                except Exception:  # noqa: BLE001
                    log.exception("could not apply the suspension change")

    def state(self) -> str:
        if self.integrity_locked:
            return "modified"
        if self.unpaid:
            return "suspended"
        if not self.enabled:
            return "disabled"
        self._reload_if_changed()
        if not self.key:
            return "grace" if time.time() < self.grace_until else "missing"
        if not self.info:
            return "invalid"
        exp = self.info.get("expires")
        if exp and time.time() > float(exp):
            return "expired"
        if self._cert_valid():
            return "renewal_due" if self.billing()["status"] == "renewal_due" else "active"
        return "inactive" if self.cert is None else "lapsed"

    @property
    def active(self) -> bool:
        return self.state() in ("active", "disabled", "grace")

    @property
    def domains(self) -> list[str]:
        return list(self.info["domains"]) if self.info else []

    def covers(self, domain: str) -> bool:
        return (domain or "").lower().rstrip(".") in self.domains

    def require(self, domain: str | None = None):
        """Raise LicenseRequired unless new accounts/domains may be created (for `domain`)."""
        if not self.enabled:
            return
        st = self.state()
        if st == "grace":               # first 7 days: everything works while the admin gets a key
            return
        if st != "active":
            msg = {
                "missing": "Add your license key to keep creating email accounts and domains. Get it free on "
                           f"{self.register_url} (My account > License keys > Community Edition, enter this server's IP "
                           f"{self.public_ip or 'address'}), then paste it in Admin console > License",
                "invalid": f"The license key isn't valid ({self.problem}). Enter a new key in Admin console > License",
                "expired": "Your license key has expired. Enter a new key in Admin console > License",
                "inactive": "Your license key hasn't been activated yet. Open Admin console > License and activate it",
                "lapsed": "This server couldn't confirm its license with the licensing portal. "
                          "Check the server's internet connection, then click 'Check now' in Admin console > License",
                "renewal_due": "Your yearly license renewal is due. Renew it (free) on the licensing portal; "
                               "your key stays the same. Then click 'Check now' in Admin console > License",
                "suspended": SUSPENDED_MESSAGE,
                "modified": self.lock_message,
            }[st]
            if self.problem and st in ("inactive", "lapsed"):
                msg = f"License not active: {self.problem}"
            raise LicenseRequired(msg)
        if domain is not None and not self.covers(domain):
            raise LicenseRequired(f"Your license covers {', '.join(self.domains)} only. "
                                  f"Add {domain} to your registration on the licensing portal, then enter the new key")

    def public(self, full: bool = False) -> dict:
        st = self.state()
        out = {"state": st, "active": self.active, "required": self.enabled, "domains": self.domains, "register_url": self.register_url,
               "grace_until": self.grace_until if not self.key else None, "server_ip": self.public_ip,
               "ips": (self.info or {}).get("ips", []),
               "upgrade_url": self.upgrade_url, "suspended": self.locked}
        if self.locked:
            out["message"] = self.lock_message
        if self.cert:
            out["billing"] = self.billing()
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
        # Also the daily "this server is live" check-in. Only these fields are sent: no accounts, mail or usage.
        r = self._call("/v1/activate", {"license_key": key, "license_id": info.get("lid"),
                                        "install_id": self.install_id, "instance_id": self.instance_id,
                                        "edition": self.edition,
                                        "app_version": __version__, "hostname": platform.node(),
                                        # code integrity: ok | modified | unsigned, fingerprint, changed file names
                                        "integrity": self.integrity or None,
                                        "server_ip": self.public_ip or None})
        token = r.get("activation")
        if not token:
            raise ConnectionError("the licensing portal sent an unexpected answer")
        return self._check_cert(token, info)

    def activate(self, key: str) -> dict:
        """Check a new key, activate it with the portal and store it. Raises LicenseError.

        The key names the server IP(s) entered on zoltismail.com. A known public IP that isn't listed is refused
        here; the licensing server then checks the address the request really comes from.
        """
        key = "".join((key or "").split())
        info = parse_key(key)
        mine = _norm_ip(self.public_ip) if self.public_ip else None
        if mine and mine not in info["ips"]:
            raise LicenseError(f"This key is for server IP {', '.join(info['ips'])}, but this server's IP is {mine}. "
                               "Update the server IP in your account on zoltismail.com and copy the new key")
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
        self._notify()
        self.start()   # keep the daily check-in going (also when licensing isn't required)
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
            self._notify()
            raise
        with self.lock:
            self._write(self.cert_path, cert["_token"])
            self.cert, self.problem, self.last_check = cert, None, time.time()
            self._stamp = self._file_stamp()
        self._notify()
        return self.public(full=True)

    def report_soon(self):
        """Check in right away (in the background), e.g. when the code integrity status changes."""
        if not (self.key and self.info):
            return

        def run():
            try:
                self.refresh()
            except Exception as e:  # noqa: BLE001
                log.info("integrity report postponed to the next check-in: %s", e)
        threading.Thread(target=run, name="license-report", daemon=True).start()

    # -- background renewal ---------------------------------------------
    def start(self):
        """Activate a key given in ZOLTIS_LICENSE_KEY and keep the activation renewed.

        Runs when licensing is required, and also when it isn't but a key has been entered: then the
        daily check-in still tells the portal this server is live, but nothing is ever blocked.
        """
        has_key = bool(self.key or (os.environ.get("ZOLTIS_LICENSE_KEY") or "").strip())
        if self._thread or not (self.enabled or has_key):
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
            # Check in once a day; every 15 min while suspended, so an unlock from ZOcc applies quickly.
            every = RETRY_SECONDS if self.locked else REFRESH_SECONDS
            wait = min(every, 3600)   # re-check the due date hourly even if the portal is unreachable
            if self.key and self.info and (self.last_check is None or time.time() - self.last_check >= every):
                try:
                    self.refresh()
                except LicenseError:
                    pass
                except ConnectionError as e:
                    log.warning("license renewal postponed: %s", e)
                    wait = RETRY_SECONDS
            self._notify()
            if self.enabled and self.state() == "missing":
                log.warning("NO LICENSE KEY: creating email accounts is disabled. Register for a free key at %s",
                            self.register_url)
            time.sleep(wait)
