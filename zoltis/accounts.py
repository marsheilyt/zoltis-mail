"""Account database for the admin console (SQLite, standard library).

The database is the source of truth for domains, mailboxes and aliases.
After every change the mail-server backend (mailserver.py) re-renders the
files Dovecot and Postfix read.

Two modes ([mail_server] mode):
  bundled  - Zoltis Mail runs its own Postfix + Dovecot. Accounts created here
             are real mailboxes with passwords and a storage quota.
  external - Mail accounts live on another server. The admin console only
             controls which accounts may use the webmail (seat limit).
"""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
import subprocess
import threading
import time

LOCAL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?$")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
RESERVED_LOCALS = {"zoltis-master"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS domains (
    name TEXT PRIMARY KEY,
    created INTEGER NOT NULL,
    dkim_selector TEXT,
    dkim_public TEXT
);
CREATE TABLE IF NOT EXISTS accounts (
    email TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    pw_hash TEXT,
    quota_mb INTEGER NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    created INTEGER NOT NULL,
    last_login INTEGER
);
CREATE TABLE IF NOT EXISTS aliases (
    source TEXT PRIMARY KEY,
    destinations TEXT NOT NULL,
    created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_acceptance (
    version TEXT NOT NULL,
    email TEXT NOT NULL,
    accepted_at INTEGER NOT NULL,
    ip TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit (
    ts INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT ''
);
"""


# Columns added after 2.0.0 (existing databases are upgraded on start).
MIGRATIONS = [
    ("totp_secret", "TEXT"),        # two-step verification secret (None = off)
    ("totp_last", "INTEGER"),       # last accepted TOTP time step (blocks code reuse)
    ("recovery_codes", "TEXT"),     # comma-separated SHA-256 of unused recovery codes
    ("app_pw_hash", "TEXT"),        # password for mail apps (IMAP/SMTP), SHA512-CRYPT
    ("app_pw_created", "INTEGER"),
]
DOMAIN_MIGRATIONS = [
    # MTA-STS policy published for the domain: off | testing | enforce (+ policy id for the TXT record)
    ("mta_sts", "TEXT NOT NULL DEFAULT 'testing'"),
    ("mta_sts_id", "TEXT NOT NULL DEFAULT ''"),
]
MTA_STS_MODES = ("off", "testing", "enforce")


class AccountError(Exception):
    """User-facing validation error."""


class LimitReached(AccountError):
    pass


class PoliciesRequired(AccountError):
    """The current Community Edition policies haven't been accepted yet."""


class NotLicensed(AccountError):
    """No active license, or the license doesn't cover the domain."""


def hash_password(password: str) -> str:
    """SHA512-CRYPT, the scheme Dovecot verifies natively ({SHA512-CRYPT}$6$...)."""
    salt = secrets.token_urlsafe(12)[:16].replace("-", "a").replace("_", "b")
    r = subprocess.run(["openssl", "passwd", "-6", "-salt", salt, "-stdin"], input=password.encode(),
                       capture_output=True, check=True, timeout=10)
    return "{SHA512-CRYPT}" + r.stdout.decode().strip()


def verify_password(password: str, stored: str) -> bool:
    if not stored or not stored.startswith("{SHA512-CRYPT}$6$"):
        return False
    h = stored[len("{SHA512-CRYPT}"):]
    salt = h.split("$")[2]
    r = subprocess.run(["openssl", "passwd", "-6", "-salt", salt, "-stdin"], input=password.encode(),
                       capture_output=True, timeout=10)
    return secrets.compare_digest(r.stdout.decode().strip(), h)


def check_password_strength(pw: str, email: str = ""):
    if len(pw) < 8:
        raise AccountError("Password must be at least 8 characters")
    if len(pw) > 256:
        raise AccountError("Password is too long")
    if email and pw.lower() in (email.lower(), email.split("@")[0].lower()):
        raise AccountError("Password can't be the same as the email address")
    if pw.lower() in ("password", "12345678", "123456789", "qwertyui", "password1", "iloveyou"):
        raise AccountError("Password is too common")
    if any(c in pw for c in ":\n\r\0"):
        raise AccountError("Password contains characters that aren't allowed (: or line breaks)")


class AccountDB:
    def __init__(self, path: str, limits: dict, mode: str = "bundled", license=None):
        self.path = path
        self.license = license  # licensing.LicenseManager; None = no license check
        self.limits = limits
        self.mode = mode
        self.lock = threading.RLock()
        new = not os.path.exists(path)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(accounts)")}
        for col, typ in MIGRATIONS:
            if col not in cols:
                self.db.execute(f"ALTER TABLE accounts ADD COLUMN {col} {typ}")
        dcols = {r[1] for r in self.db.execute("PRAGMA table_info(domains)")}
        for col, typ in DOMAIN_MIGRATIONS:
            if col not in dcols:
                self.db.execute(f"ALTER TABLE domains ADD COLUMN {col} {typ}")
        if new:
            os.chmod(path, 0o600)

    # -------------------------------------------------------------- helpers
    def _q(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def _x(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args)

    def audit(self, actor, action, target=""):
        self._x("INSERT INTO audit(ts, actor, action, target) VALUES (?,?,?,?)", (int(time.time()), actor, action, target))

    def audit_log(self, limit=200):
        return [dict(r) for r in self._q("SELECT * FROM audit ORDER BY ts DESC LIMIT ?", (limit,))]

    # -------------------------------------------------------------- policies (Community Edition)
    # Version the admin must have accepted before accounts or domains can be created (None = not needed).
    policy_version: str | None = None

    def policy_status(self) -> dict:
        r = self._q("SELECT * FROM policy_acceptance WHERE version = ? ORDER BY accepted_at LIMIT 1",
                    (self.policy_version or "",))
        a = dict(r[0]) if r else None
        return {"required": bool(self.policy_version), "version": self.policy_version,
                "accepted": bool(a) or not self.policy_version,
                "accepted_by": a and a["email"], "accepted_at": a and a["accepted_at"]}

    def accept_policies(self, version: str, email: str, ip: str = "") -> dict:
        if not self.policy_version:
            return self.policy_status()
        if str(version) != self.policy_version:
            raise AccountError(f"Accept the current policies (version {self.policy_version})")
        self._x("INSERT INTO policy_acceptance(version, email, accepted_at, ip) VALUES (?,?,?,?)",
                (self.policy_version, (email or "").lower(), int(time.time()), ip or ""))
        self.audit(email or "system", "policies.accept", f"version {self.policy_version}")
        return self.policy_status()

    def _require_policies(self):
        if self.policy_version and not self.policy_status()["accepted"]:
            raise PoliciesRequired(f"Accept the Zoltis Mail Community Edition policies (version {self.policy_version}) "
                                   "in the admin console before creating email accounts or domains")

    def _require_license(self, domain):
        if self.license is None:
            return
        from .licensing import LicenseRequired
        try:
            self.license.require(domain)
        except LicenseRequired as e:
            raise NotLicensed(str(e))

    @property
    def max_accounts(self):
        return self.limits.get("max_accounts")

    @property
    def max_aliases(self):
        return self.limits.get("max_aliases")

    @property
    def max_domains(self):
        return self.limits.get("max_domains")

    @staticmethod
    def _counts_as_alias(source: str) -> bool:
        return not source.startswith("postmaster@")

    def alias_count(self) -> int:
        return sum(1 for a in self.aliases() if self._counts_as_alias(a["source"]))

    @property
    def max_quota(self):
        return self.limits.get("max_quota_mb")

    # -------------------------------------------------------------- domains
    def domains(self) -> list[dict]:
        rows = self._q("""SELECT d.*, (SELECT COUNT(*) FROM accounts a WHERE a.domain = d.name) AS accounts
                          FROM domains d ORDER BY name""")
        return [dict(r) for r in rows]

    def domain(self, name):
        r = self._q("SELECT * FROM domains WHERE name = ?", (name.lower(),))
        return dict(r[0]) if r else None

    def set_mta_sts(self, name, mode, actor="system") -> dict:
        """off | testing | enforce. A new policy id is issued so senders re-fetch the policy."""
        if mode not in MTA_STS_MODES:
            raise AccountError("MTA-STS mode must be off, testing or enforce")
        d = self.domain(name or "")
        if not d:
            raise AccountError("Domain not found")
        self._x("UPDATE domains SET mta_sts = ?, mta_sts_id = ? WHERE name = ?",
                (mode, time.strftime("%Y%m%d%H%M%S", time.gmtime()), d["name"]))
        self.audit(actor, "domain.mta_sts", f"{d['name']} ({mode})")
        return self.domain(d["name"])

    def add_domain(self, name: str, actor="system") -> dict:
        name = name.strip().lower().rstrip(".")
        if not DOMAIN_RE.match(name):
            raise AccountError(f"'{name}' is not a valid domain name")
        if self.domain(name):
            raise AccountError(f"Domain {name} already exists")
        self._require_policies()
        self._require_license(name)
        if self.max_domains and len(self.domains()) >= self.max_domains:
            raise LimitReached(f"Community Edition allows up to {self.max_domains} domains. "
                               "Delete a domain you no longer use, or upgrade to Zoltis Mail Pro for more")
        self._x("INSERT INTO domains(name, created) VALUES (?, ?)", (name, int(time.time())))
        self.audit(actor, "domain.add", name)
        return self.domain(name)

    def set_dkim(self, name, selector, public_b64):
        self._x("UPDATE domains SET dkim_selector = ?, dkim_public = ? WHERE name = ?", (selector, public_b64, name))

    def delete_domain(self, name, actor="system"):
        name = name.lower()
        n = self._q("SELECT COUNT(*) FROM accounts WHERE domain = ?", (name,))[0][0]
        if n:
            raise AccountError(f"Delete the {n} account(s) in {name} first")
        self._x("DELETE FROM aliases WHERE source LIKE ?", (f"%@{name}",))
        self._x("DELETE FROM domains WHERE name = ?", (name,))
        self.audit(actor, "domain.delete", name)

    # -------------------------------------------------------------- accounts
    def accounts(self) -> list[dict]:
        return [self._pub(r) for r in self._q("SELECT * FROM accounts ORDER BY domain, email")]

    def count(self) -> int:
        return self._q("SELECT COUNT(*) FROM accounts")[0][0]

    @staticmethod
    def _pub(r) -> dict:
        d = dict(r)
        d["has_password"] = bool(d.pop("pw_hash", None))
        d["twofa"] = bool(d.pop("totp_secret", None))
        d["has_app_password"] = bool(d.pop("app_pw_hash", None))
        d.pop("totp_last", None)
        d.pop("recovery_codes", None)
        d["is_admin"] = bool(d["is_admin"])
        d["enabled"] = bool(d["enabled"])
        return d

    def get(self, email) -> dict | None:
        r = self._q("SELECT * FROM accounts WHERE email = ?", (email.lower(),))
        return dict(r[0]) if r else None

    def is_admin(self, email) -> bool:
        a = self.get(email)
        return bool(a and a["is_admin"] and a["enabled"])

    def _check_quota(self, quota_mb):
        try:
            q = int(quota_mb)
        except (TypeError, ValueError):
            raise AccountError("Storage limit must be a number of MB")
        if q < 10:
            raise AccountError("Storage limit must be at least 10 MB")
        if self.max_quota and q > self.max_quota:
            raise LimitReached(f"The maximum mailbox size in this edition is {self.max_quota} MB")
        return q

    def _check_seat(self):
        if self.max_accounts and self.count() >= self.max_accounts:
            raise LimitReached(f"Community Edition allows up to {self.max_accounts} email accounts. "
                               "Delete an account, or upgrade to Zoltis Mail Pro for more.")

    def create_account(self, email, password=None, name="", quota_mb=None, is_admin=False, actor="system") -> dict:
        email = (email or "").strip().lower()
        if "@" not in email:
            raise AccountError("Enter a full email address, e.g. john@example.com")
        local, domain = email.split("@", 1)
        if not LOCAL_RE.match(local) or ".." in local or local in RESERVED_LOCALS:
            raise AccountError("The part before @ may use letters, digits and . _ + - only")
        with self.lock:
            if self.mode == "bundled" and not self.domain(domain):
                raise AccountError(f"Add the domain {domain} first")
            if self.get(email):
                raise AccountError(f"{email} already exists")
            if self._q("SELECT 1 FROM aliases WHERE source = ?", (email,)):
                raise AccountError(f"{email} is already used as an alias")
            self._require_policies()
            self._require_license(domain)
            self._check_seat()
            quota = self._check_quota(quota_mb if quota_mb is not None else (self.max_quota or 1024))
            pw_hash = None
            if self.mode == "bundled":
                if not password:
                    raise AccountError("Set a password for the new account")
                check_password_strength(password, email)
                pw_hash = hash_password(password)
            self._x("""INSERT INTO accounts(email, domain, name, pw_hash, quota_mb, is_admin, enabled, created)
                       VALUES (?,?,?,?,?,?,1,?)""", (email, domain, (name or "").strip()[:120], pw_hash, quota,
                                                    1 if is_admin else 0, int(time.time())))
        self.audit(actor, "account.create", email)
        return self._pub(self._q("SELECT * FROM accounts WHERE email = ?", (email,))[0])

    def import_account(self, a: dict, actor="import") -> dict:
        """Create an account from a migration export, keeping its password hash.

        Applies the same checks as create_account (license, domain, seat limit). A storage
        limit above this edition's maximum is lowered to the maximum (flagged with _capped).
        """
        email = (a.get("email") or "").strip().lower()
        if "@" not in email:
            raise AccountError("Invalid email address in export")
        local, domain = email.split("@", 1)
        if not LOCAL_RE.match(local) or local in RESERVED_LOCALS:
            raise AccountError("Invalid email address in export")
        pw_hash = a.get("pw_hash")
        if self.mode == "bundled" and not (isinstance(pw_hash, str) and pw_hash.startswith("{SHA512-CRYPT}$6$")
                                           and ":" not in pw_hash and "\n" not in pw_hash):
            raise AccountError("The export has no usable password for this account")
        with self.lock:
            if self.mode == "bundled" and not self.domain(domain):
                raise AccountError(f"Add the domain {domain} first")
            if self.get(email):
                raise AccountError(f"{email} already exists")
            if self._q("SELECT 1 FROM aliases WHERE source = ?", (email,)):
                raise AccountError(f"{email} is already used as an alias")
            self._require_policies()
            self._require_license(domain)
            self._check_seat()
            want = int(a.get("quota_mb") or (self.max_quota or 1024))
            capped = bool(self.max_quota and want > self.max_quota)
            quota = self._check_quota(self.max_quota if capped else want)
            self._x("""INSERT INTO accounts(email, domain, name, pw_hash, quota_mb, is_admin, enabled, created)
                       VALUES (?,?,?,?,?,?,?,?)""", (email, domain, str(a.get("name") or "")[:120], pw_hash, quota,
                                                    1 if a.get("is_admin") else 0, 0 if a.get("enabled") is False else 1,
                                                    int(a.get("created") or time.time())))
        self.audit(actor, "account.import", email)
        out = self._pub(self._q("SELECT * FROM accounts WHERE email = ?", (email,))[0])
        out["_capped"] = capped
        return out

    def update_account(self, email, actor="system", **changes) -> dict:
        a = self.get(email)
        if not a:
            raise AccountError("Account not found")
        sets, args = [], []
        if "name" in changes:
            sets.append("name = ?"); args.append(str(changes["name"] or "").strip()[:120])
        if "quota_mb" in changes:
            sets.append("quota_mb = ?"); args.append(self._check_quota(changes["quota_mb"]))
        if "is_admin" in changes:
            if not changes["is_admin"] and a["is_admin"] and self._admins_left(excluding=email) == 0:
                raise AccountError("At least one administrator must remain")
            sets.append("is_admin = ?"); args.append(1 if changes["is_admin"] else 0)
        if "enabled" in changes:
            if not changes["enabled"] and a["is_admin"] and self._admins_left(excluding=email) == 0:
                raise AccountError("You can't disable the last administrator")
            sets.append("enabled = ?"); args.append(1 if changes["enabled"] else 0)
        if changes.get("password"):
            if self.mode != "bundled":
                raise AccountError("Passwords are managed by your external mail server")
            check_password_strength(changes["password"], email)
            sets.append("pw_hash = ?"); args.append(hash_password(changes["password"]))
        if not sets:
            return self._pub(self._q("SELECT * FROM accounts WHERE email = ?", (email.lower(),))[0])
        args.append(email.lower())
        self._x(f"UPDATE accounts SET {', '.join(sets)} WHERE email = ?", args)
        what = ",".join(k for k in changes if k != "password") + (",password" if changes.get("password") else "")
        self.audit(actor, "account.update", f"{email} ({what})")
        return self._pub(self._q("SELECT * FROM accounts WHERE email = ?", (email.lower(),))[0])

    def _admins_left(self, excluding):
        return self._q("SELECT COUNT(*) FROM accounts WHERE is_admin = 1 AND enabled = 1 AND email != ?",
                       (excluding.lower(),))[0][0]

    def delete_account(self, email, actor="system"):
        a = self.get(email)
        if not a:
            raise AccountError("Account not found")
        if a["is_admin"] and self._admins_left(excluding=email) == 0:
            raise AccountError("You can't delete the last administrator")
        self._x("DELETE FROM accounts WHERE email = ?", (email.lower(),))
        # remove the account from alias destinations
        for al in self.aliases():
            dests = [d for d in al["destinations"] if d != email.lower()]
            if dests != al["destinations"]:
                if dests:
                    self._x("UPDATE aliases SET destinations = ? WHERE source = ?", (",".join(dests), al["source"]))
                else:
                    self._x("DELETE FROM aliases WHERE source = ?", (al["source"],))
        self.audit(actor, "account.delete", email)

    # -------------------------------------------------------------- two-step verification
    def set_totp(self, email, secret, recovery_hashes=(), actor="system"):
        """Turn two-step verification on (secret) or off (None)."""
        self._x("UPDATE accounts SET totp_secret = ?, totp_last = NULL, recovery_codes = ? WHERE email = ?",
                (secret, ",".join(recovery_hashes) if secret else None, email.lower()))
        self.audit(actor, "account.2fa.on" if secret else "account.2fa.off", email.lower())

    def set_recovery_codes(self, email, hashes):
        self._x("UPDATE accounts SET recovery_codes = ? WHERE email = ?", (",".join(hashes), email.lower()))

    def use_totp_step(self, email, step) -> bool:
        """Record an accepted time step; False if it (or a later one) was already used."""
        with self.lock:
            cur = self.db.execute("UPDATE accounts SET totp_last = ? WHERE email = ? AND (totp_last IS NULL OR totp_last < ?)",
                                  (step, email.lower(), step))
            return cur.rowcount == 1

    def use_recovery_code(self, email, code_hash) -> int | None:
        """Consume a recovery code. Returns how many are left, or None if it isn't valid."""
        with self.lock:
            a = self.get(email)
            codes = [c for c in ((a or {}).get("recovery_codes") or "").split(",") if c]
            if code_hash not in codes:
                return None
            codes.remove(code_hash)
            self.set_recovery_codes(email, codes)
        self.audit(email.lower(), "account.2fa.recovery_used", email.lower())
        return len(codes)

    def set_app_password(self, email, pw_hash, actor="system"):
        self._x("UPDATE accounts SET app_pw_hash = ?, app_pw_created = ? WHERE email = ?",
                (pw_hash, int(time.time()) if pw_hash else None, email.lower()))
        self.audit(actor, "account.app_password.create" if pw_hash else "account.app_password.delete", email.lower())

    def record_login(self, email):
        self._x("UPDATE accounts SET last_login = ? WHERE email = ?", (int(time.time()), email.lower()))

    def ensure_seat(self, email) -> dict:
        """External mode: register a webmail user on first login, enforcing the seat limit."""
        a = self.get(email)
        if a:
            if not a["enabled"]:
                raise AccountError("This account has been disabled by your administrator")
            return a
        self._require_license(email.split("@", 1)[1])
        if self.max_accounts and self.count() >= self.max_accounts:
            raise LimitReached(f"This webmail is limited to {self.max_accounts} accounts. Ask your administrator.")
        domain = email.split("@", 1)[1]
        self._x("""INSERT INTO accounts(email, domain, name, pw_hash, quota_mb, is_admin, enabled, created)
                   VALUES (?,?,?,NULL,?,?,1,?)""", (email.lower(), domain, "", self.max_quota or 1024,
                                                   1 if self.count() == 0 else 0, int(time.time())))
        self.audit(email, "account.register", email)
        return self.get(email)

    # -------------------------------------------------------------- aliases
    def aliases(self) -> list[dict]:
        return [{"source": r["source"], "destinations": r["destinations"].split(","), "created": r["created"]}
                for r in self._q("SELECT * FROM aliases ORDER BY source")]

    def add_alias(self, source, destinations, actor="system") -> dict:
        source = source.strip().lower()
        if "@" not in source:
            raise AccountError("Enter the full alias address, e.g. info@example.com")
        local, domain = source.split("@", 1)
        if not LOCAL_RE.match(local):
            raise AccountError("Invalid alias address")
        if not self.domain(domain):
            raise AccountError(f"Add the domain {domain} first")
        if self.get(source):
            raise AccountError(f"{source} is already a mailbox")
        self._require_license(domain)
        is_new = not self._q("SELECT 1 FROM aliases WHERE source = ?", (source,))
        if is_new and self.max_aliases and self._counts_as_alias(source) and self.alias_count() >= self.max_aliases:
            raise LimitReached(f"Community Edition allows up to {self.max_aliases} aliases (postmaster@ doesn't count). "
                               "Delete an alias, or upgrade to Zoltis Mail Pro for more.")
        dests = sorted({d.strip().lower() for d in re.split(r"[,\s]+", ",".join(destinations) if isinstance(destinations, list) else destinations) if d.strip()})
        if not dests:
            raise AccountError("Add at least one destination")
        for d in dests:
            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", d):
                raise AccountError(f"Invalid destination {d}")
        self._x("INSERT OR REPLACE INTO aliases(source, destinations, created) VALUES (?,?,?)",
                (source, ",".join(dests), int(time.time())))
        self.audit(actor, "alias.set", f"{source} -> {','.join(dests)}")
        return {"source": source, "destinations": dests}

    def delete_alias(self, source, actor="system"):
        self._x("DELETE FROM aliases WHERE source = ?", (source.lower(),))
        self.audit(actor, "alias.delete", source)

    # -------------------------------------------------------------- export for backend
    def snapshot(self) -> dict:
        with self.lock:
            return {
                "domains": [dict(r) for r in self.db.execute("SELECT * FROM domains ORDER BY name")],
                "accounts": [dict(r) for r in self.db.execute("SELECT * FROM accounts ORDER BY email")],
                "aliases": self.aliases(),
            }
