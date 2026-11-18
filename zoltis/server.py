"""Zoltis Mail HTTP server: static web UI + JSON API. Standard library only."""

from __future__ import annotations

import base64
import json
import logging
import mimetypes
import os
import re
import secrets
import threading
import time
import traceback
from email.utils import getaddresses
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

from . import __version__
from .edition import Edition
from .mail import assistant, dnscheck
from .mail.sanitize import sanitize_html
from .mail.antivirus import ClamAV, ScannerUnavailable, VirusFound
from .mail.filepolicy import FilePolicy
from .accounts import AccountDB, AccountError, LimitReached, NotLicensed, PoliciesRequired, hash_password
from . import policies
from .licensing import LicenseError, LicenseManager, parse_key
from .integrity import IntegrityMonitor
from .mailserver import BundledMailServer, ExternalMailServer
from .importer import ImportJob, run_import
from . import migration
from .mail.imap import AuthError, IMAPAccount, MailError
from .mail.smtp import SMTPSender, build_message
from .store import SiteSettings, UserStore, valid_timezone
from . import reminders, totp

log = logging.getLogger("zoltis")
WEB_DIR = os.environ.get("ZOLTIS_WEB_DIR") or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")
EMAIL_RE = re.compile(r"^[^@\s]+@([^@\s]+\.[^@\s]+)$")
INLINE_OK = {"image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf", "text/plain"}


class HTTPError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
class Session:
    def __init__(self, email, account: IMAPAccount, password: str, ip="", ua=""):
        self.id = secrets.token_urlsafe(32)
        self.handle = __import__("hashlib").sha256(self.id.encode()).hexdigest()[:12]
        self.email = email
        self.account = account
        self.password = password
        self.ip, self.ua = ip, (ua or "")[:200]
        self.created = self.seen = time.time()
        self.pending_totp = None   # secret being set up, until the first code confirms it
        self.no_categories = False # set when the mail server can't store category keywords


class SessionManager:
    def __init__(self, hours: int):
        self.ttl = hours * 3600
        self.sessions: dict[str, Session] = {}
        self.lock = threading.Lock()
        threading.Thread(target=self._reaper, daemon=True).start()

    def add(self, s: Session):
        with self.lock:
            self.sessions[s.id] = s

    def get(self, sid: str | None) -> Session | None:
        if not sid:
            return None
        with self.lock:
            s = self.sessions.get(sid)
        if s and time.time() - s.created > self.ttl:
            self.drop(sid)
            return None
        if s:
            s.seen = time.time()
        return s

    def drop(self, sid: str):
        with self.lock:
            s = self.sessions.pop(sid, None)
        if s:
            s.account.close()

    def all(self) -> list[Session]:
        with self.lock:
            return list(self.sessions.values())

    def drop_user(self, email: str, keep: str | None = None) -> int:
        n = 0
        for s in self.all():
            if s.email.lower() == email.lower() and s.id != keep:
                self.drop(s.id)
                n += 1
        return n

    def drop_handle(self, handle: str) -> bool:
        for s in self.all():
            if s.handle == handle:
                self.drop(s.id)
                return True
        return False

    def _reaper(self):
        while True:
            time.sleep(60)
            now = time.time()
            with self.lock:
                items = list(self.sessions.items())
            for sid, s in items:
                if now - s.created > self.ttl:
                    self.drop(sid)
                elif now - s.seen > 900 and s.account.conn is not None:
                    s.account.close()  # idle: free the IMAP connection, keep session


class RateLimiter:
    def __init__(self, limit=10, window=300):
        self.limit, self.window = limit, window
        self.hits: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def blocked(self, key: str) -> bool:
        now = time.time()
        with self.lock:
            h = [t for t in self.hits.get(key, []) if now - t < self.window]
            if h:
                self.hits[key] = h
            else:
                self.hits.pop(key, None)
            return len(h) >= self.limit

    def fail(self, key: str):
        with self.lock:
            self.hits.setdefault(key, []).append(time.time())

    def reset(self, key: str):
        with self.lock:
            self.hits.pop(key, None)


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
class Router:
    def __init__(self):
        self.routes: dict[tuple[str, str], tuple] = {}

    def add(self, method, path, handler, auth=True):
        self.routes[(method, path)] = (handler, auth)

    def find(self, method, path):
        return self.routes.get((method, path))


class App:
    def __init__(self, cfg):
        self.cfg = cfg
        data_dir = cfg.get("server", "data_dir")
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.store = UserStore(data_dir)
        self.sessions = SessionManager(cfg.getint("server", "session_hours"))
        self.login_limiter = RateLimiter(10, 900)
        self.pending_logins: dict[str, dict] = {}   # 2-step verification: password OK, waiting for the code
        self.pending_lock = threading.Lock()
        self.edition = Edition(cfg)
        self.app_name = self.edition.app_name(cfg.get("branding", "app_name"))
        wanted = (cfg.get("branding", "app_name") or "").strip()
        if wanted and wanted != self.app_name:
            log.warning("branding: '%s' ignored. Community Edition always shows the Zoltis Mail name and logo "
                        "(custom branding is an Enterprise feature)", wanted)
        self.av = ClamAV(cfg)
        self.policy = FilePolicy(cfg)
        ms = lambda k, d="": os.environ.get(f"ZOLTIS_MAIL_SERVER_{k.upper()}") or cfg.raw.get("mail_server", {}).get(k) or d
        self.mode = ms("mode", "external").lower()
        self.license = LicenseManager(cfg, data_dir)
        self.license.edition = self.edition.name
        self.license.on_change = self._on_license_change
        self.accounts = AccountDB(os.path.join(data_dir, "accounts.db"), self.edition.limits, self.mode, self.license)
        if self.edition.name == "community":      # the admin must accept the Community Edition policies
            self.accounts.policy_version = policies.VERSION
        self.mailserver = BundledMailServer(cfg, data_dir) if self.mode == "bundled" else ExternalMailServer()
        self.public_ip = ms("public_ip", "")
        self.license.public_ip = self.public_ip or None
        # Code integrity: changed core files lock the service (when enforced) and are reported at check-in
        self.site = SiteSettings(data_dir)
        self.integrity = IntegrityMonitor(cfg, self.license, WEB_DIR)
        self.jobs: dict[str, ImportJob] = {}
        self.migrations: dict[str, migration.MigrationJob] = {}
        self.export_dir = os.path.join(data_dir, "exports")
        os.makedirs(self.export_dir, mode=0o700, exist_ok=True)
        self.setup_token = None
        if self.mode == "bundled":
            self._apply()
            if self.accounts.count() == 0:
                tok_path = os.path.join(data_dir, "setup.token")
                if os.path.exists(tok_path):
                    self.setup_token = open(tok_path).read().strip()
                else:
                    self.setup_token = os.environ.get("ZOLTIS_SETUP_TOKEN") or secrets.token_hex(4).upper()
                    with open(tok_path, "w") as f:
                        f.write(self.setup_token)
                    os.chmod(tok_path, 0o600)
                log.warning("FIRST-RUN SETUP: open the webmail and use setup code %s to create the first admin", self.setup_token)
        self.router = Router()
        self._routes()
        self.edition.register(self.router)

    # -- per-domain server resolution -------------------------------------
    def _server_for(self, kind: str, domain: str) -> dict:
        sect = f"domain:{domain}"
        raw = self.cfg.raw.get(sect, {})
        def g(key):
            return raw.get(f"{kind}_{key}") or self.cfg.get(kind, key)
        host = g("host")
        if host == "auto":
            host = f"mail.{domain}"
        out = {"host": host, "port": int(g("port")), "security": g("security"),
               "verify_cert": g("verify_cert").lower() in ("1", "true", "yes", "on"),
               "timeout": int(g("timeout"))}
        if kind == "smtp":
            out["auth"] = g("auth").lower() in ("1", "true", "yes", "on")
        return out

    # -- routes -----------------------------------------------------------
    def _routes(self):
        r = self.router
        r.add("GET", "/api/config", self.api_config, auth=False)
        r.add("GET", "/api/client", self.api_client_discovery, auth=False)
        r.add("POST", "/api/login", self.api_login, auth=False)
        r.add("POST", "/api/login/2fa", self.api_login_2fa, auth=False)
        r.add("POST", "/api/logout", self.api_logout)
        r.add("GET", "/api/me", self.api_me)
        r.add("GET", "/api/folders", self.api_folders)
        r.add("POST", "/api/folders", self.api_folder_create)
        r.add("DELETE", "/api/folders", self.api_folder_delete)
        r.add("GET", "/api/messages", self.api_messages)
        r.add("GET", "/api/message", self.api_message)
        r.add("GET", "/api/raw", self.api_raw)
        r.add("GET", "/api/attachment", self.api_attachment)
        r.add("POST", "/api/messages/flags", self.api_flags)
        r.add("POST", "/api/messages/move", self.api_move)
        r.add("POST", "/api/messages/delete", self.api_delete)
        r.add("POST", "/api/messages/restore", self.api_restore)
        r.add("POST", "/api/messages/category", self.api_set_category)
        r.add("POST", "/api/folders/empty", self.api_folder_empty)
        r.add("POST", "/api/send", self.api_send)
        r.add("POST", "/api/draft", self.api_draft)
        r.add("GET", "/api/settings", self.api_settings_get)
        r.add("POST", "/api/settings", self.api_settings_set)
        r.add("GET", "/api/contacts", self.api_contacts)
        r.add("GET", "/api/deliverability", self.api_deliverability)
        r.add("GET", "/api/scan", self.api_scan)
        r.add("GET", "/api/antivirus", self.api_av_status)
        r.add("POST", "/api/attachments/check", self.api_attachments_check)
        r.add("GET", "/api/setup", self.api_setup_status, auth=False)
        r.add("POST", "/api/setup", self.api_setup, auth=False)
        r.add("POST", "/api/account/password", self.api_change_password)
        r.add("GET", "/api/account/quota", self.api_my_quota)
        r.add("GET", "/api/account/security", self.api_security)
        r.add("POST", "/api/account/2fa/start", self.api_2fa_start)
        r.add("POST", "/api/account/2fa/enable", self.api_2fa_enable)
        r.add("POST", "/api/account/2fa/disable", self.api_2fa_disable)
        r.add("POST", "/api/account/2fa/recovery", self.api_2fa_recovery)
        r.add("POST", "/api/account/app-password", self.api_app_password)
        r.add("POST", "/api/account/app-password/delete", self.api_app_password_delete)
        r.add("GET", "/api/account/mail-setup", self.api_mail_setup)
        r.add("GET", "/api/account/apple-profile", self.api_apple_profile)
        a = lambda m, p, h: r.add(m, p, self._admin(h))
        a("GET", "/api/admin/overview", self.adm_overview)
        a("GET", "/api/admin/accounts", self.adm_accounts)
        a("POST", "/api/admin/accounts", self.adm_account_create)
        a("POST", "/api/admin/accounts/update", self.adm_account_update)
        a("POST", "/api/admin/accounts/delete", self.adm_account_delete)
        a("GET", "/api/admin/domains", self.adm_domains)
        a("POST", "/api/admin/domains", self.adm_domain_add)
        a("POST", "/api/admin/domains/delete", self.adm_domain_delete)
        a("POST", "/api/admin/domains/mta-sts", self.adm_mta_sts)
        a("POST", "/api/admin/timezone", self.adm_timezone)
        a("GET", "/api/admin/policies", self.adm_policies)
        a("POST", "/api/admin/policies/accept", self.adm_policies_accept)
        r.add("GET", "/api/internal/tls-allowed", self.api_tls_allowed, auth=False)
        a("GET", "/api/admin/dns-check", self.adm_dns_check)
        a("GET", "/api/admin/aliases", self.adm_aliases)
        a("POST", "/api/admin/aliases", self.adm_alias_set)
        a("POST", "/api/admin/aliases/delete", self.adm_alias_delete)
        a("GET", "/api/admin/sessions", self.adm_sessions)
        a("POST", "/api/admin/sessions/revoke", self.adm_session_revoke)
        a("GET", "/api/admin/audit", self.adm_audit)
        a("GET", "/api/admin/license", self.adm_license)
        a("POST", "/api/admin/license", self.adm_license_activate)
        a("POST", "/api/admin/license/refresh", self.adm_license_refresh)
        a("GET", "/api/admin/migration", self.adm_migration)
        a("POST", "/api/admin/migration/export", self.adm_migration_export)
        a("POST", "/api/admin/migration/import", self.adm_migration_import)
        a("POST", "/api/admin/migration/cancel", self.adm_migration_cancel)
        a("POST", "/api/admin/migration/delete", self.adm_migration_delete)
        a("GET", "/api/admin/migration/download", self.adm_migration_download)
        a("GET", "/api/admin/import", self.adm_import_list)
        a("POST", "/api/admin/import", self.adm_import_start)
        a("POST", "/api/admin/import/cancel", self.adm_import_cancel)

    def api_config(self, req, s):
        b = lambda k: self.cfg.get("branding", k)
        brand = self.edition.custom_branding
        return {"app_name": self.app_name, "custom_branding": brand, "company": b("company") if brand else "",
                "primary_color": b("primary_color") if brand else "",
                "default_domain": b("default_domain"), "version": __version__,
                "max_upload_mb": self.cfg.getint("server", "max_upload_mb"),
                "antivirus": self.av.enabled, "attachments": self.policy.public(), "mail_mode": self.mode,
                "setup_needed": bool(self.setup_token), "license": self.license.public(),
                "policies": policies.public() if self.accounts.policy_version else None,
                "server_time": self._server_time(), **self.edition.public()}

    def api_client_discovery(self, req, s):
        """What the Zoltis Mail app (and other clients) need to connect to this server.

        Also served at /.well-known/zoltis-mail.json, so the app only needs the server address.
        """
        out = {"service": "zoltis-mail", "api_version": 1, "version": __version__,
               "app_name": self.app_name,
               "edition": self.edition.public().get("edition", "community"), "mail_mode": self.mode,
               "auth": {"login": "/api/login", "two_factor": "/api/login/2fa", "logout": "/api/logout",
                        "scheme": "Bearer", "login_body": {"client": "app"},
                        "csrf_header": {"X-Zoltis": "1"},
                        "token_lifetime_seconds": self.cfg.getint("server", "session_hours") * 3600},
               "features": {"two_factor": self.mode == "bundled", "app_passwords": self.mode == "bundled"},
               "icon": "/img/icon-512.png"}
        if self.mode == "bundled":
            host = self.mailserver.hostname
            out["imap"] = {"host": host, "port": 993, "security": "ssl"}
            out["smtp"] = {"host": host, "port": 587, "security": "starttls", "alt_port": 465, "alt_security": "ssl"}
        return out

    def api_login(self, req, s):
        body = req.json()
        email = (body.get("email") or "").strip()
        password = body.get("password") or ""
        dd = self.cfg.get("branding", "default_domain")
        if "@" not in email and dd:
            email = f"{email}@{dd}"
        m = EMAIL_RE.match(email)
        if not m or not password:
            raise HTTPError(400, "Enter your email address and password")
        domain = m.group(1).lower()
        allowed = self.cfg.getlist("branding", "allowed_domains")
        if allowed and domain not in allowed:
            raise HTTPError(403, "This domain is not allowed on this server")
        if self.license.locked:
            raise HTTPError(423, self.license.lock_message)
        ip_key, user_key = "ip:" + req.client_ip(), "u:" + email.lower()
        if self.login_limiter.blocked(ip_key) or self.login_limiter.blocked(user_key):
            raise HTTPError(429, "Too many failed sign-in attempts. Wait a few minutes and try again.")
        srv = self._server_for("imap", domain)
        acct = IMAPAccount(srv["host"], srv["port"], srv["security"], srv["verify_cert"],
                           email, password, srv["timeout"])
        try:
            acct.connect()
        except AuthError as e:
            self.login_limiter.fail(ip_key)
            self.login_limiter.fail(user_key)
            log.warning("login failed for %s from %s", email, req.client_ip())
            if "disabled" in str(e).lower():
                raise HTTPError(403, "This account has been disabled by your administrator")
            raise HTTPError(401, "Wrong email or password")
        self.login_limiter.reset(user_key)
        if self.mode == "external":
            try:
                self.accounts.ensure_seat(email)
            except AccountError as e:
                acct.close()
                raise HTTPError(403, str(e))
        rec = self.accounts.get(email) if self.mode == "bundled" else None
        if rec and rec.get("totp_secret"):
            ticket = secrets.token_urlsafe(32)
            with self.pending_lock:
                self._prune_pending()
                self.pending_logins[ticket] = {"email": email, "acct": acct, "password": password,
                                               "ip": req.client_ip(), "expires": time.time() + 300,
                                               "app": self._is_app_client(req, body)}
            log.info("password ok for %s from %s, waiting for the 2-step verification code", email, req.client_ip())
            return {"ok": True, "email": email, "twofa_required": True, "ticket": ticket}
        return self._start_session(req, email, acct, password, self._is_app_client(req, body))

    @staticmethod
    def _is_app_client(req, body) -> bool:
        """The Zoltis Mail phone/desktop app (or another API client) signs in with
        {"client": "app"} or the X-Zoltis-Client header, and gets a bearer token instead of a cookie."""
        return str(body.get("client") or req.headers.get("X-Zoltis-Client") or "").lower() in ("app", "api")

    def _start_session(self, req, email, acct, password, app_client=False):
        self.accounts.record_login(email)
        sess = Session(email, acct, password, req.client_ip(), req.headers.get("User-Agent", ""))
        self.sessions.add(sess)
        hours = self.cfg.getint("server", "session_hours")
        log.info("login ok for %s from %s%s", email, req.client_ip(), " (app)" if app_client else "")
        if app_client:
            # Sent as "Authorization: Bearer <token>" on every API request.
            return {"ok": True, "email": email, "token": sess.id, "token_type": "Bearer",
                    "expires_in": hours * 3600}
        req.set_cookie("zm_sid", sess.id, max_age=hours * 3600)
        return {"ok": True, "email": email}

    def _prune_pending(self):
        now = time.time()
        for t, p in list(self.pending_logins.items()):
            if p["expires"] < now:
                self.pending_logins.pop(t, None)
                p["acct"].close()

    def _check_second_factor(self, email, code) -> str | None:
        """Accept an authenticator code or a recovery code. Returns which one matched."""
        rec = self.accounts.get(email) or {}
        secret = rec.get("totp_secret")
        if not secret:
            return None
        code = "".join(str(code or "").split())
        if code.isdigit():
            step = totp.verify(secret, code, rec.get("totp_last") or -1)
            if step is not None and self.accounts.use_totp_step(email, step):
                return "totp"
            return None
        if totp.normalize_recovery(code):
            left = self.accounts.use_recovery_code(email, totp.hash_recovery(code))
            if left is not None:
                log.warning("%s signed in with a recovery code (%d left)", email, left)
                return "recovery"
        return None

    def api_login_2fa(self, req, s):
        b = req.json()
        ticket = str(b.get("ticket") or "")
        with self.pending_lock:
            self._prune_pending()
            p = self.pending_logins.get(ticket)
        if not p:
            raise HTTPError(401, "Your sign-in expired. Enter your password again.")
        email = p["email"]
        if self.license.locked:
            raise HTTPError(423, self.license.lock_message)
        ip_key, user_key = "ip:" + req.client_ip(), "2fa:" + email.lower()
        if self.login_limiter.blocked(ip_key) or self.login_limiter.blocked(user_key):
            raise HTTPError(429, "Too many wrong codes. Wait a few minutes and try again.")
        how = self._check_second_factor(email, b.get("code"))
        if not how:
            self.login_limiter.fail(ip_key)
            self.login_limiter.fail(user_key)
            log.warning("wrong 2-step verification code for %s from %s", email, req.client_ip())
            raise HTTPError(401, "Wrong code. Try again.")
        with self.pending_lock:
            p = self.pending_logins.pop(ticket, None)
        if not p:
            raise HTTPError(401, "Your sign-in expired. Enter your password again.")
        self.login_limiter.reset(user_key)
        out = self._start_session(req, email, p["acct"], p["password"], p.get("app", False))
        if how == "recovery":
            rec = self.accounts.get(email) or {}
            out["recovery_left"] = len([c for c in (rec.get("recovery_codes") or "").split(",") if c])
        return out

    def api_logout(self, req, s):
        self.sessions.drop(s.id)
        req.set_cookie("zm_sid", "", max_age=0)
        return {"ok": True}

    def api_me(self, req, s):
        d = self.store.load(s.email)
        acc = self.accounts.get(s.email) or {}
        return {"email": s.email, "settings": d["settings"], "is_admin": self.accounts.is_admin(s.email),
                "mail_mode": self.mode, "name": acc.get("name", ""), "license": self.license.public(),
                **self.edition.public()}

    def api_folders(self, req, s):
        return {"folders": s.account.folders()}

    def api_folder_create(self, req, s):
        name = (req.json().get("name") or "").strip()
        if not name or len(name) > 200:
            raise HTTPError(400, "Enter a label name")
        s.account.create_folder(name)
        return {"ok": True}

    def api_folder_delete(self, req, s):
        name = req.q("name")
        if not name or name.upper() == "INBOX":
            raise HTTPError(400, "This folder can't be deleted")
        s.account.delete_folder(name)
        return {"ok": True}

    def api_messages(self, req, s):
        folder = req.q("folder") or "INBOX"
        page = max(0, int(req.q("page") or 0))
        settings = self.store.load(s.email)["settings"]
        size = min(200, max(10, int(req.q("size") or settings["page_size"])))
        query = req.q("q") or ""
        cat = (req.q("category") or "").lower()
        tabs = settings["inbox_tabs"] and folder.upper() == "INBOX" and not query and not s.no_categories
        if tabs:
            d = self.store.load(s.email)
            contacts = d["contacts"]
            try:
                s.account.categorize(folder, lambda a: a in contacts, d["sender_categories"])
            except MailError as e:                 # e.g. an external server without IMAP keywords
                log.info("inbox categories off for %s: %s", s.email, e)
                s.no_categories, tabs = True, False
        if not tabs or cat not in assistant.CATEGORIES:
            cat = ""
        r = s.account.list_messages(folder, page, size, query, cat)
        if tabs:
            r["categories"] = s.account.category_unread(folder)
            r["category"] = cat or None
        return r

    def api_set_category(self, req, s):
        """Move messages to another inbox tab; with learn, future mail from those senders goes there too."""
        b = req.json()
        folder, cat = b.get("folder") or "INBOX", str(b.get("category") or "")
        if cat not in assistant.CATEGORIES:
            raise HTTPError(400, "Unknown category")
        uids = self._uids(b)
        s.account.set_category(folder, uids, cat)
        senders = sorted({str(x).strip().lower() for x in b.get("senders", []) if EMAIL_RE.match(str(x).strip())})[:50]
        if b.get("learn") and senders:
            self.store.set_sender_category(s.email, senders, cat)
            for snd in senders:
                more = [u for u in s.account.uids_from(folder, snd) if u not in uids]
                s.account.set_category(folder, more, cat)
        return {"ok": True, "learned": senders if b.get("learn") else []}

    def api_folder_empty(self, req, s):
        """Empty Trash or Spam now (permanently deletes every message in it)."""
        folder = req.json().get("folder") or ""
        roles = {f["name"]: f["role"] for f in s.account.folders(with_counts=False)}
        if roles.get(folder) not in ("trash", "junk"):
            raise HTTPError(400, "Only Trash and Spam can be emptied")
        uids = s.account.all_uids(folder)
        for i in range(0, len(uids), 1000):
            s.account.purge(folder, uids[i:i + 1000])
        return {"ok": True, "deleted": len(uids)}

    def api_message(self, req, s):
        folder, uid = req.q("folder"), int(req.q("uid") or 0)
        allow = req.q("images") == "1" or self.store.load(s.email)["settings"]["load_images"] == "always"
        junk = folder == s.account.role_folder("junk")
        if junk:
            allow = req.q("images") == "1"           # never load remote images automatically from Spam
        inspect = self.policy.check if (self.policy.apply_incoming or junk) else None
        m = s.account.get_message(folder, uid, allow_remote=allow, mark_seen=req.q("peek") != "1" and not junk, inspect=inspect)
        if junk:      # shown as a warning before the message is displayed
            m["spam_check"] = assistant.spam_check(m.get("html"), m.get("text"), m.get("attachments"), m.get("from"))
        if self.store.load(s.email)["settings"]["smart_summary"]:
            try:
                m["assistant"] = assistant.summarize(m.get("text") or "", m.get("subject") or "", m.get("attachments"))
            except Exception:  # noqa: BLE001  - a summary must never break reading mail
                log.exception("summary failed")
        return m

    def api_raw(self, req, s):
        raw = s.account.get_raw(req.q("folder"), int(req.q("uid") or 0))
        req.send_bytes(raw, "text/plain; charset=utf-8")

    def api_attachment(self, req, s):
        name, ctype, data = s.account.get_attachment(req.q("folder"), int(req.q("uid") or 0), int(req.q("part") or -1))
        if req.q("folder") == s.account.role_folder("junk"):
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            if ext in assistant.RESTRICTED_EXT or self.policy.check(name, data)["verdict"] != "allow":
                raise HTTPError(403, f"\"{name}\" can't be downloaded from Spam. If you trust the sender, mark the message as not spam first.")
        if self.policy.apply_incoming:
            pr = self.policy.check(name, data)
            if pr["verdict"] == "block" and self.policy.incoming_action == "block":
                log.warning("blocked download of %s by %s: %s", name, s.email, pr["summary"])
                raise HTTPError(403, f"\"{name}\" was blocked for your security: {pr['summary']}")
        if self.av.scan_incoming:
            self._av_check(name, data)
        inline = req.q("download") != "1" and ctype in INLINE_OK
        if not inline:
            ctype = "application/octet-stream"
        disp = "inline" if inline else "attachment"
        safe = re.sub(r'[\r\n"]', "_", name)
        req.send_bytes(data, ctype, {
            "Content-Disposition": f"{disp}; filename=\"{safe}\"; filename*=UTF-8''{quote(name)}",
            "Content-Security-Policy": "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; sandbox",
        })

    def _uids(self, body):
        uids = [int(u) for u in body.get("uids", [])]
        if not uids:
            raise HTTPError(400, "No messages selected")
        return uids

    def api_flags(self, req, s):
        b = req.json()
        flag = {"seen": "\\Seen", "flagged": "\\Flagged", "answered": "\\Answered"}.get(b.get("flag"))
        if not flag:
            raise HTTPError(400, "Unknown flag")
        s.account.set_flags(b["folder"], self._uids(b), [flag], bool(b.get("value", True)))
        return {"ok": True}

    def api_move(self, req, s):
        b = req.json()
        dest = b.get("dest") or ""
        if dest.startswith("role:"):
            role = dest[5:]
            dest = s.account.role_folder(role)
            if not dest and role == "archive":
                s.account.create_folder("Archive")
                dest = "Archive"
            if not dest:
                raise HTTPError(400, f"No {role} folder on this account")
        s.account.move(b["folder"], self._uids(b), dest)
        return {"ok": True, "dest": dest}

    def api_restore(self, req, s):
        """Undo a move: find messages by Message-ID in `from` and move them back to `to`."""
        b = req.json()
        ids = [m for m in b.get("message_ids", []) if isinstance(m, str) and m][:200]
        if not ids:
            raise HTTPError(400, "Nothing to undo")
        uids = s.account.find_uids(b["from"], ids)
        if uids:
            s.account.move(b["from"], uids, b["to"])
        return {"ok": True, "restored": len(uids)}

    def api_delete(self, req, s):
        b = req.json()
        s.account.delete(b["folder"], self._uids(b))
        return {"ok": True}

    def _compose(self, s, b, draft=False):
        settings = self.store.load(s.email)["settings"]
        atts = []
        total = 0
        limit = self.cfg.getint("server", "max_upload_mb") * 1024 * 1024
        for a in b.get("attachments", []):
            data = base64.b64decode(a.get("data", ""))
            total += len(data)
            if total > limit:
                raise HTTPError(413, "Attachments are too large")
            fname = a.get("filename") or "file"
            self._policy_check(s, fname, data)
            if self.av.scan_outgoing:
                self._av_check(fname, data)
            atts.append({"filename": fname, "content_type": a.get("content_type"), "data": data})
        for f in b.get("forward_attachments", []):  # keep attachments when forwarding
            name, ctype, data = s.account.get_attachment(f["folder"], int(f["uid"]), int(f["part"]))
            self._policy_check(s, name, data)
            if self.av.scan_outgoing:
                self._av_check(name, data)
            atts.append({"filename": name, "content_type": ctype, "data": data})
        return build_message(
            from_name=b.get("from_name") or settings.get("display_name") or "",
            from_email=s.email, to=b.get("to", ""), cc=b.get("cc", ""), bcc=b.get("bcc", ""),
            subject=b.get("subject", ""), html=b.get("html", ""), attachments=atts,
            in_reply_to=b.get("in_reply_to", ""), references=b.get("references", ""),
            require_recipients=not draft)

    def api_send(self, req, s):
        b = req.json()
        msg, rcpts = self._compose(s, b)
        domain = s.email.split("@")[1].lower()
        srv = self._server_for("smtp", domain)
        refused = SMTPSender(srv["host"], srv["port"], srv["security"], srv["verify_cert"], srv["auth"],
                             srv["timeout"]).send(s.email, s.password, msg, rcpts) or {}
        log.info("sent message %s from %s to %d recipient(s)", msg["Message-ID"], s.email, len(rcpts) - len(refused))
        warnings = [f"Not delivered to {a}: {why}" for a, why in refused.items()]
        sent = s.account.role_folder("sent")
        if sent:
            try:
                s.account.append(sent, msg.as_bytes(), "(\\Seen)")
            except MailError as e:
                warnings.append(f"Sent, but could not save a copy: {e}")
        if b.get("reply_folder") and b.get("reply_uid"):
            try:
                s.account.set_flags(b["reply_folder"], [int(b["reply_uid"])], ["\\Answered"], True)
            except MailError:
                pass
        if b.get("draft_uid"):
            self._drop_draft(s, int(b["draft_uid"]))
        hdrs = [str(v) for v in (msg.get("To"), msg.get("Cc"), b.get("bcc")) if v]
        self.store.remember_contacts(s.email, [a for h in hdrs for a in getaddresses([h])])
        return {"ok": True, "message_id": msg["Message-ID"], "warnings": warnings}

    def _drop_draft(self, s, uid):
        drafts = s.account.role_folder("drafts")
        if drafts:
            try:
                s.account.purge(drafts, [uid])
            except MailError:
                pass

    def api_draft(self, req, s):
        b = req.json()
        drafts = s.account.role_folder("drafts")
        if not drafts:
            raise HTTPError(400, "No Drafts folder on this account")
        msg, _ = self._compose(s, b, draft=True)
        if b.get("draft_uid"):
            self._drop_draft(s, int(b["draft_uid"]))
        s.account.append(drafts, msg.as_bytes(), "(\\Seen \\Draft)")
        return {"ok": True, "draft_uid": s.account.find_uid(drafts, msg["Message-ID"])}

    def api_settings_get(self, req, s):
        return self.store.load(s.email)["settings"]

    def api_settings_set(self, req, s):
        patch = req.json()
        if isinstance(patch.get("signature"), str):     # HTML signature: no scripts, forms or tracking tricks
            patch["signature"] = sanitize_html(patch["signature"][:10000], allow_remote=True)[0].strip()
        return self.store.update_settings(s.email, patch)

    def api_contacts(self, req, s):
        return {"contacts": self.store.search_contacts(s.email, req.q("q") or "")}

    def _policy_check(self, s, name, data):
        if not self.policy.apply_outgoing:
            return
        r = self.policy.check(name, data)
        if r["verdict"] == "block":
            log.warning("blocked attachment %s from %s: %s", name, s.email, r["summary"])
            raise HTTPError(422, f"\"{name}\" can't be sent: {r['summary']}")

    def api_attachments_check(self, req, s):
        """Check files before sending. Body: {files:[{name, data?(base64)}]}.

        Without data only the name is checked (used for folder uploads); with data
        the content and archive contents are inspected too.
        """
        out = []
        files = req.json().get("files", [])[:2000]
        for f in files:
            name = str(f.get("name") or "file")[:1024]
            data = base64.b64decode(f["data"]) if f.get("data") else None
            r = self.policy.check(name, data)
            out.append({"name": name, **r})
        return {"results": out}

    def _av_check(self, name, data):
        try:
            return self.av.enforce(name, data)
        except VirusFound as e:
            raise HTTPError(422, f"Virus detected in \"{e.filename}\" ({e.signature}). The file was blocked.")
        except ScannerUnavailable as e:
            raise HTTPError(503, str(e))

    def api_scan(self, req, s):
        """Scan one attachment of a received message (used for the badge in the UI)."""
        name, ctype, data = s.account.get_attachment(req.q("folder"), int(req.q("uid") or 0), int(req.q("part") or -1))
        if self.policy.apply_incoming and self.policy.check(name, data)["verdict"] == "block":
            return {"status": "skipped", "reason": "blocked by attachment policy"}
        r = self.av.scan(name, data)
        if r["status"] == "error" and self.av.fail_mode == "block":
            r["blocked"] = True
        return r

    def api_av_status(self, req, s):
        return self.av.status()

    # ---------------------------------------------------------------- setup & self-service
    def _apply(self):
        self.mailserver.apply(self.accounts.snapshot(), suspended=self.license.locked)

    def _on_license_change(self, locked: bool):
        """Managed plan suspended for non-payment, or program files modified (or restored): lock or unlock every sign-in."""
        if not hasattr(self, "integrity"):
            return   # still starting up; the first _apply() uses the current state
        if self.mode == "bundled":
            self._apply()
        if locked:
            for sess in self.sessions.all():
                self.sessions.drop(sess.id)
        if self.license.integrity_locked:
            self.accounts.audit("integrity-check", "service.locked_modified",
                                ", ".join((self.license.integrity or {}).get("files") or [])[:500])
        else:
            self.accounts.audit("licensing-portal", "service.suspended" if locked else "service.restored", "")

    def _server_time(self) -> dict:
        tz, configured = self.site.timezone()
        return {"now": time.time(), "timezone": tz, "configured": configured}

    def _set_timezone(self, tz, actor):
        tz = (tz or "").strip()
        if not valid_timezone(tz):
            raise HTTPError(400, "Choose a valid time zone, e.g. Asia/Dubai")
        self.site.update(timezone=tz, timezone_set_by=actor, timezone_set_at=int(time.time()))
        self.accounts.audit(actor, "server.timezone", tz)

    def _send_reminders(self):
        try:
            reminders.run(self)
        except Exception:  # noqa: BLE001
            log.exception("license reminder failed")

    def _reminder_loop(self):
        while True:
            self._send_reminders()
            time.sleep(3600)

    def api_setup_status(self, req, s):
        return {"needed": bool(self.setup_token), "mode": self.mode, "license": self.license.public()}

    def api_setup(self, req, s):
        if not self.setup_token:
            raise HTTPError(409, "Setup has already been completed")
        b = req.json()
        if not self.login_limiter.blocked("setup:" + req.client_ip()) and \
                not secrets.compare_digest(str(b.get("token", "")).strip().upper(), self.setup_token):
            self.login_limiter.fail("setup:" + req.client_ip())
            raise HTTPError(403, "Wrong setup code. Find it with: docker compose logs web | grep SETUP")
        if self.login_limiter.blocked("setup:" + req.client_ip()):
            raise HTTPError(429, "Too many attempts. Wait a few minutes.")
        email = (b.get("email") or "").strip().lower()
        domain = email.split("@")[-1] if "@" in email else ""
        if self.accounts.policy_version and str(b.get("accept_policies") or "") != self.accounts.policy_version:
            raise HTTPError(400, f"Read and accept the {policies.TITLE} to continue")
        key = "".join(str(b.get("license_key") or "").split())
        if self.license.enabled and (key or not self.license.active):
            if not key:
                raise HTTPError(400, f"Enter your license key. Register for a free key at {self.license.register_url}")
            try:
                info = parse_key(key)
                if domain and domain not in info["domains"]:
                    raise HTTPError(400, f"This license key is for {', '.join(info['domains'])}. "
                                         f"Use an admin address on that domain, or add {domain} to your license on zoltismail.com")
                self.license.activate(key)
            except LicenseError as e:
                raise HTTPError(400, str(e))
        if "@" not in email:
            raise HTTPError(400, "Enter a full email address, e.g. admin@yourcompany.com")
        if not self.accounts.policy_status()["accepted"]:
            self.accounts.accept_policies(self.accounts.policy_version, email, req.client_ip())
        try:
            if not self.accounts.domain(domain):
                self.accounts.add_domain(domain, actor="setup")
                sel, pub = self.mailserver.generate_dkim(domain)
                if sel:
                    self.accounts.set_dkim(domain, sel, pub)
            self.accounts.create_account(email, b.get("password"), b.get("name", ""), None, True, actor="setup")
        except AccountError as e:
            raise HTTPError(400, str(e))
        self._apply()
        self.setup_token = None
        try:
            os.remove(os.path.join(self.cfg.get("server", "data_dir"), "setup.token"))
        except OSError:
            pass
        tz = str(b.get("timezone") or "")
        if valid_timezone(tz):          # the administrator's local time zone becomes the server time
            self._set_timezone(tz, email)
        log.info("first-run setup completed: admin %s", email)
        threading.Thread(target=self._send_reminders, daemon=True).start()   # "add your key within 7 days"
        return {"ok": True, "email": email}

    def api_change_password(self, req, s):
        if self.mode != "bundled":
            raise HTTPError(400, "Your password is managed by your mail server administrator")
        b = req.json()
        if b.get("current") != s.password:
            raise HTTPError(403, "Your current password is incorrect")
        try:
            self.accounts.update_account(s.email, actor=s.email, password=b.get("new", ""))
        except AccountError as e:
            raise HTTPError(400, str(e))
        self._apply()
        s.password = b["new"]
        s.account.password = b["new"]
        self.sessions.drop_user(s.email, keep=s.id)
        return {"ok": True}

    def api_my_quota(self, req, s):
        try:
            q = s.account.quota()
        except MailError:
            q = None
        return {"quota": q}

    # ---------------------------------------------------------------- 2-step verification, app passwords
    def _bundled_only(self):
        if self.mode != "bundled":
            raise HTTPError(400, "Two-step verification and app passwords are managed by your mail server administrator")

    def _confirm_password(self, s, b):
        key = "pw:" + s.email.lower()
        if self.login_limiter.blocked(key):
            raise HTTPError(429, "Too many wrong passwords. Wait a few minutes and try again.")
        if not secrets.compare_digest(str(b.get("password") or "").encode(), s.password.encode()):
            self.login_limiter.fail(key)
            raise HTTPError(403, "Your password is incorrect")

    def api_security(self, req, s):
        rec = self.accounts.get(s.email) or {}
        return {"available": self.mode == "bundled", "twofa": bool(rec.get("totp_secret")),
                "recovery_left": len([c for c in (rec.get("recovery_codes") or "").split(",") if c]),
                "app_password": bool(rec.get("app_pw_hash")), "app_password_created": rec.get("app_pw_created")}

    def api_2fa_start(self, req, s):
        self._bundled_only()
        self._confirm_password(s, req.json())
        if (self.accounts.get(s.email) or {}).get("totp_secret"):
            raise HTTPError(409, "Two-step verification is already on")
        s.pending_totp = totp.new_secret()
        issuer = self.app_name
        return {"secret": s.pending_totp, "uri": totp.otpauth_uri(s.pending_totp, s.email, issuer)}

    def api_2fa_enable(self, req, s):
        self._bundled_only()
        if not s.pending_totp:
            raise HTTPError(400, "Start the setup again")
        step = totp.verify(s.pending_totp, req.json().get("code"))
        if step is None:
            raise HTTPError(400, "That code isn't right. Check the time on your phone and try the newest code.")
        codes = totp.new_recovery_codes()
        self.accounts.set_totp(s.email, s.pending_totp, [totp.hash_recovery(c) for c in codes], actor=s.email)
        self.accounts.use_totp_step(s.email, step)
        s.pending_totp = None
        self._apply()
        self.sessions.drop_user(s.email, keep=s.id)
        log.info("2-step verification turned on for %s", s.email)
        return {"ok": True, "recovery_codes": codes}

    def api_2fa_disable(self, req, s):
        self._bundled_only()
        self._confirm_password(s, req.json())
        self.accounts.set_totp(s.email, None, actor=s.email)
        self._apply()
        log.info("2-step verification turned off for %s", s.email)
        return {"ok": True}

    def api_2fa_recovery(self, req, s):
        self._bundled_only()
        self._confirm_password(s, req.json())
        if not (self.accounts.get(s.email) or {}).get("totp_secret"):
            raise HTTPError(400, "Two-step verification is off")
        codes = totp.new_recovery_codes()
        self.accounts.set_recovery_codes(s.email, [totp.hash_recovery(c) for c in codes])
        self.accounts.audit(s.email, "account.2fa.recovery_new", s.email)
        return {"ok": True, "recovery_codes": codes}

    def api_app_password(self, req, s):
        self._bundled_only()
        self._confirm_password(s, req.json())
        pw = totp.new_app_password()
        self.accounts.set_app_password(s.email, hash_password(pw), actor=s.email)
        self._apply()
        return {"ok": True, "app_password": pw}

    def api_app_password_delete(self, req, s):
        self._bundled_only()
        self.accounts.set_app_password(s.email, None, actor=s.email)
        self._apply()
        return {"ok": True}

    def api_mail_setup(self, req, s):
        domain = s.email.split("@")[1].lower()
        rec = self.accounts.get(s.email) or {}
        if self.mode == "bundled":
            host = self.mailserver.hostname
            imap = {"host": host, "port": 993, "security": "SSL/TLS"}
            smtp = {"host": host, "port": 587, "security": "STARTTLS", "alt_port": 465, "alt_security": "SSL/TLS"}
        else:
            i, o = self._server_for("imap", domain), self._server_for("smtp", domain)
            sec = {"ssl": "SSL/TLS", "starttls": "STARTTLS", "plain": "None"}
            imap = {"host": i["host"], "port": i["port"], "security": sec.get(i["security"], i["security"])}
            smtp = {"host": o["host"], "port": o["port"], "security": sec.get(o["security"], o["security"])}
        return {"email": s.email, "name": rec.get("name") or self.store.load(s.email)["settings"].get("display_name") or "",
                "username": s.email, "imap": imap, "smtp": smtp, "twofa": bool(rec.get("totp_secret")),
                "app_password": bool(rec.get("app_pw_hash")), "profile": self.mode == "bundled"}

    def api_apple_profile(self, req, s):
        """iPhone / iPad / Mac configuration profile: sets up the account in Apple Mail in one tap.

        The password isn't included: the device asks for it while installing.
        """
        if self.mode != "bundled":
            raise HTTPError(400, "Not available for this server")
        import plistlib
        import uuid
        info = self.api_mail_setup(req, s)
        app = self.app_name
        host = self.mailserver.hostname
        base = f"zoltis.{host}.{s.email}"
        mail = {
            "PayloadType": "com.apple.mail.managed", "PayloadVersion": 1,
            "PayloadIdentifier": base + ".mail", "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_DNS, base + ".mail")).upper(),
            "PayloadDisplayName": s.email, "PayloadDescription": f"Email account {s.email}",
            "EmailAccountDescription": f"{s.email}", "EmailAccountName": info["name"] or s.email.split("@")[0],
            "EmailAccountType": "EmailTypeIMAP", "EmailAddress": s.email,
            "IncomingMailServerHostName": host, "IncomingMailServerPortNumber": 993, "IncomingMailServerUseSSL": True,
            "IncomingMailServerUsername": s.email, "IncomingMailServerAuthentication": "EmailAuthPassword",
            "OutgoingMailServerHostName": host, "OutgoingMailServerPortNumber": 587, "OutgoingMailServerUseSSL": True,
            "OutgoingMailServerUsername": s.email, "OutgoingMailServerAuthentication": "EmailAuthPassword",
            "OutgoingPasswordSameAsIncomingPassword": True, "SMIMEEnabled": False,
            "PreventMove": False, "PreventAppSheet": False, "disableMailRecentsSyncing": False,
        }
        profile = {
            "PayloadType": "Configuration", "PayloadVersion": 1, "PayloadContent": [mail],
            "PayloadIdentifier": base, "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_DNS, base)).upper(),
            "PayloadDisplayName": f"{app}: {s.email}", "PayloadOrganization": app,
            "PayloadDescription": "Adds your email account to the Mail app. You'll be asked for your password "
                                  "(your app password if two-step verification is on).",
            "PayloadRemovalDisallowed": False,
        }
        data = plistlib.dumps(profile, fmt=plistlib.FMT_XML)
        fname = re.sub(r"[^A-Za-z0-9._@-]", "_", s.email) + ".mobileconfig"
        req.send_bytes(data, "application/x-apple-aspen-config", {"Content-Disposition": f'attachment; filename="{fname}"'})

    # ---------------------------------------------------------------- admin console
    def _admin(self, fn):
        def wrapped(req, s):
            if not self.accounts.is_admin(s.email):
                raise HTTPError(403, "Administrator access required")
            try:
                return fn(req, s)
            except LimitReached as e:
                raise HTTPError(402, str(e))
            except PoliciesRequired as e:
                raise HTTPError(428, str(e))
            except NotLicensed as e:
                raise HTTPError(403, str(e))
            except AccountError as e:
                raise HTTPError(400, str(e))
        return wrapped

    def adm_overview(self, req, s):
        accts = self.accounts.accounts()
        lim = self.edition.limits
        return {
            "edition": self.edition.name, "mode": self.mode, "limits": lim, "license": self.license.public(full=True),
            "policies": {**policies.public(), **self.accounts.policy_status()},
            "server_time": self._server_time(),
            "accounts": len(accts), "admins": sum(1 for a in accts if a["is_admin"]),
            "aliases_counted": self.accounts.alias_count(),
            "disabled": sum(1 for a in accts if not a["enabled"]),
            "domains": len(self.accounts.domains()), "aliases": len(self.accounts.aliases()),
            "sessions": len(self.sessions.all()),
            "allocated_mb": sum(a["quota_mb"] for a in accts),
            "server": self.mailserver.status(),
            "antivirus": self.av.status(), "attachment_policy": self.policy.public(),
            "mail_hostname": getattr(self.mailserver, "hostname", None),
        }

    def adm_license(self, req, s):
        return {**self.license.public(full=True), "integrity": self.integrity.public()}

    def adm_license_activate(self, req, s):
        try:
            out = self.license.activate(str(req.json().get("key") or ""))
        except LicenseError as e:
            raise HTTPError(400, str(e))
        self.accounts.audit(s.email, "license.activate", out.get("license_id") or "")
        return out

    def adm_license_refresh(self, req, s):
        try:
            return self.license.refresh()
        except LicenseError as e:
            raise HTTPError(403, str(e))
        except ConnectionError as e:
            raise HTTPError(502, f"Couldn't reach zoltismail.com: {e}. The current activation stays in use "
                                 "until it expires")

    def adm_accounts(self, req, s):
        accts = self.accounts.accounts()
        online = {}
        for sess in self.sessions.all():
            online[sess.email.lower()] = max(online.get(sess.email.lower(), 0), sess.seen)
        if self.mode == "bundled" and req.q("usage") != "0":
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=8) as ex:
                usage = dict(zip([a["email"] for a in accts], ex.map(lambda a: self.mailserver.quota(a["email"]), accts)))
        else:
            usage = {}
        for a in accts:
            a["usage"] = usage.get(a["email"])
            a["online"] = a["email"] in online
        return {"accounts": accts, "limits": self.edition.limits, "mode": self.mode}

    def adm_account_create(self, req, s):
        b = req.json()
        a = self.accounts.create_account(b.get("email"), b.get("password"), b.get("name", ""),
                                         b.get("quota_mb"), bool(b.get("is_admin")), actor=s.email)
        self._apply()
        return a

    def adm_account_update(self, req, s):
        b = req.json()
        email = b.pop("email", "")
        if email.lower() == s.email.lower() and (b.get("is_admin") is False or b.get("enabled") is False):
            raise HTTPError(400, "You can't remove your own admin rights or disable yourself")
        allowed = {k: b[k] for k in ("name", "quota_mb", "is_admin", "enabled", "password") if k in b}
        a = self.accounts.update_account(email, actor=s.email, **allowed)
        if b.get("reset_2fa"):
            if not self.accounts.get(email):
                raise HTTPError(404, "Account not found")
            self.accounts.set_totp(email, None, actor=s.email)
            self.accounts.set_app_password(email, None, actor=s.email)
            a = self.accounts.update_account(email, actor=s.email)
        self._apply()
        if allowed.get("password") or allowed.get("enabled") is False:
            self.sessions.drop_user(email, keep=s.id if email.lower() == s.email.lower() else None)
        return a

    def adm_account_delete(self, req, s):
        b = req.json()
        email = (b.get("email") or "").lower()
        if email == s.email.lower():
            raise HTTPError(400, "You can't delete your own account")
        if not self.accounts.get(email):
            raise HTTPError(404, "Account not found")
        purged = False
        if self.mode == "bundled" and b.get("purge", True):
            try:
                self.mailserver.purge_mailbox(email)
                purged = True
            except (MailError, OSError) as e:
                log.warning("could not purge mailbox %s: %s", email, e)
        self.accounts.delete_account(email, actor=s.email)
        self._apply()
        self.sessions.drop_user(email)
        return {"ok": True, "purged": purged}

    def adm_domains(self, req, s):
        out = []
        aliases = {a["source"] for a in self.accounts.aliases()}
        for d in self.accounts.domains():
            d["dns"] = self.mailserver.dns_records(d, self.public_ip or None)
            pm = f"postmaster@{d['name']}"
            d["postmaster_ok"] = bool(self.accounts.get(pm)) or pm in aliases
            out.append(d)
        return {"domains": out, "mail_hostname": getattr(self.mailserver, "hostname", None),
                "web_hostname": getattr(self.mailserver, "web_hostname", None) or None,
                "public_ip": self.public_ip or None, "mode": self.mode,
                "max_domains": self.edition.limits.get("max_domains")}

    def adm_domain_add(self, req, s):
        name = (req.json().get("name") or "").strip().lower()
        d = self.accounts.add_domain(name, actor=s.email)
        sel, pub = self.mailserver.generate_dkim(d["name"])
        if sel:
            self.accounts.set_dkim(d["name"], sel, pub)
        self._apply()
        return self.accounts.domain(d["name"])

    def adm_domain_delete(self, req, s):
        self.accounts.delete_domain(req.json().get("name", ""), actor=s.email)
        self._apply()
        return {"ok": True}

    def adm_timezone(self, req, s):
        self._set_timezone(req.json().get("timezone"), s.email)
        return self._server_time()

    def adm_policies(self, req, s):
        return {**policies.public(), **self.accounts.policy_status()}

    def adm_policies_accept(self, req, s):
        self.accounts.accept_policies(str(req.json().get("version") or ""), s.email, req.client_ip())
        return self.adm_policies(req, s)

    def adm_mta_sts(self, req, s):
        b = req.json()
        return self.accounts.set_mta_sts((b.get("name") or "").strip().lower(), b.get("mode", ""), actor=s.email)

    # ---------------------------------------------------------------- MTA-STS (public)
    def _sts_domain(self, host):
        host = (host or "").split(":")[0].strip().lower().rstrip(".")
        if self.mode != "bundled" or not host.startswith("mta-sts."):
            return None
        d = self.accounts.domain(host[8:])
        return d if d and (d.get("mta_sts") or "testing") != "off" else None

    def api_tls_allowed(self, req, s):
        """Caddy asks this before fetching an on-demand certificate for mta-sts.<domain>."""
        if not self._sts_domain(req.q("domain")):
            raise HTTPError(404, "Not a hosted MTA-STS name")
        return {"ok": True}

    def mta_sts_policy(self, host):
        """https://mta-sts.<domain>/.well-known/mta-sts.txt (RFC 8461)."""
        d = self._sts_domain(host)
        if not d:
            return 404, b"Not found\n"
        mode = d.get("mta_sts") or "testing"
        age = 604800 if mode == "enforce" else 86400
        return 200, f"version: STSv1\r\nmode: {mode}\r\nmx: {self.mailserver.hostname}\r\nmax_age: {age}\r\n".encode()

    def adm_dns_check(self, req, s):
        domain = (req.q("domain") or "").lower()
        if not self.accounts.domain(domain):
            raise HTTPError(404, "Unknown domain")
        d = self.accounts.domain(domain)
        return dnscheck.run(domain, self.public_ip or req.q("ip") or None, d.get("dkim_selector"))

    def adm_aliases(self, req, s):
        return {"aliases": self.accounts.aliases(), "counted": self.accounts.alias_count(),
                "max_aliases": self.edition.limits.get("max_aliases"), "upgrade_url": self.license.upgrade_url}

    def adm_alias_set(self, req, s):
        b = req.json()
        a = self.accounts.add_alias(b.get("source", ""), b.get("destinations", ""), actor=s.email)
        self._apply()
        return a

    def adm_alias_delete(self, req, s):
        self.accounts.delete_alias(req.json().get("source", ""), actor=s.email)
        self._apply()
        return {"ok": True}

    def adm_sessions(self, req, s):
        return {"sessions": [{"handle": x.handle, "email": x.email, "ip": x.ip, "user_agent": x.ua,
                              "created": x.created, "last_seen": x.seen, "current": x.id == s.id}
                             for x in sorted(self.sessions.all(), key=lambda x: -x.seen)]}

    def adm_session_revoke(self, req, s):
        b = req.json()
        if b.get("email"):
            n = self.sessions.drop_user(b["email"], keep=s.id)
            self.accounts.audit(s.email, "session.revoke_all", b["email"])
            return {"ok": True, "revoked": n}
        ok = self.sessions.drop_handle(str(b.get("handle", "")))
        self.accounts.audit(s.email, "session.revoke", str(b.get("handle", "")))
        return {"ok": ok}

    def adm_audit(self, req, s):
        return {"events": self.accounts.audit_log(300)}

    def adm_import_list(self, req, s):
        return {"jobs": [j.as_dict() for j in sorted(self.jobs.values(), key=lambda j: -j.started)]}

    def adm_import_start(self, req, s):
        if self.mode != "bundled":
            raise HTTPError(400, "Mailbox import is available with the built-in mail server")
        b = req.json()
        target = (b.get("email") or "").lower()
        if not self.accounts.get(target):
            raise HTTPError(404, "Choose an existing account to import into")
        if any(j.target == target and j.state in ("queued", "running") for j in self.jobs.values()):
            raise HTTPError(409, "An import into this account is already running")
        host = (b.get("host") or "").strip()
        if not host:
            raise HTTPError(400, "Enter the old IMAP server address")
        sec = b.get("security") or "ssl"
        port = int(b.get("port") or (993 if sec == "ssl" else 143))
        src = IMAPAccount(host, port, sec, bool(b.get("verify_cert", True)), b.get("username") or target,
                          b.get("password") or "", timeout=60)
        try:
            src.connect()   # fail fast on wrong password / host
        except (AuthError, MailError) as e:
            raise HTTPError(400, f"Couldn't sign in to the old server: {e}")
        dst = self.mailserver._master(target)
        dst.close()
        job = ImportJob(target, f"{src.user}@{host}:{port}")
        self.jobs[job.id] = job
        self.accounts.audit(s.email, "import.start", f"{job.source} -> {target}")
        threading.Thread(target=run_import, args=(job, src, self.mailserver._master_account(target)),
                         daemon=True).start()
        return job.as_dict()

    # ---------------------------------------------------------------- migration (export / import)
    EXPORT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.zmexport$")

    def _export_path(self, name) -> str:
        name = os.path.basename(str(name or ""))
        if not self.EXPORT_NAME.match(name):
            raise HTTPError(400, "Invalid export file name")
        return os.path.join(self.export_dir, name)

    def _mail_used_mb(self) -> float:
        total = 0.0
        for a in self.accounts.accounts():
            q = self.mailserver.quota(a["email"]) or {}
            total += float(q.get("used_mb") or 0)
        return total

    def _migration_running(self):
        return any(j.state in ("queued", "running") for j in self.migrations.values())

    def adm_migration(self, req, s):
        import shutil
        files = []
        for n in sorted(os.listdir(self.export_dir)):
            p = os.path.join(self.export_dir, n)
            if self.EXPORT_NAME.match(n) and os.path.isfile(p):
                st = os.stat(p)
                files.append({"file": n, "size": st.st_size, "modified": int(st.st_mtime)})
        return {"jobs": [j.as_dict() for j in sorted(self.migrations.values(), key=lambda j: -j.started)],
                "files": files, "free_mb": shutil.disk_usage(self.export_dir).free // 1048576,
                "mail_mb": round(self._mail_used_mb(), 1), "mode": self.mode,
                "export_dir": self.export_dir}

    def adm_migration_export(self, req, s):
        import shutil
        if self.mode != "bundled":
            raise HTTPError(400, "Export needs the built-in mail server")
        if self._migration_running():
            raise HTTPError(409, "An export or import is already running")
        pw = str(req.json().get("passphrase") or "")
        try:
            migration.check_passphrase(pw)
        except migration.MigrationError as e:
            raise HTTPError(400, str(e))
        need = self._mail_used_mb() * 0.8 + 200
        free = shutil.disk_usage(self.export_dir).free / 1048576
        if free < need:
            raise HTTPError(507, f"Not enough free disk for the export file (needs about {need:.0f} MB, {free:.0f} MB free). "
                                 "Delete old exports or backups, or stream the export straight to another computer: "
                                 "see 'zoltis export create -' in docs/MIGRATION.md")
        host = re.sub(r"[^A-Za-z0-9.-]", "", getattr(self.mailserver, "hostname", "") or "zoltis")
        path = os.path.join(self.export_dir, f"{host}-{time.strftime('%Y%m%d-%H%M%S')}.zmexport")
        job = migration.MigrationJob("export", path)
        self.migrations[job.id] = job
        self.accounts.audit(s.email, "migration.export", job.file)
        threading.Thread(target=self._run_migration, args=(migration.export_all, path, pw, job), daemon=True).start()
        return job.as_dict()

    def adm_migration_import(self, req, s):
        if self.mode != "bundled":
            raise HTTPError(400, "Import needs the built-in mail server")
        if self._migration_running():
            raise HTTPError(409, "An export or import is already running")
        b = req.json()
        path = self._export_path(b.get("file"))
        if not os.path.isfile(path):
            raise HTTPError(404, "Export file not found on this server")
        job = migration.MigrationJob("import", path)
        self.migrations[job.id] = job
        self.accounts.audit(s.email, "migration.import", job.file)
        threading.Thread(target=self._run_migration, args=(migration.import_all, path, str(b.get("passphrase") or ""), job),
                         daemon=True).start()
        return job.as_dict()

    def _run_migration(self, fn, path, pw, job):
        try:
            fn(self, path, pw, job)
        except migration.MigrationError as e:
            job.state, job.error = "failed", str(e)
        except Exception as e:  # noqa: BLE001 - report to the admin
            job.state, job.error = "failed", str(e)
            log.error("%s failed: %s\n%s", job.kind, e, traceback.format_exc())
        finally:
            job.finished = job.finished or time.time()
            log.info("%s %s: %s (%d accounts, %d messages, %d skipped, %d failed)", job.kind, job.file, job.state,
                     job.accounts, job.messages, job.skipped, job.failed)

    def adm_migration_cancel(self, req, s):
        j = self.migrations.get(str(req.json().get("id", "")))
        if j:
            j.cancel.set()
        return {"ok": bool(j)}

    def adm_migration_delete(self, req, s):
        path = self._export_path(req.json().get("file"))
        if any(j.path == path and j.state in ("queued", "running") for j in self.migrations.values()):
            raise HTTPError(409, "This file is in use")
        try:
            os.remove(path)
        except FileNotFoundError:
            raise HTTPError(404, "Export file not found")
        self.accounts.audit(s.email, "migration.delete", os.path.basename(path))
        return {"ok": True}

    def adm_migration_download(self, req, s):
        path = self._export_path(req.q("file"))
        if not os.path.isfile(path):
            raise HTTPError(404, "Export file not found")
        self.accounts.audit(s.email, "migration.download", os.path.basename(path))
        req.send_file(path, "application/octet-stream", os.path.basename(path))

    def adm_import_cancel(self, req, s):
        j = self.jobs.get(req.json().get("id", ""))
        if j:
            j.cancel.set()
        return {"ok": bool(j)}

    def api_deliverability(self, req, s):
        domain = (req.q("domain") or s.email.split("@")[1]).lower()
        if domain != s.email.split("@")[1].lower():
            raise HTTPError(403, "You can only check your own domain")
        return dnscheck.run(domain, req.q("ip") or None, req.q("selector") or None)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}
APP_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
           "img-src 'self' data: blob: https: http:; font-src 'self' data:; frame-src 'self' blob: about:; "
           "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'")


def make_handler(app: App):
    max_body = (app.cfg.getint("server", "max_upload_mb") * 4 // 3 + 2) * 1024 * 1024
    behind_https = app.cfg.getbool("server", "behind_https")
    trust_proxy = app.cfg.getbool("server", "trust_proxy")

    class Handler(BaseHTTPRequestHandler):
        server_version = "ZoltisMail"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.client_ip(), fmt % args)

        # -- helpers --------------------------------------------------------
        def client_ip(self):
            if trust_proxy:
                xf = self.headers.get("X-Forwarded-For")
                if xf:
                    return xf.split(",")[0].strip()
            return self.client_address[0]

        def q(self, key):
            v = self._query.get(key)
            return v[0] if v else None

        def json(self):
            if self._body is None:
                n = int(self.headers.get("Content-Length") or 0)
                if n > max_body:
                    raise HTTPError(413, "Request too large")
                self._body = self.rfile.read(n) if n else b""
            try:
                return json.loads(self._body or b"{}")
            except ValueError:
                raise HTTPError(400, "Invalid JSON")

        def set_cookie(self, name, value, max_age):
            c = f"{name}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
            if behind_https:
                c += "; Secure"
            self._cookies.append(c)

        def _send(self, status, body: bytes, ctype, extra=None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            if behind_https:
                self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
            for c in self._cookies:
                self.send_header("Set-Cookie", c)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            self._sent = True

        def send_bytes(self, data, ctype, extra=None):
            self._send(200, data, ctype, {"Cache-Control": "private, no-store", **(extra or {})})

        def send_file(self, path, ctype, filename):
            """Stream a (possibly multi-GB) file without loading it into memory."""
            size = os.path.getsize(path)
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Cache-Control", "private, no-store")
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            for c in self._cookies:
                self.send_header("Set-Cookie", c)
            self.end_headers()
            self._sent = True
            if self.command == "HEAD":
                return
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)

        def send_json(self, obj, status=200):
            self._send(status, json.dumps(obj, default=str).encode(), "application/json",
                       {"Cache-Control": "no-store"})

        # -- dispatch -------------------------------------------------------
        def _dispatch(self):
            self._cookies, self._body, self._sent = [], None, False
            u = urlparse(self.path)
            self._query = parse_qs(u.query)
            path = u.path
            if path == "/healthz":
                return self._send(200, b"ok", "text/plain")
            if path == "/.well-known/mta-sts.txt" and self.command in ("GET", "HEAD"):
                code, body = app.mta_sts_policy(self.headers.get("Host"))
                return self._send(code, body, "text/plain; charset=utf-8")
            if path == "/.well-known/zoltis-mail.json" and self.command in ("GET", "HEAD"):
                return self.send_json(app.api_client_discovery(self, None))
            if not path.startswith("/api/"):
                if self.command not in ("GET", "HEAD"):
                    return self._send(405, b"", "text/plain")
                return self._static(path)
            try:
                route = app.router.find(self.command, path)
                if not route:
                    raise HTTPError(404, "Not found")
                handler, need_auth = route
                if self.command != "GET" and self.headers.get("X-Zoltis") != "1":
                    raise HTTPError(403, "Missing CSRF header")
                sess = None
                if need_auth:
                    sid = None
                    if self.headers.get("Cookie"):
                        ck = SimpleCookie(self.headers.get("Cookie"))
                        sid = ck["zm_sid"].value if "zm_sid" in ck else None
                    auth = self.headers.get("Authorization", "")
                    if not sid and auth.startswith("Bearer "):  # mobile apps / API clients
                        sid = auth[7:].strip()
                    sess = app.sessions.get(sid)
                    if not sess:
                        raise HTTPError(401, "Please sign in")
                    if app.license.locked:
                        app.sessions.drop(sess.id)
                        raise HTTPError(423, app.license.lock_message)
                result = handler(self, sess)
                if not self._sent:
                    self.send_json(result if result is not None else {"ok": True})
            except HTTPError as e:
                self.send_json({"error": e.message}, e.status)
            except AuthError as e:
                self.send_json({"error": str(e)}, 401)
            except MailError as e:
                self.send_json({"error": str(e)}, 502)
            except Exception:
                log.error("Unhandled error on %s %s\n%s", self.command, path, traceback.format_exc())
                if not self._sent:
                    self.send_json({"error": "Internal server error"}, 500)

        def _static(self, path):
            if path in ("/", "") or not os.path.splitext(path)[1]:
                path = "/index.html"
            full = os.path.realpath(os.path.join(WEB_DIR, path.lstrip("/")))
            if not full.startswith(os.path.realpath(WEB_DIR) + os.sep) or not os.path.isfile(full):
                return self._send(404, b"Not found", "text/plain")
            with open(full, "rb") as f:
                data = f.read()
            ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
                ctype += "; charset=utf-8"
            extra = {"Cache-Control": "no-cache"}
            if full.endswith(".html"):
                extra["Content-Security-Policy"] = APP_CSP
            self._send(200, data, ctype, extra)

        do_GET = do_POST = do_DELETE = do_PUT = do_HEAD = _dispatch

    return Handler


def serve(cfg):
    app = App(cfg)
    host, port = cfg.get("server", "listen"), cfg.getint("server", "port")
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    httpd.daemon_threads = True
    app.license.start()
    app.integrity.start()
    threading.Thread(target=app._reminder_loop, name="license-reminders", daemon=True).start()
    log.info("Zoltis Mail %s (%s edition) listening on http://%s:%d", __version__, app.edition.name, host, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
