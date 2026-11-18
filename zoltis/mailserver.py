"""Bundled mail-server backend (Docker).

The web container is the only place accounts are edited. After each change it
renders plain files into a shared volume ([mail_server] conf_dir); small watcher
loops inside the postfix and dovecot containers notice the new `serial` and
reload. No container needs privileges in another.

conf_dir layout
    serial                       changes on every render (watchers poll it)
    dovecot/users                passwd-file: mailboxes, SHA512-CRYPT, per-user quota
    dovecot/master-users         master login used by the web app (quota, import, purge)
    dovecot/app-passwords        passwd-file: app passwords for mail apps (accounts with 2-step verification)
    postfix/domains              virtual_mailbox_domains
    postfix/mailboxes            virtual_mailbox_maps
    postfix/aliases              virtual_alias_maps
    postfix/senders              smtpd_sender_login_maps (anti-spoofing)
    dkim/KeyTable, dkim/SigningTable, dkim/keys/<domain>.private
"""

from __future__ import annotations

import base64
import imaplib
import logging
import os
import re
import secrets
import socket
import subprocess
import threading
import time

from .accounts import hash_password
from .mail.imap import IMAPAccount, MailError

log = logging.getLogger("zoltis.mailserver")


def _atomic_write(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


class BundledMailServer:
    def __init__(self, cfg, data_dir):
        g = lambda k, d="": os.environ.get(f"ZOLTIS_MAIL_SERVER_{k.upper()}") or cfg.raw.get("mail_server", {}).get(k) or d
        self.conf_dir = g("conf_dir", os.path.join(data_dir, "mailconf"))
        self.hostname = g("hostname", "mail.example.com")
        self.web_hostname = g("web_hostname", "")
        self.imap_host = g("imap_host", "dovecot")
        self.imap_port = int(g("imap_port", "143"))
        self.smtp_host = g("smtp_host", "postfix")
        self.smtp_port = int(g("smtp_port", "25"))
        self.master_user = g("master_user", "zoltis-master")
        self.master_nets = g("master_allow_nets", "127.0.0.1/32,172.28.0.0/24")
        self.dkim_selector = g("dkim_selector", "zoltis")
        # Links from the web app to Dovecot use STARTTLS too (plain only for old setups/tests)
        self.internal_security = g("internal_security", "starttls")
        self.secret_path = os.path.join(data_dir, "master.secret")
        self.lock = threading.Lock()
        self._quota_cache: dict[str, tuple[float, dict]] = {}
        os.makedirs(self.conf_dir, exist_ok=True)
        self.master_password = self._master_secret()

    # ------------------------------------------------------------------ secrets
    def _master_secret(self) -> str:
        if os.path.exists(self.secret_path):
            with open(self.secret_path) as f:
                return f.read().strip()
        pw = secrets.token_urlsafe(32)
        _atomic_write(self.secret_path, pw, 0o600)
        return pw

    # ------------------------------------------------------------------ DKIM
    def generate_dkim(self, domain: str) -> tuple[str, str]:
        """Create a 2048-bit DKIM key for domain. Returns (selector, public_key_base64)."""
        keydir = os.path.join(self.conf_dir, "dkim", "keys")
        os.makedirs(keydir, exist_ok=True)
        key_path = os.path.join(keydir, f"{domain}.private")
        if not os.path.exists(key_path):
            pem = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, check=True, timeout=60).stdout
            _atomic_write(key_path, pem.decode(), 0o600)
        der = subprocess.run(["openssl", "rsa", "-in", key_path, "-pubout", "-outform", "DER"],
                             capture_output=True, check=True, timeout=30).stdout
        return self.dkim_selector, base64.b64encode(der).decode()

    # ------------------------------------------------------------------ render
    def apply(self, snap: dict, suspended: bool = False):
        """Render every file the mail containers read, then bump the serial.

        suspended: managed plan locked for non-payment. Nobody can sign in (IMAP, POP, SMTP), but the
        mailboxes stay in the user database, so incoming mail is still delivered and kept.
        """
        with self.lock:
            accounts = snap["accounts"]
            domains = [d["name"] for d in snap["domains"]]
            local = {a["email"] for a in accounts}
            users, app_pw = [], []
            for a in accounts:
                if not a.get("pw_hash"):
                    continue
                extra = [f"userdb_quota_rule=*:storage={int(a['quota_mb'])}M"]
                if suspended:
                    extra += ["nologin=y", "reason=Service_suspended_-_contact_Zoltis_via_the_customer_portal"]
                elif not a["enabled"]:
                    extra += ["nologin=y", "reason=Account_disabled_by_administrator"]
                elif a.get("totp_secret"):
                    # Two-step verification on: the account password only works from the webmail
                    # container (which asks for the code). Mail apps must use the app password.
                    extra.append(f"allow_nets={self.master_nets}")
                users.append(f"{a['email']}:{a['pw_hash']}::::::{' '.join(extra)}")
                if a["enabled"] and a.get("app_pw_hash") and not suspended:
                    app_pw.append(f"{a['email']}:{a['app_pw_hash']}::::::")
            _atomic_write(os.path.join(self.conf_dir, "dovecot", "users"), "\n".join(users) + "\n", 0o640)
            _atomic_write(os.path.join(self.conf_dir, "dovecot", "app-passwords"), "\n".join(app_pw) + "\n", 0o640)
            master_hash = hash_password(self.master_password)
            _atomic_write(os.path.join(self.conf_dir, "dovecot", "master-users"),
                          f"{self.master_user}:{master_hash}::::::allow_nets={self.master_nets}\n", 0o640)

            pf = os.path.join(self.conf_dir, "postfix")
            _atomic_write(os.path.join(pf, "domains"), "".join(f"{d} OK\n" for d in domains))
            _atomic_write(os.path.join(pf, "mailboxes"), "".join(f"{a['email']} OK\n" for a in accounts))
            _atomic_write(os.path.join(pf, "aliases"),
                          "".join(f"{al['source']} {','.join(al['destinations'])}\n" for al in snap["aliases"]))
            senders = [f"{a['email']} {a['email']}" for a in accounts]
            for al in snap["aliases"]:
                owners = [d for d in al["destinations"] if d in local]
                if owners:
                    senders.append(f"{al['source']} {','.join(owners)}")
            _atomic_write(os.path.join(pf, "senders"), "\n".join(senders) + "\n")

            dk = os.path.join(self.conf_dir, "dkim")
            kt, st = [], []
            for d in snap["domains"]:
                if d.get("dkim_selector") and os.path.exists(os.path.join(dk, "keys", f"{d['name']}.private")):
                    rec = f"{d['dkim_selector']}._domainkey.{d['name']}"
                    kt.append(f"{rec} {d['name']}:{d['dkim_selector']}:/etc/opendkim/keys/{d['name']}.private")
                    st.append(f"*@{d['name']} {rec}")
            _atomic_write(os.path.join(dk, "KeyTable"), "\n".join(kt) + "\n")
            _atomic_write(os.path.join(dk, "SigningTable"), "\n".join(st) + "\n")
            _atomic_write(os.path.join(self.conf_dir, "serial"), f"{time.time():.6f}\n")
            self._quota_cache.clear()
        log.info("mail server config rendered: %d domains, %d mailboxes, %d aliases",
                 len(domains), len(accounts), len(snap["aliases"]))

    # ------------------------------------------------------------------ master login helpers
    def _master(self, email) -> IMAPAccount:
        a = IMAPAccount(self.imap_host, self.imap_port, self.internal_security, False, f"{email}*{self.master_user}",
                        self.master_password, timeout=15)
        a.connect()
        return a

    def _master_account(self, email) -> IMAPAccount:
        """Not yet connected (the importer connects it in its own thread)."""
        return IMAPAccount(self.imap_host, self.imap_port, self.internal_security, False, f"{email}*{self.master_user}",
                           self.master_password, timeout=60)

    def quota(self, email: str, max_age=60) -> dict | None:
        """{'used_mb', 'limit_mb', 'percent'} via IMAP QUOTA, cached for max_age seconds."""
        hit = self._quota_cache.get(email)
        if hit and time.time() - hit[0] < max_age:
            return hit[1]
        try:
            acct = self._master(email)
            try:
                q = acct.quota()
            finally:
                acct.close()
        except (MailError, OSError) as e:
            log.debug("quota lookup failed for %s: %s", email, e)
            return None
        self._quota_cache[email] = (time.time(), q)
        return q

    def deliver_notice(self, email: str, raw: bytes):
        """Put a system notice straight into a user's Inbox (unread), through the internal master login."""
        acct = self._master(email)
        try:
            acct.append("INBOX", raw, flags=None)
        finally:
            acct.close()

    def purge_mailbox(self, email: str):
        """Delete every message and folder of a mailbox (used when an account is deleted)."""
        acct = self._master(email)
        try:
            folders = sorted(acct.folders(with_counts=False), key=lambda x: -len(x["name"]))
            for f in folders:
                uids = acct.all_uids(f["name"])
                if uids:
                    acct.purge(f["name"], uids)
            for f in folders:
                if f["name"].upper() != "INBOX":
                    try:
                        acct.delete_folder(f["name"])
                    except MailError:
                        pass
        finally:
            acct.close()

    def status(self) -> dict:
        def tcp(host, port):
            try:
                with socket.create_connection((host, port), timeout=2):
                    return True
            except OSError:
                return False
        serial_file = os.path.join(self.conf_dir, "serial")
        applied = {}
        for svc in ("postfix", "dovecot"):
            p = os.path.join(self.conf_dir, f"applied.{svc}")
            try:
                with open(p) as f:
                    applied[svc] = f.read().strip()
            except OSError:
                applied[svc] = None
        try:
            with open(serial_file) as f:
                serial = f.read().strip()
        except OSError:
            serial = None
        return {
            "hostname": self.hostname,
            "imap": tcp(self.imap_host, self.imap_port),
            "smtp": tcp(self.smtp_host, self.smtp_port),
            "serial": serial,
            "synced": {k: (v == serial) if serial else None for k, v in applied.items()},
        }

    def dns_records(self, domain: dict, public_ip: str | None = None) -> list[dict]:
        """DNS records the customer must publish for this domain.

        `name`/`value` are the classic zone-file form. The extra fields match the Cloudflare
        "Add record" form: `host` (Name, relative to the zone: @, mail, _dmarc, ...), `content`,
        `priority` (MX only), `proxy` ("DNS only" for A records: Cloudflare's proxy only carries
        web traffic, so a proxied mail host can't receive or send mail), and `zone` (the
        Cloudflare site the record belongs in, or None for PTR, which is set at the IP's owner).
        """
        name = domain["name"]

        def rel(fqdn):
            if fqdn == name:
                return "@", name
            if fqdn.endswith("." + name):
                return fqdn[: -len(name) - 1], name
            parts = fqdn.split(".")                     # host in another zone, e.g. mail.firstdomain.com
            return parts[0], ".".join(parts[1:])

        def rec(type_, fqdn, content, purpose, **extra):
            host, zone = rel(fqdn)
            value = f"{extra['priority']} {content}." if type_ == "MX" else content
            return {"type": type_, "name": fqdn, "value": value, "host": host, "zone": zone, "content": content,
                    "priority": extra.get("priority"), "proxy": extra.get("proxy"), "purpose": purpose}

        recs = [
            rec("MX", name, self.hostname, "Receive mail", priority=10),
            rec("TXT", name, f"v=spf1 mx a:{self.hostname} -all", "SPF: who may send"),
            rec("TXT", f"_dmarc.{name}", f"v=DMARC1; p=quarantine; rua=mailto:postmaster@{name}; fo=1", "DMARC policy"),
        ]
        sts = domain.get("mta_sts") or "testing"
        if sts != "off":
            recs += [
                rec("CNAME", f"mta-sts.{name}", self.hostname,
                    "MTA-STS: hosts the policy that makes other servers use encryption", proxy="DNS only"),
                rec("TXT", f"_mta-sts.{name}", f"v=STSv1; id={domain.get('mta_sts_id') or '1'}",
                    f"MTA-STS policy ({sts}). Update this record whenever you change the mode"),
                rec("TXT", f"_smtp._tls.{name}", f"v=TLSRPTv1; rua=mailto:postmaster@{name}",
                    "TLS reports: other servers tell you if encrypted delivery fails"),
            ]
        if domain.get("dkim_public"):
            recs.append(rec("TXT", f"{domain['dkim_selector']}._domainkey.{name}",
                            f"v=DKIM1; k=rsa; p={domain['dkim_public']}", "DKIM signature key"))
        if public_ip:
            recs.insert(0, rec("A", self.hostname, public_ip, "Mail server address", proxy="DNS only"))
            if self.web_hostname and self.web_hostname != self.hostname:
                recs.insert(1, rec("A", self.web_hostname, public_ip, "Webmail address", proxy="DNS only"))
            recs.append({"type": "PTR", "name": public_ip, "value": self.hostname, "host": public_ip, "zone": None,
                         "content": self.hostname, "priority": None, "proxy": None,
                         "purpose": "Reverse DNS: set at your hosting provider, not in Cloudflare"})
        return recs


class ExternalMailServer:
    """Accounts live on someone else's server: nothing to render."""

    hostname = None

    def apply(self, snap, suspended=False):
        pass

    def generate_dkim(self, domain):
        return None, None

    def quota(self, email, max_age=60):
        return None

    def deliver_notice(self, email, raw):
        pass

    def purge_mailbox(self, email):
        pass

    def status(self):
        return {"external": True}

    def dns_records(self, domain, public_ip=None):
        return []

