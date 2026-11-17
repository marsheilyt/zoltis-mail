"""Export everything from one Zoltis Mail server and import it into another.

Used to move a self-hosted Community install to a server managed by Zoltis
(Mail Pro), or between servers. One encrypted file carries:

  - domains, including their DKIM private keys (DNS records stay valid)
  - accounts with password hashes (people keep their passwords), name, storage
    limit, admin flag, enabled flag
  - aliases
  - each user's settings, signature and contacts
  - every message in every folder (Inbox, Sent, Drafts, Archive, Trash, Junk
    and custom folders), attachments included, with read/starred/answered
    flags and the original received date

File format (.zmexport), see docs/MIGRATION.md:
  openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -md sha256  over a  tar.gz (PAX)
  manifest.json, domains.json, accounts.json, aliases.json, users/<email>.json,
  then mail/<email>/<n>/folder.json followed by that folder's <uid>.eml files
  (flags and date in PAX headers), and finally end.json.

Import is safe to run again: domains/accounts/aliases that exist are kept, and
messages already in the destination folder (same Message-ID) are skipped.
"""

from __future__ import annotations

import email
import email.policy
import imaplib
import io
import json
import logging
import os
import re
import subprocess
import tarfile
import threading
import time
import uuid

from . import __version__
from .accounts import AccountError, LimitReached
from .mail.imap import AuthError, MailError, _parse_fetch

log = logging.getLogger("zoltis.migration")

FORMAT, VERSION = "zoltis-export", 1
EXT = ".zmexport"
BATCH = 25
MIN_PASSPHRASE = 10
PBKDF2_ITER = "600000"
FLAGS_KEY, DATE_KEY = "ZOLTIS.flags", "ZOLTIS.internaldate"


class MigrationError(Exception):
    """User-facing problem with an export file or passphrase."""


class Cancelled(Exception):
    pass


class MigrationJob:
    def __init__(self, kind: str, path: str):
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind            # export | import
        self.path = path
        self.file = os.path.basename(path) if path not in ("-", "") else "(stream)"
        self.state = "queued"       # queued | running | done | failed | cancelled
        self.current = ""
        self.accounts = self.messages = self.skipped = self.failed = 0
        self.total = 0
        self.bytes = 0
        self.warnings: list[str] = []
        self.error = ""
        self.started = time.time()
        self.finished = None
        self.cancel = threading.Event()

    def check(self):
        if self.cancel.is_set():
            raise Cancelled()

    def warn(self, msg):
        log.warning("%s: %s", self.kind, msg)
        if len(self.warnings) < 200:
            self.warnings.append(msg)

    def as_dict(self):
        return {k: getattr(self, k) for k in ("id", "kind", "file", "state", "current", "accounts", "messages",
                                               "skipped", "failed", "total", "bytes", "warnings", "error",
                                               "started", "finished")}


def check_passphrase(p: str):
    if len(p or "") < MIN_PASSPHRASE:
        raise MigrationError(f"Use a passphrase of at least {MIN_PASSPHRASE} characters. "
                             "Anyone with the file and the passphrase can read all mail in it")


# ---------------------------------------------------------------------------
# Encryption (openssl enc, so the file can also be opened with standard tools)
# ---------------------------------------------------------------------------
def _openssl(decrypt: bool, passphrase: str, infile=None, outfile=None):
    r, w = os.pipe()
    os.write(w, passphrase.encode())
    os.close(w)
    cmd = ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", PBKDF2_ITER, "-md", "sha256", "-pass", f"fd:{r}"]
    cmd.insert(2, "-d") if decrypt else cmd.append("-salt")
    try:
        return subprocess.Popen(cmd, stdin=infile if infile is not None else subprocess.PIPE,
                                stdout=outfile if outfile is not None else subprocess.PIPE,
                                stderr=subprocess.PIPE, pass_fds=(r,))
    finally:
        os.close(r)


class _Counter(io.RawIOBase):
    """Write-through wrapper that counts bytes (for progress)."""

    def __init__(self, raw, job):
        self.raw, self.job = raw, job

    def writable(self):
        return True

    def write(self, b):
        self.raw.write(b)
        self.job.bytes += len(b)
        return len(b)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
def _add_json(tf, name, obj):
    data = json.dumps(obj, indent=1, default=str).encode()
    ti = tarfile.TarInfo(name)
    ti.size, ti.mtime, ti.mode = len(data), int(time.time()), 0o600
    tf.addfile(ti, io.BytesIO(data))


def _dkim_private(app, domain) -> str | None:
    conf = getattr(app.mailserver, "conf_dir", None)
    if not conf:
        return None
    try:
        with open(os.path.join(conf, "dkim", "keys", f"{domain}.private")) as f:
            return f.read()
    except OSError:
        return None


def export_all(app, out_path: str, passphrase: str, job: MigrationJob, out_stream=None):
    """Write the export to out_path, or to out_stream (a binary file object) when out_path == '-'."""
    check_passphrase(passphrase)
    if app.mode != "bundled":
        raise MigrationError("Export needs the built-in mail server (bundled mode)")
    job.state = "running"
    db, ms = app.accounts, app.mailserver
    snap = db.snapshot()
    tmp = None
    if out_path == "-":
        sink = out_stream
    else:
        tmp = out_path + ".part"
        sink = open(tmp, "wb")
        os.chmod(tmp, 0o600)
    enc = _openssl(False, passphrase, outfile=sink)
    ok = False
    try:
        # count first, so progress can be shown
        job.current = "Counting messages"
        for a in snap["accounts"]:
            try:
                acct = ms._master_account(a["email"])
                acct.connect()
                job.total += sum(f["total"] for f in acct.folders(with_counts=True) if f["role"] != "all")
                acct.close()
            except (MailError, OSError) as e:
                job.warn(f"{a['email']}: couldn't open the mailbox to count messages ({e})")
        tf = tarfile.open(fileobj=_Counter(enc.stdin, job), mode="w|gz", format=tarfile.PAX_FORMAT)
        lic = getattr(app, "license", None)
        _add_json(tf, "manifest.json", {
            "format": FORMAT, "version": VERSION, "created": int(time.time()), "app_version": __version__,
            "edition": app.edition.name, "license_id": (lic.info or {}).get("lid") if lic else None,
            "mail_hostname": getattr(ms, "hostname", None),
            "counts": {"domains": len(snap["domains"]), "accounts": len(snap["accounts"]),
                       "aliases": len(snap["aliases"]), "messages": job.total}})
        _add_json(tf, "domains.json", [{"name": d["name"], "created": d["created"], "dkim_selector": d.get("dkim_selector"),
                                        "dkim_public": d.get("dkim_public"), "dkim_private": _dkim_private(app, d["name"])}
                                       for d in snap["domains"]])
        _add_json(tf, "accounts.json", [{k: a.get(k) for k in ("email", "domain", "name", "pw_hash", "quota_mb",
                                                               "is_admin", "enabled", "created", "last_login")}
                                        for a in snap["accounts"]])
        _add_json(tf, "aliases.json", snap["aliases"])
        for a in snap["accounts"]:
            _add_json(tf, f"users/{a['email']}.json", app.store.load(a["email"]))
        for a in snap["accounts"]:
            job.check()
            _export_mailbox(ms, a["email"], tf, job)
            job.accounts += 1
        _add_json(tf, "end.json", {"complete": True, "messages": job.messages, "accounts": job.accounts})
        tf.close()
        enc.stdin.close()
        if enc.wait() != 0:
            raise MigrationError("Encryption failed: " + enc.stderr.read().decode(errors="replace")[:200])
        ok = True
        if tmp:
            sink.close()
            os.replace(tmp, out_path)
        job.state = "done"
    except Cancelled:
        job.state = "cancelled"
    finally:
        if not ok:
            try:
                enc.stdin.close()
            except OSError:
                pass
            enc.kill()
            enc.wait()
            if tmp:
                sink.close()
                try:
                    os.remove(tmp)
                except OSError:
                    pass
        job.current = ""
        job.finished = time.time()


def _export_mailbox(ms, mail_addr, tf, job):
    job.current = mail_addr
    acct = ms._master_account(mail_addr)
    try:
        acct.connect()
        folders = [f for f in acct.folders(with_counts=False) if f["role"] != "all"]
        for i, f in enumerate(folders):
            job.check()
            base = f"mail/{mail_addr}/{i}"
            _add_json(tf, f"{base}/folder.json", {"name": f["name"], "role": f["role"], "delim": f["delim"]})
            uids = acct.all_uids(f["name"])
            for j in range(0, len(uids), BATCH):
                job.check()
                chunk = ",".join(map(str, uids[j:j + BATCH]))
                data = acct._run(lambda c: (acct._select(c, f["name"], readonly=True),
                                            c.uid("FETCH", chunk, "(UID FLAGS INTERNALDATE BODY.PEEK[])"))[1][1])
                for m in _parse_fetch(data):
                    raw = m["parts"].get("BODY[]")
                    if raw is None:
                        job.failed += 1
                        continue
                    flags = " ".join(x for x in m["flags"] if x.lower() != "\\recent")
                    ti = tarfile.TarInfo(f"{base}/{m['uid']}.eml")
                    ti.size, ti.mtime, ti.mode = len(raw), int(time.time()), 0o600
                    ti.pax_headers = {FLAGS_KEY: flags, DATE_KEY: m["internaldate"] or ""}
                    tf.addfile(ti, io.BytesIO(raw))
                    job.messages += 1
    except (AuthError, MailError, OSError) as e:
        job.failed += 1
        job.warn(f"{mail_addr}: mailbox export stopped: {e}")
    finally:
        acct.close()


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------
def _connect_retry(ms, mail_addr, job, timeout=90):
    """New accounts become usable once Dovecot reloads its users file (a few seconds)."""
    end = time.time() + timeout
    while True:
        acct = ms._master_account(mail_addr)
        try:
            acct.connect()
            return acct
        except (AuthError, MailError, OSError):
            acct.close()
            if time.time() > end:
                raise
            job.check()
            time.sleep(2)


def _message_ids(acct, folder) -> set[str]:
    from .importer import _message_ids as mids
    try:
        return mids(acct, folder)
    except MailError:
        return set()


def import_all(app, in_path: str, passphrase: str, job: MigrationJob, in_stream=None):
    if app.mode != "bundled":
        raise MigrationError("Import needs the built-in mail server (bundled mode)")
    job.state = "running"
    src = in_stream if in_path == "-" else open(in_path, "rb")
    dec = _openssl(True, passphrase, infile=src)
    state = {"manifest": None, "complete": False, "skip_mail": set(), "acct": None, "acct_email": None,
             "folder": None, "existing": set(), "full": set()}
    try:
        try:
            tf = tarfile.open(fileobj=dec.stdout, mode="r|gz")
            for m in tf:
                job.check()
                _import_member(app, tf, m, state, job)
        except (tarfile.TarError, EOFError, OSError, ValueError, UnicodeDecodeError) as e:
            dec.kill()
            err = dec.stderr.read().decode(errors="replace")
            if state["manifest"] is None or "bad decrypt" in err:
                raise MigrationError("Wrong passphrase, or this isn't a Zoltis Mail export file")
            raise MigrationError(f"The export file is damaged or incomplete: {e}")
        dec.wait()
        if state["manifest"] is None:
            raise MigrationError("Wrong passphrase, or this isn't a Zoltis Mail export file")
        if not state["complete"]:
            job.warn("The export file ends early (it was cut off). Everything up to that point was imported; "
                     "export again and re-import to get the rest. Messages already imported are skipped")
        job.state = "done"
    except Cancelled:
        job.state = "cancelled"
    finally:
        if state["acct"]:
            state["acct"].close()
        if dec.poll() is None:
            dec.kill()
        dec.wait()
        if src is not in_stream:
            src.close()
        try:
            app._apply()
        except Exception as e:  # noqa: BLE001
            log.warning("could not re-render mail server config after import: %s", e)
        job.current = ""
        job.finished = time.time()


def _read_json(tf, m):
    return json.loads(tf.extractfile(m).read())


def _import_member(app, tf, m, st, job):
    name, db, ms = m.name, app.accounts, app.mailserver
    if name == "manifest.json":
        man = _read_json(tf, m)
        if man.get("format") != FORMAT:
            raise MigrationError("This isn't a Zoltis Mail export file")
        if int(man.get("version", 0)) > VERSION:
            raise MigrationError("This export was made by a newer Zoltis Mail. Update this server first")
        st["manifest"] = man
        job.total = int(man.get("counts", {}).get("messages") or 0)
        return
    if st["manifest"] is None:
        raise MigrationError("This isn't a Zoltis Mail export file")
    if name == "domains.json":
        job.current = "Domains"
        for d in _read_json(tf, m):
            _import_domain(app, d, job)
        return
    if name == "accounts.json":
        job.current = "Accounts"
        for a in _read_json(tf, m):
            try:
                created = db.import_account(a, actor="import")
                if created.get("_capped"):
                    job.warn(f"{a['email']}: storage limit lowered to {created['quota_mb']} MB (this edition's maximum)")
                job.accounts += 1
            except AccountError as e:
                if db.get(a.get("email", "")):
                    job.accounts += 1         # already here: keep it, merge mail
                    continue
                st["skip_mail"].add((a.get("email") or "").lower())
                job.warn(f"{a.get('email')}: not imported ({e}). Its mail is skipped")
        app._apply()
        return
    if name == "aliases.json":
        for al in _read_json(tf, m):
            try:
                db.add_alias(al["source"], al["destinations"], actor="import")
            except AccountError as e:
                job.warn(f"alias {al.get('source')}: not imported ({e})")
        app._apply()
        return
    if name.startswith("users/") and name.endswith(".json"):
        addr = name[len("users/"):-len(".json")].lower()
        if db.get(addr):
            data, cur = _read_json(tf, m), app.store.load(addr)
            if not os.path.exists(app.store._path(addr)):
                app.store.save(addr, data)
            else:   # keep this server's settings, add the contacts it doesn't know yet
                cur["contacts"] = {**data.get("contacts", {}), **cur.get("contacts", {})}
                app.store.save(addr, cur)
        return
    if name == "end.json":
        st["complete"] = bool(_read_json(tf, m).get("complete"))
        return
    mm = re.match(r"^mail/([^/]+)/(\d+)/(folder\.json|\d+\.eml)$", name)
    if not mm:
        return                      # unknown entry from a newer version: ignore
    addr = mm.group(1).lower()
    if addr in st["skip_mail"] or addr in st["full"]:
        if mm.group(3) != "folder.json":
            job.skipped += 1
        return
    if st["acct_email"] != addr:
        if st["acct"]:
            st["acct"].close()
        job.current = addr
        try:
            st["acct"] = _connect_retry(ms, addr, job)
            st["acct"].folders(with_counts=False)
            st["acct_email"] = addr
        except (AuthError, MailError, OSError) as e:
            st["acct"], st["acct_email"] = None, None
            st["skip_mail"].add(addr)
            job.warn(f"{addr}: couldn't open the mailbox on this server ({e}). Its mail is skipped")
            return
    acct = st["acct"]
    if mm.group(3) == "folder.json":
        f = _read_json(tf, m)
        dest = acct.role_folder(f["role"]) if f.get("role") and f["role"] != "inbox" else None
        if f.get("role") == "inbox" or f["name"].upper() == "INBOX":
            dest = "INBOX"
        if not dest:
            dest = f["name"]
            if dest not in [x["name"] for x in (acct._folders_cache or [])]:
                try:
                    acct.create_folder(dest)
                except MailError:
                    pass
                acct.folders(with_counts=False)
        st["folder"], st["existing"] = dest, _message_ids(acct, dest)
        return
    raw = tf.extractfile(m).read()
    mid = email.message_from_bytes(raw[:65536], policy=email.policy.compat32).get("Message-ID", "").strip()
    if mid and mid in st["existing"]:
        job.skipped += 1
        return
    flags = m.pax_headers.get(FLAGS_KEY, "")
    when = m.pax_headers.get(DATE_KEY) or ""
    when = f'"{when}"' if when else imaplib.Time2Internaldate(time.time())
    try:
        acct.append(st["folder"] or "INBOX", raw, f"({flags})", when)
        job.messages += 1
        if mid:
            st["existing"].add(mid)
    except MailError as e:
        if "full" in str(e).lower():
            st["full"].add(addr)
            job.warn(f"{addr}: the mailbox is full (storage limit reached). The rest of its mail is skipped")
        job.failed += 1


def _import_domain(app, d, job):
    db, ms = app.accounts, app.mailserver
    name = d["name"]
    existed = bool(db.domain(name))
    if not existed:
        try:
            db.add_domain(name, actor="import")
        except AccountError as e:
            job.warn(f"domain {name}: not imported ({e})")
            return
    conf = getattr(ms, "conf_dir", None)
    key_path = os.path.join(conf, "dkim", "keys", f"{name}.private") if conf else None
    if d.get("dkim_private") and key_path and (not existed or not os.path.exists(key_path)):
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        from .mailserver import _atomic_write
        _atomic_write(key_path, d["dkim_private"], 0o600)
        db.set_dkim(name, d.get("dkim_selector") or getattr(ms, "dkim_selector", "zoltis"), d.get("dkim_public"))
    elif not existed:
        sel, pub = ms.generate_dkim(name)
        if sel:
            db.set_dkim(name, sel, pub)
            job.warn(f"domain {name}: the export had no DKIM key, so a new one was made. Update its DKIM DNS record")


__all__ = ["MigrationJob", "MigrationError", "export_all", "import_all", "check_passphrase", "EXT", "LimitReached"]
