#!/usr/bin/env python3
"""In-memory IMAP + SMTP server for development, demos and automated tests.

NOT for production. Implements the subset of IMAP4rev1 (+ MOVE, UIDPLUS,
SPECIAL-USE) and ESMTP that Zoltis Mail uses.

    python3 devtools/devmail.py --imap 1143 --smtp 1587 --seed
    users: demo@example.com / demo   (and alex@example.com / alex)
"""

from __future__ import annotations

import argparse
import base64
import os
import subprocess
import email
import email.policy
import re
import socketserver
import threading
import time
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid, formatdate, getaddresses
from datetime import datetime, timedelta, timezone


class Msg:
    def __init__(self, uid, raw: bytes, flags=None, when=None):
        self.uid, self.raw = uid, raw
        self.flags = set(flags or [])
        self.when = when or datetime.now(timezone.utc)
        self.parsed = email.message_from_bytes(raw, policy=email.policy.compat32)


class Mailbox:
    def __init__(self, special=None):
        self.msgs: list[Msg] = []
        self.next_uid = 1
        self.uidvalidity = int(time.time())
        self.special = special

    def add(self, raw, flags=None, when=None):
        m = Msg(self.next_uid, raw, flags, when)
        self.next_uid += 1
        self.msgs.append(m)
        return m


class Store:
    """Users come from two places: static dev users (add_user) and, like the real
    bundled Dovecot, the passwd-file rendered by Zoltis Mail (conf_dir/dovecot/users)."""

    def __init__(self):
        self.lock = threading.RLock()
        self.users: dict[str, str] = {}
        self.boxes: dict[str, dict[str, Mailbox]] = {}
        self.outbox: list[tuple[str, list[str], bytes]] = []
        self.conf_dir = None
        self.file_users: dict[str, dict] = {}
        self.master: dict[str, str] = {}
        self.aliases: dict[str, list[str]] = {}
        self.senders: dict[str, list[str]] = {}
        self._serial = None
        self._verified: dict[tuple, bool] = {}
        self.on_new_mailbox = None

    def add_user(self, user, pw):
        self.users[user] = pw
        self._ensure_box(user)

    def _ensure_box(self, user):
        if user not in self.boxes:
            self.boxes[user] = {"INBOX": Mailbox(), "Sent": Mailbox("\\Sent"), "Drafts": Mailbox("\\Drafts"),
                                "Trash": Mailbox("\\Trash"), "Junk": Mailbox("\\Junk"), "Archive": Mailbox("\\Archive")}
            if self.on_new_mailbox:
                self.on_new_mailbox(user)

    # -- emulate Dovecot/Postfix reading the shared config volume
    def sync(self):
        if not self.conf_dir:
            return
        try:
            with open(os.path.join(self.conf_dir, "serial")) as f:
                serial = f.read().strip()
        except OSError:
            return
        if serial == self._serial:
            return
        def lines(rel):
            try:
                with open(os.path.join(self.conf_dir, rel)) as f:
                    return [l.rstrip("\n") for l in f if l.strip()]
            except OSError:
                return []
        users = {}
        for l in lines("dovecot/users"):
            parts = l.split(":", 7)   # like Dovecot: everything after field 7 is extra fields
            email, pw_hash, extra = parts[0], parts[1], parts[7] if len(parts) > 7 else ""
            fields = dict(x.split("=", 1) for x in extra.split() if "=" in x)
            m = re.search(r"storage=(\d+)M", fields.get("userdb_quota_rule", ""))
            users[email] = {"hash": pw_hash, "quota_kb": int(m.group(1)) * 1024 if m else 0,
                            "nologin": fields.get("nologin") == "y", "allow_nets": fields.get("allow_nets", "")}
        app_pw = {}
        for l in lines("dovecot/app-passwords"):
            parts = l.split(":")
            app_pw[parts[0]] = parts[1]
        self.app_passwords = app_pw
        master = {}
        for l in lines("dovecot/master-users"):
            parts = l.split(":")
            master[parts[0]] = parts[1]
        self.file_users, self.master = users, master
        self.aliases = {l.split()[0]: l.split()[1].split(",") for l in lines("postfix/aliases")}
        self.senders = {l.split()[0]: l.split()[1].split(",") for l in lines("postfix/senders")}
        for u in users:
            self._ensure_box(u)
        self._serial = serial
        for svc in ("postfix", "dovecot"):
            with open(os.path.join(self.conf_dir, f"applied.{svc}"), "w") as f:
                f.write(serial + "\n")

    def _check_hash(self, pw, stored):
        key = (pw, stored)
        if key not in self._verified:
            ok = False
            if stored.startswith("{SHA512-CRYPT}$6$"):
                h = stored[len("{SHA512-CRYPT}"):]
                salt = h.split("$")[2]
                out = subprocess.run(["openssl", "passwd", "-6", "-salt", salt, "-stdin"], input=pw.encode(),
                                     capture_output=True).stdout.decode().strip()
                ok = out == h
            self._verified[key] = ok
        return self._verified[key]

    def authenticate(self, user, pw, ip="127.0.0.1"):
        """Return (mailbox_user or None, error). Like the bundled Dovecot: app password first,
        then the account password (limited to allow_nets when the account has 2-step verification)."""
        self.sync()
        if "*" not in user and user in getattr(self, "app_passwords", {}) and user in self.file_users \
                and self._check_hash(pw, self.app_passwords[user]):
            return user, None
        if "*" in user:  # master login: user*master
            target, master = user.rsplit("*", 1)
            if master in self.master and self._check_hash(pw, self.master[master]) and target in self.boxes:
                return target, None
            return None, "AUTHENTICATIONFAILED"
        if user in self.file_users:
            u = self.file_users[user]
            if not self._check_hash(pw, u["hash"]):
                return None, "AUTHENTICATIONFAILED"
            if u["allow_nets"]:
                import ipaddress
                addr = ipaddress.ip_address(ip)
                if not any(addr in ipaddress.ip_network(n.strip(), strict=False) for n in u["allow_nets"].split(",") if n.strip()):
                    return None, "AUTHENTICATIONFAILED"
            if u["nologin"]:
                return None, "AUTHORIZATIONFAILED"
            return user, None
        if self.users.get(user) == pw:
            return user, None
        return None, "AUTHENTICATIONFAILED"

    def quota_kb(self, user):
        self.sync()
        return self.file_users.get(user, {}).get("quota_kb", 0)

    def used_kb(self, user):
        return sum(len(m.raw) for mb in self.boxes.get(user, {}).values() for m in mb.msgs) // 1024

    def over_quota(self, user, extra_bytes=0):
        q = self.quota_kb(user)
        used = sum(len(m.raw) for mb in self.boxes.get(user, {}).values() for m in mb.msgs)
        return bool(q) and used + extra_bytes >= q * 1024

    def is_local(self, addr):
        self.sync()
        return addr in self.boxes


STORE = Store()

# ---------------------------------------------------------------------------
# IMAP
# ---------------------------------------------------------------------------
TOKEN_RE = re.compile(rb'\s*(\(|\)|"(?:[^"\\]|\\.)*"|\x00LIT\d+\x00|\[[^\]]*\]|[^\s()"\[]+(?:\[[^\]]*\](?:<[\d.]+>)?)?)')


def tokenize(line: bytes, lits: list[bytes]):
    out, stack = [], []
    cur = out
    pos = 0
    while pos < len(line):
        m = TOKEN_RE.match(line, pos)
        if not m or m.end() == pos:
            break
        tok = m.group(1)
        pos = m.end()
        if tok == b"(":
            new = []
            cur.append(new)
            stack.append(cur)
            cur = new
        elif tok == b")":
            cur = stack.pop() if stack else out
        elif tok.startswith(b'"'):
            cur.append(re.sub(rb'\\(.)', rb'\1', tok[1:-1]).decode())
        elif tok.startswith(b"\x00LIT"):
            cur.append(lits[int(tok[4:-1])])
        else:
            cur.append(tok.decode())
    return out


def parse_seq(spec: str, uids: list[int]) -> set[int]:
    res = set()
    mx = max(uids) if uids else 0
    for part in spec.split(","):
        if ":" in part:
            a, b = part.split(":")
            a = mx if a == "*" else int(a)
            b = mx if b == "*" else int(b)
            lo, hi = min(a, b), max(a, b)
            res |= {u for u in uids if lo <= u <= hi}
        else:
            v = mx if part == "*" else int(part)
            if v in uids:
                res.add(v)
    return res


def lit(b: bytes) -> bytes:
    return b"{%d}\r\n" % len(b) + b


def bodystructure(m: Msg) -> str:
    p = m.parsed
    def one(part):
        if part.is_multipart():
            return "(" + "".join(one(x) for x in part.get_payload()) + f' "{part.get_content_subtype().upper()}")'
        disp = part.get("Content-Disposition", "")
        d = ' ("ATTACHMENT" NIL)' if "attachment" in disp.lower() else " NIL"
        return f'("{part.get_content_maintype().upper()}" "{part.get_content_subtype().upper()}" NIL NIL NIL "7BIT" {len(str(part.get_payload()))} NIL{d} NIL)'
    return one(p)


def header_bytes(raw: bytes) -> tuple[bytes, bytes]:
    i = raw.find(b"\r\n\r\n")
    j = raw.find(b"\n\n")
    if i != -1 and (j == -1 or i < j):
        return raw[: i + 4], raw[i + 4 :]
    if j != -1:
        return raw[: j + 2], raw[j + 2 :]
    return raw, b""


class IMAPHandler(socketserver.StreamRequestHandler):
    def send(self, data: bytes):
        self.wfile.write(data)

    def line(self, s: str | bytes):
        self.send((s.encode() if isinstance(s, str) else s) + b"\r\n")

    def read_command(self):
        line = self.rfile.readline()
        if not line:
            return None
        lits, buf = [], b""
        while True:
            m = re.search(rb"\{(\d+)\+?\}\r?\n$", line)
            if not m:
                buf += line.rstrip(b"\r\n")
                break
            buf += line[: m.start()] + b"\x00LIT%d\x00" % len(lits)
            if not line[m.start():].startswith(b"{%s+" % m.group(1)):
                self.line("+ go ahead")
            lits.append(self.rfile.read(int(m.group(1))))
            line = self.rfile.readline()
        return buf, lits

    def handle(self):
        self.user = None
        self.sel: str | None = None
        self.ro = True
        self.line("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] devmail ready")
        while True:
            try:
                cmd = self.read_command()
            except (ConnectionError, OSError):
                return
            if cmd is None:
                return
            raw, lits = cmd
            toks = tokenize(raw, lits)
            if len(toks) < 2:
                self.line("* BAD empty")
                continue
            tag, verb, args = toks[0], toks[1].upper(), toks[2:]
            try:
                with STORE.lock:
                    done = self.dispatch(tag, verb, args)
                if done == "BYE":
                    return
            except Exception as e:  # pragma: no cover
                self.line(f"{tag} BAD {e}")

    @property
    def boxes(self):
        return STORE.boxes[self.user]

    def dispatch(self, tag, verb, args):
        if verb == "CAPABILITY":
            self.line("* CAPABILITY IMAP4rev1 MOVE UIDPLUS SPECIAL-USE LITERAL+ QUOTA AUTH=PLAIN")
            return self.line(f"{tag} OK done")
        if verb == "NOOP":
            return self.line(f"{tag} OK noop")
        if verb == "LOGOUT":
            self.line("* BYE")
            self.line(f"{tag} OK bye")
            return "BYE"
        if verb == "LOGIN":
            u, p = [a.decode() if isinstance(a, bytes) else a for a in args[:2]]
            who, err = STORE.authenticate(u, p, self.client_address[0])
            if who:
                self.user = who
                return self.line(f"{tag} OK logged in")
            if err == "AUTHORIZATIONFAILED":
                return self.line(f"{tag} NO [AUTHORIZATIONFAILED] Account disabled by administrator")
            return self.line(f"{tag} NO [AUTHENTICATIONFAILED] invalid credentials")
        if not self.user:
            return self.line(f"{tag} NO login first")
        if verb in ("LIST", "LSUB"):
            for name, mb in self.boxes.items():
                fl = ["\\HasNoChildren"] + ([mb.special] if mb.special else [])
                self.line(f'* {verb} ({" ".join(fl)}) "/" "{name}"')
            return self.line(f"{tag} OK done")
        if verb == "GETQUOTAROOT":
            q = STORE.quota_kb(self.user)
            self.line('* QUOTAROOT "INBOX" "User quota"')
            if q:
                self.line(f'* QUOTA "User quota" (STORAGE {STORE.used_kb(self.user)} {q})')
            return self.line(f"{tag} OK Getquotaroot completed")
        if verb == "STATUS":
            mb = self.boxes.get(args[0])
            if not mb:
                return self.line(f"{tag} NO no such mailbox")
            unseen = sum(1 for m in mb.msgs if "\\Seen" not in m.flags)
            self.line(f'* STATUS "{args[0]}" (MESSAGES {len(mb.msgs)} UNSEEN {unseen} UIDNEXT {mb.next_uid})')
            return self.line(f"{tag} OK done")
        if verb in ("SELECT", "EXAMINE"):
            mb = self.boxes.get(args[0])
            if not mb:
                return self.line(f"{tag} NO no such mailbox")
            self.sel, self.ro = args[0], verb == "EXAMINE"
            self.line(f"* {len(mb.msgs)} EXISTS")
            self.line("* 0 RECENT")
            self.line(f"* OK [UIDVALIDITY {mb.uidvalidity}] ok")
            self.line(f"* OK [UIDNEXT {mb.next_uid}] ok")
            self.line("* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)")
            return self.line(f"{tag} OK [{'READ-ONLY' if self.ro else 'READ-WRITE'}] selected")
        if verb == "CREATE":
            self.boxes.setdefault(args[0], Mailbox())
            return self.line(f"{tag} OK created")
        if verb == "DELETE":
            self.boxes.pop(args[0], None)
            return self.line(f"{tag} OK deleted")
        if verb in ("SUBSCRIBE", "UNSUBSCRIBE"):
            return self.line(f"{tag} OK")
        if verb == "APPEND":
            name = args[0]
            flags = args[1] if len(args) > 1 and isinstance(args[1], list) else []
            data = args[-1]
            mb = self.boxes.get(name)
            if mb is None:
                return self.line(f"{tag} NO [TRYCREATE] no such mailbox")
            if STORE.over_quota(self.user, len(data)):
                return self.line(f"{tag} NO [OVERQUOTA] Quota exceeded (mailbox for user is full)")
            m = mb.add(data, flags)
            return self.line(f"{tag} OK [APPENDUID {mb.uidvalidity} {m.uid}] appended")
        if verb == "CLOSE":
            self._expunge(None, silent=True)
            self.sel = None
            return self.line(f"{tag} OK closed")
        if verb == "EXPUNGE":
            self._expunge(None)
            return self.line(f"{tag} OK expunged")
        if verb == "UID":
            sub = args[0].upper()
            rest = args[1:]
            mb = self.boxes.get(self.sel) if self.sel else None
            if mb is None:
                return self.line(f"{tag} NO select first")
            uids = [m.uid for m in mb.msgs]
            if sub == "SEARCH":
                hits = self._search(mb, rest)
                self.line("* SEARCH" + "".join(f" {u}" for u in hits))
                return self.line(f"{tag} OK search done")
            target = parse_seq(rest[0], uids)
            if sub == "FETCH":
                items = rest[1] if isinstance(rest[1], list) else [rest[1]]
                for i, m in enumerate(mb.msgs, 1):
                    if m.uid in target:
                        self.send(self._fetch(i, m, items) + b"\r\n")
                return self.line(f"{tag} OK fetch done")
            if sub == "STORE":
                mode, flags = rest[1].upper(), rest[2] if isinstance(rest[2], list) else [rest[2]]
                for m in mb.msgs:
                    if m.uid in target:
                        if mode.startswith("+"):
                            m.flags |= set(flags)
                        elif mode.startswith("-"):
                            m.flags -= set(flags)
                        else:
                            m.flags = set(flags)
                return self.line(f"{tag} OK store done")
            if sub in ("COPY", "MOVE"):
                dest = self.boxes.get(rest[1])
                if dest is None:
                    return self.line(f"{tag} NO [TRYCREATE] no such mailbox")
                for m in list(mb.msgs):
                    if m.uid in target:
                        dest.add(m.raw, set(m.flags) - {"\\Deleted"}, m.when)
                        if sub == "MOVE":
                            mb.msgs.remove(m)
                return self.line(f"{tag} OK {sub.lower()} done")
            if sub == "EXPUNGE":
                self._expunge(target)
                return self.line(f"{tag} OK expunged")
        return self.line(f"{tag} BAD unknown command {verb}")

    def _expunge(self, only, silent=False):
        mb = self.boxes.get(self.sel) if self.sel else None
        if not mb:
            return
        i = 0
        while i < len(mb.msgs):
            m = mb.msgs[i]
            if "\\Deleted" in m.flags and (only is None or m.uid in only):
                mb.msgs.pop(i)
                if not silent:
                    self.line(f"* {i + 1} EXPUNGE")
            else:
                i += 1

    def _search(self, mb, crit):
        crit = [c.decode() if isinstance(c, bytes) else c for c in crit]
        if crit and crit[0].upper() == "CHARSET":
            crit = crit[2:]
        res = []
        for m in mb.msgs:
            if self._match(m, list(crit)):
                res.append(m.uid)
        return res

    def _match(self, m, crit):
        p = m.parsed
        i = 0
        ok = True
        while i < len(crit):
            c = crit[i].upper() if isinstance(crit[i], str) else crit[i]
            if c == "ALL":
                i += 1
            elif c in ("SEEN", "UNSEEN", "FLAGGED", "ANSWERED"):
                has = {"SEEN": "\\Seen", "UNSEEN": "\\Seen", "FLAGGED": "\\Flagged", "ANSWERED": "\\Answered"}[c] in m.flags
                ok &= (not has) if c == "UNSEEN" else has
                i += 1
            elif c in ("KEYWORD", "UNKEYWORD"):
                has = crit[i + 1].lower() in {f.lower() for f in m.flags}
                ok &= has if c == "KEYWORD" else not has
                i += 2
            elif c in ("FROM", "TO", "CC", "BCC", "SUBJECT"):
                ok &= crit[i + 1].lower() in str(p.get(c.title(), "")).lower()
                i += 2
            elif c == "HEADER":
                ok &= crit[i + 2].lower() in str(p.get(crit[i + 1], "")).lower()
                i += 3
            elif c in ("TEXT", "BODY"):
                ok &= crit[i + 1].lower() in m.raw.decode(errors="replace").lower()
                i += 2
            elif c in ("SINCE", "BEFORE", "ON"):
                d = datetime.strptime(crit[i + 1], "%d-%b-%Y").date()
                md = m.when.date()
                ok &= {"SINCE": md >= d, "BEFORE": md < d, "ON": md == d}[c]
                i += 2
            else:
                i += 1
        return ok

    def _fetch(self, seq, m: Msg, items):
        parts = [b"UID %d" % m.uid]
        lits = []
        hdr, body = header_bytes(m.raw)
        flat = []
        it = iter(range(len(items)))
        k = 0
        while k < len(items):
            x = items[k]
            if isinstance(x, str) and x.upper().startswith(("BODY.PEEK[HEADER.FIELDS", "BODY[HEADER.FIELDS")) and k + 1 < len(items) and isinstance(items[k + 1], list):
                flat.append((x, items[k + 1]))
                k += 2
                continue
            flat.append((x, None))
            k += 1
        for x, extra in flat:
            if not isinstance(x, str):
                continue
            X = x.upper()
            if X == "UID":
                continue
            if X == "FLAGS":
                parts.append(("FLAGS (" + " ".join(sorted(m.flags)) + ")").encode())
            elif X == "INTERNALDATE":
                parts.append(('INTERNALDATE "' + m.when.strftime("%d-%b-%Y %H:%M:%S %z") + '"').encode())
            elif X == "RFC822.SIZE":
                parts.append(b"RFC822.SIZE %d" % len(m.raw))
            elif X == "BODYSTRUCTURE":
                parts.append(b"BODYSTRUCTURE " + bodystructure(m).encode())
            elif X.startswith("BODY"):
                if "]" not in X and extra is not None:
                    X = X + " (" + " ".join(extra) + ")]"
                spec = re.search(r"\[(.*?)\]", X + ("" if "]" in X else "]"))
                spec = spec.group(1) if spec else ""
                rng = re.search(r"<(\d+)\.(\d+)>", x)
                if spec == "":
                    data = m.raw
                elif spec == "HEADER":
                    data = hdr
                elif spec == "TEXT":
                    data = body
                elif spec.startswith("HEADER.FIELDS"):
                    want = [w.lower() for w in (extra or re.findall(r"[\w-]+", spec.split("(", 1)[1]))]
                    lines, keep = [], False
                    for ln in hdr.splitlines(keepends=True):
                        if ln[:1] in (b" ", b"\t"):
                            if keep:
                                lines.append(ln)
                            continue
                        keep = ln.split(b":", 1)[0].decode(errors="replace").strip().lower() in want
                        if keep:
                            lines.append(ln)
                    data = b"".join(lines) + b"\r\n"
                    spec = "HEADER.FIELDS (" + " ".join(w.upper() for w in want) + ")"
                else:
                    data = b""
                if rng:
                    a, n = int(rng.group(1)), int(rng.group(2))
                    data = data[a : a + n]
                    name = f"BODY[{spec}]<{a}>"
                else:
                    name = f"BODY[{spec}]"
                parts.append(name.encode() + b" " + lit(data))
                if not X.startswith("BODY.PEEK") and "\\Seen" not in m.flags and not self.ro:
                    m.flags.add("\\Seen")
        return b"* %d FETCH (" % seq + b" ".join(parts) + b")"


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------
class SMTPHandler(socketserver.StreamRequestHandler):
    def line(self, s):
        self.wfile.write(s.encode() + b"\r\n")

    def handle(self):
        self.line("220 devmail ESMTP")
        user, mail_from, rcpts = None, None, []
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            cmd = raw.decode(errors="replace").strip()
            up = cmd.upper()
            if up.startswith(("EHLO", "HELO")):
                self.wfile.write(b"250-devmail\r\n250-AUTH PLAIN LOGIN\r\n250-8BITMIME\r\n250 SIZE 52428800\r\n")
            elif up.startswith("AUTH PLAIN"):
                parts = cmd.split()
                tok = parts[2] if len(parts) > 2 else None
                if not tok:
                    self.line("334 ")
                    tok = self.rfile.readline().decode().strip()
                _, u, p = base64.b64decode(tok).decode().split("\0")
                who, _ = STORE.authenticate(u, p, self.client_address[0])
                if who and "*" not in u:
                    user = u
                    self.line("235 ok")
                else:
                    self.line("535 bad credentials")
            elif up.startswith("AUTH LOGIN"):
                self.line("334 VXNlcm5hbWU6")
                u = base64.b64decode(self.rfile.readline().strip()).decode()
                self.line("334 UGFzc3dvcmQ6")
                p = base64.b64decode(self.rfile.readline().strip()).decode()
                if STORE.authenticate(u, p, self.client_address[0])[0] and "*" not in u:
                    user = u
                    self.line("235 ok")
                else:
                    self.line("535 bad credentials")
            elif up.startswith("MAIL FROM"):
                if not user:
                    self.line("530 auth required")
                    continue
                mail_from = re.search(r"<([^>]*)>", cmd).group(1)
                STORE.sync()
                if STORE.senders and user in STORE.file_users and user not in STORE.senders.get(mail_from, []):
                    self.line("553 5.7.1 Sender address rejected: not owned by user " + user)
                    continue
                rcpts = []
                self.line("250 ok")
            elif up.startswith("RCPT TO"):
                r = re.search(r"<([^>]*)>", cmd).group(1)
                targets = STORE.aliases.get(r, [r])
                if any(STORE.over_quota(t) for t in targets if t in STORE.boxes):
                    self.line("552 5.2.2 Mailbox is full")
                    continue
                rcpts.append(r)
                self.line("250 ok")
            elif up == "DATA":
                self.line("354 end with .")
                buf = []
                while True:
                    l = self.rfile.readline()
                    if l in (b".\r\n", b".\n", b""):
                        break
                    buf.append(l[1:] if l.startswith(b"..") else l)
                data = b"".join(buf)
                with STORE.lock:
                    STORE.outbox.append((mail_from, rcpts, data))
                    for r in rcpts:
                        for t in STORE.aliases.get(r, [r]):
                            if t in STORE.boxes:
                                STORE.boxes[t]["INBOX"].add(data)
                self.line("250 queued")
            elif up == "RSET":
                mail_from, rcpts = None, []
                self.line("250 ok")
            elif up == "NOOP":
                self.line("250 ok")
            elif up == "QUIT":
                self.line("221 bye")
                return
            else:
                self.line("502 not implemented")


class TS(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------------------
# Demo data
# ---------------------------------------------------------------------------
def _mk(frm, to, subject, text, html=None, when=None, attach=None, msgid_domain="example.com"):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, to, subject
    m["Date"] = format_datetime(when or datetime.now(timezone.utc))
    m["Message-ID"] = make_msgid(domain=msgid_domain)
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    if attach:
        name, ctype, data = attach
        mt, st = ctype.split("/")
        m.add_attachment(data, maintype=mt, subtype=st, filename=name)
    return m.as_bytes()


def seed():
    STORE.add_user("demo@example.com", "demo")
    STORE.add_user("alex@example.com", "alex")
    now = datetime.now(timezone.utc)
    box = STORE.boxes["demo@example.com"]
    samples = [
        ("Priya Natarajan <priya@northwind.io>", "Q4 roadmap review - slides attached",
         "Hi team,\n\nAttached are the slides for Thursday's roadmap review. Please add comments before Wednesday EOD.\n\nThanks,\nPriya",
         None, timedelta(minutes=12), ("Q4-roadmap.pdf", "application/pdf", b"%PDF-1.4 demo"), set()),
        ("GitHub <noreply@github.com>", "[zoltis] Pull request #42 merged",
         "Your pull request 'Add keyboard shortcuts' was merged into main.", None, timedelta(hours=1), None, set()),
        ("Marco Rossi <marco@acme-logistics.com>", "Re: Shipment delay for order #88213",
         "Hello,\n\nThe container cleared customs this morning. Expected delivery is now Friday.\n\n> Can you confirm the new ETA?\n\nBest regards,\nMarco",
         None, timedelta(hours=3), None, {"\\Seen"}),
        ("Finance Team <finance@example.com>", "Expense reports due Friday",
         "Reminder: please submit November expense reports by Friday 5pm.",
         "<p>Reminder: please submit <b>November expense reports</b> by <span style='color:#c5221f'>Friday 5pm</span>.</p>"
         "<p><img src='https://example.com/tracker.png' width='1' height='1'></p><script>alert(1)</script>",
         timedelta(hours=7), None, {"\\Flagged"}),
        ("Lena Fischer <lena@designhaus.de>", "Brand refresh - first concepts",
         "Hi! Here are three first directions for the brand refresh. Let me know which one resonates.",
         "<h2 style='font-family:Georgia'>Brand refresh</h2><p>Hi! Here are <b>three first directions</b>. Let me know which one resonates.</p>"
         "<table border=1 cellpadding=6><tr><td>Option A</td><td>Calm</td></tr><tr><td>Option B</td><td>Bold</td></tr><tr><td>Option C</td><td>Playful</td></tr></table>",
         timedelta(days=1), None, {"\\Seen"}),
        ("Calendar <calendar@example.com>", "Invitation: Weekly sync @ Mon 10:00",
         "You have been invited to Weekly sync, Mondays at 10:00.", None, timedelta(days=1, hours=5), None, {"\\Seen"}),
        ("Sarah Chen <sarah.chen@contoso.com>", "Contract renewal",
         "Hi, attaching the renewal draft. The main change is the SLA section.", None,
         timedelta(days=2), ("renewal-draft.txt", "text/plain", b"Renewal draft v2\nSLA: 99.9%"), {"\\Seen", "\\Answered"}),
        ("Newsletter <news@techweekly.com>", "This week in open source: 10 projects to watch",
         "Our pick of the week's best open source releases.", None, timedelta(days=3), None, {"\\Seen"}),
        ("IT Helpdesk <it@example.com>", "Scheduled maintenance this Saturday",
         "Mail services will be briefly unavailable on Saturday between 02:00 and 03:00 UTC.", None,
         timedelta(days=5), None, {"\\Seen"}),
        ("Ravi Kumar <ravi@example.com>", "Lunch next week?", "Free on Tuesday or Wednesday?", None,
         timedelta(days=8), None, {"\\Seen"}),
    ]
    for frm, subj, text, html, ago, att, flags in reversed(samples):
        box["INBOX"].add(_mk(frm, "Demo User <demo@example.com>", subj, text, html, now - ago, att), flags, now - ago)
    for i in range(30):
        w = now - timedelta(days=10 + i)
        box["INBOX"].add(_mk(f"Sender {i} <sender{i}@example.org>", "demo@example.com", f"Older message #{i}",
                             f"Body of older message {i}.", None, w), {"\\Seen"}, w)
    w = now - timedelta(hours=9)
    box["INBOX"].add(_mk("Unknown <invoice@billing-alerts.example>", "demo@example.com", "Overdue invoice - open attachment",
                         "Please see the attached invoice.", None, w, ("invoice.zip", "application/zip", EICAR)), set(), w)
    import io as _io, zipfile as _zf

    def _zip(files):
        b = _io.BytesIO()
        with _zf.ZipFile(b, "w", _zf.ZIP_DEFLATED) as z:
            for n, d in files:
                z.writestr(n, d)
        return b.getvalue()

    pe = b"MZ" + b"\0" * 512
    risky = [
        ("Shipping Notice <notice@track-parcel.example>", "Your parcel could not be delivered",
         "Open the attached label to reschedule.", ("label.pdf.exe", "application/octet-stream", pe), timedelta(hours=8)),
        ("Dev Team <dev@partner.example>", "Project files for review",
         "Zipped project folder attached.", ("project.zip", "application/zip",
                                             _zip([("project/README.txt", "read me"), ("project/tools/setup.exe", pe)])), timedelta(hours=8, minutes=30)),
        ("Accounts <accounts@example.com>", "Budget 2027 draft (macros)",
         "The workbook uses macros for the totals.", ("Budget-2027.xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12",
                                                      _zip([("[Content_Types].xml", "x"), ("xl/vbaProject.bin", "x")])), timedelta(hours=8, minutes=45)),
    ]
    for frm, subj, text, att, ago in risky:
        w = now - ago
        box["INBOX"].add(_mk(frm, "demo@example.com", subj, text, None, w, att), set(), w)
    box["INBOX"].msgs.sort(key=lambda m: m.when)
    for n, m in enumerate(box["INBOX"].msgs, 1):
        m.uid = n
    box["INBOX"].next_uid = len(box["INBOX"].msgs) + 1
    box["Sent"].add(_mk("Demo User <demo@example.com>", "Marco Rossi <marco@acme-logistics.com>",
                        "Shipment delay for order #88213", "Can you confirm the new ETA?", None, now - timedelta(days=1)), {"\\Seen"})
    box["Junk"].add(_mk("Prize Dept <win@lottery.example>", "demo@example.com", "You WON $1,000,000!!!",
                        "Click here to claim", None, now - timedelta(days=2)))


def start(imap_port=1143, smtp_port=1587, host="127.0.0.1", do_seed=True):
    if do_seed and not STORE.users:
        seed()
    i = TS((host, imap_port), IMAPHandler)
    s = TS((host, smtp_port), SMTPHandler)
    for srv in (i, s):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    return i, s


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--imap", type=int, default=1143)
    ap.add_argument("--smtp", type=int, default=1587)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--clamd", type=int, default=0, help="also run a fake clamd on this TCP port")
    a = ap.parse_args()
    start(a.imap, a.smtp, a.host)
    if a.clamd:
        start_clamd(a.clamd, a.host)
    print(f"devmail: IMAP {a.host}:{a.imap}  SMTP {a.host}:{a.smtp}  users: demo@example.com/demo, alex@example.com/alex")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------------
# Fake clamd (detects the EICAR test signature) for tests and demos
# ---------------------------------------------------------------------------
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!H+H*"


class ClamdHandler(socketserver.StreamRequestHandler):
    def handle(self):
        import struct
        cmd = b""
        while not cmd.endswith(b"\0") and len(cmd) < 64:
            ch = self.rfile.read(1)
            if not ch:
                return
            cmd += ch
        cmd = cmd.strip(b"z\0")
        if cmd == b"PING":
            self.wfile.write(b"PONG\0")
        elif cmd == b"VERSION":
            self.wfile.write(b"ClamAV 1.4.0/27450/devmail-fake\0")
        elif cmd == b"INSTREAM":
            data = b""
            while True:
                n = struct.unpack(">I", self.rfile.read(4))[0]
                if n == 0:
                    break
                data += self.rfile.read(n)
            if EICAR in data:
                self.wfile.write(b"stream: Win.Test.EICAR_HDB-1 FOUND\0")
            else:
                self.wfile.write(b"stream: OK\0")


def start_clamd(port=13310, host="127.0.0.1"):
    srv = TS((host, port), ClamdHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
