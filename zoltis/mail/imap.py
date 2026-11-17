"""High-level IMAP client used by the web API.

Works with any standards-compliant IMAP4rev1 server (Dovecot, Cyrus, Courier,
Exchange, Zimbra, Stalwart, hMailServer, Gmail, ...). Uses optional
extensions (MOVE, UIDPLUS, SPECIAL-USE) when the server advertises them.
"""

from __future__ import annotations

import email
import email.policy
import imaplib
import re
import socket
import ssl
import threading
import time
from collections import OrderedDict
from datetime import datetime, timedelta
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_to_datetime

from . import utf7
from .sanitize import html_to_text, sanitize_html, snippet, text_to_html

imaplib._MAXLINE = 10_000_000  # large FETCH responses from some servers

SPECIAL_ORDER = ["inbox", "starred", "drafts", "sent", "archive", "junk", "trash", "all"]
NAME_HINTS = {
    "sent": ["sent", "sent items", "sent mail", "sent messages", "inbox.sent", "[gmail]/sent mail"],
    "drafts": ["drafts", "draft", "inbox.drafts", "[gmail]/drafts"],
    "trash": ["trash", "deleted", "deleted items", "deleted messages", "bin", "inbox.trash", "[gmail]/trash", "[gmail]/bin"],
    "junk": ["junk", "spam", "junk e-mail", "junk email", "bulk mail", "inbox.junk", "inbox.spam", "[gmail]/spam"],
    "archive": ["archive", "archives", "inbox.archive"],
    "all": ["[gmail]/all mail", "all mail"],
}
LIST_RE = re.compile(rb'\((?P<flags>[^)]*)\) (?P<delim>"[^"]*"|NIL) (?P<name>.+)')


class MailError(Exception):
    pass


class AuthError(MailError):
    pass


def _dh(value) -> str:
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


def _addrs(value) -> list[dict]:
    if not value:
        return []
    out = []
    raw = _dh(value)
    pairs = getaddresses([raw])
    if pairs == [("", "")] and raw.strip():
        try:  # Python 3.13+ strict parser rejects some real-world headers
            pairs = getaddresses([raw], strict=False)
        except TypeError:
            pairs = []
        if pairs == [("", "")]:
            pairs = [("", raw.strip())]
    for name, addr in pairs:
        if addr or name:
            out.append({"name": name, "email": addr})
    return out


def _date(value) -> str | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(str(value)).isoformat()
    except Exception:
        return None


def _quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _parse_fetch(data) -> list[dict]:
    """Parse imaplib FETCH output into [{'meta': bytes, 'parts': {name: bytes}}]."""
    msgs, cur = [], None
    for item in data or []:
        if isinstance(item, tuple):
            meta, lit = item
            if re.match(rb"^\d+ \(", meta):
                cur = {"meta": b"", "parts": {}}
                msgs.append(cur)
            if cur is None:
                continue
            cur["meta"] += meta
            m = re.search(rb"(BODY\[[^\]]*\](?:<\d+>)?|RFC822(?:\.HEADER|\.TEXT)?) \{\d+\}$", meta)
            if m:
                key = m.group(1).decode()
                key = re.sub(r"<\d+>$", "", key).replace("BODY[]", "BODY[]")
                cur["parts"][key] = lit
        elif isinstance(item, bytes):
            if re.match(rb"^\d+ \(", item):
                cur = {"meta": item, "parts": {}}
                msgs.append(cur)
            elif cur is not None:
                cur["meta"] += item
    for m in msgs:
        meta = m["meta"]
        uid = re.search(rb"UID (\d+)", meta)
        m["uid"] = int(uid.group(1)) if uid else None
        fl = re.search(rb"FLAGS \(([^)]*)\)", meta)
        m["flags"] = fl.group(1).decode(errors="replace").split() if fl else []
        sz = re.search(rb"RFC822\.SIZE (\d+)", meta)
        m["size"] = int(sz.group(1)) if sz else 0
        idt = re.search(rb'INTERNALDATE "([^"]+)"', meta)
        m["internaldate"] = idt.group(1).decode() if idt else None
        bs = re.search(rb"BODYSTRUCTURE \((.*)", meta, re.S)
        m["has_attachment"] = bool(bs and re.search(rb'"(attachment)"', bs.group(1), re.I))
    return msgs


def _part_text(part) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")


def _preview_from_partial(header: bytes, text: bytes) -> str:
    """Build a snippet from the header + the first few KB of the body."""
    try:
        msg = email.message_from_bytes(header + text, policy=email.policy.default)
        for part in msg.walk():
            ct = part.get_content_type()
            if part.get_content_maintype() == "multipart" or part.get_filename():
                continue
            if ct == "text/plain":
                return snippet(_part_text(part))
            if ct == "text/html":
                return snippet(html_to_text(_part_text(part)))
    except Exception:
        pass
    return ""


class _LRU(OrderedDict):
    def __init__(self, cap=5000):
        super().__init__()
        self.cap = cap

    def put(self, k, v):
        self[k] = v
        self.move_to_end(k)
        while len(self) > self.cap:
            self.popitem(last=False)


class IMAPAccount:
    """A logged-in user's IMAP connection (thread-safe, auto-reconnecting)."""

    def __init__(self, host, port, security, verify_cert, user, password, timeout=30):
        self.host, self.port, self.security = host, int(port), security
        self.verify_cert, self.user, self.password = verify_cert, user, password
        self.timeout = timeout
        self.lock = threading.RLock()
        self.conn: imaplib.IMAP4 | None = None
        self.selected: tuple | None = None
        self.last_used = 0.0
        self.caps: set[str] = set()
        self.preview_cache = _LRU()
        self._folders_cache = None

    # -- connection --------------------------------------------------------
    def _ctx(self):
        ctx = ssl.create_default_context()
        if not self.verify_cert:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def connect(self):
        try:
            if self.security == "ssl":
                c = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=self._ctx(), timeout=self.timeout)
            else:
                c = imaplib.IMAP4(self.host, self.port, timeout=self.timeout)
                if self.security == "starttls":
                    c.starttls(ssl_context=self._ctx())
        except (OSError, ssl.SSLError, imaplib.IMAP4.error) as e:
            raise MailError(f"Cannot reach mail server {self.host}:{self.port} ({e})") from e
        try:
            c.login(self.user, self.password)
        except imaplib.IMAP4.error as e:
            try:
                c.logout()
            except Exception:
                pass
            if "AUTHORIZATIONFAILED" in str(e) or "disabled" in str(e).lower():
                raise AuthError("Account disabled by administrator") from e
            raise AuthError("Invalid email or password") from e
        self.conn = c
        self.selected = None
        try:
            typ, data = c.capability()
            self.caps = set(data[0].decode().upper().split()) if data and data[0] else set()
        except Exception:
            self.caps = set(c.capabilities)
        self.last_used = time.time()

    def close(self):
        with self.lock:
            if self.conn:
                try:
                    self.conn.logout()
                except Exception:
                    pass
            self.conn = None

    def _ensure(self):
        if self.conn is None:
            self.connect()
        elif time.time() - self.last_used > 60:
            try:
                self.conn.noop()
            except Exception:
                self.conn = None
                self.connect()
        self.last_used = time.time()

    def _run(self, fn):
        """Run fn(conn) with one automatic reconnect on dropped connections."""
        with self.lock:
            for attempt in (1, 2):
                self._ensure()
                try:
                    return fn(self.conn)
                except (imaplib.IMAP4.abort, OSError, socket.timeout, ssl.SSLError):
                    self.conn = None
                    if attempt == 2:
                        raise MailError("Lost connection to mail server")

    def _select(self, c, folder: str, readonly=True):
        key = (folder, readonly)
        if self.selected == key:
            return self._exists
        typ, data = c.select(_quote(utf7.encode(folder)), readonly=readonly)
        if typ != "OK":
            raise MailError(f"Folder not found: {folder}")
        self.selected = key
        self._exists = int(data[0] or 0)
        uv = c.untagged_responses.get("UIDVALIDITY", [b"0"])
        self._uidvalidity = (uv[-1] if uv else b"0").decode() if isinstance(uv[-1], bytes) else str(uv[-1])
        return self._exists

    # -- folders -----------------------------------------------------------
    def folders(self, with_counts=True) -> list[dict]:
        def go(c):
            use_special = "SPECIAL-USE" in self.caps
            typ, data = c.list()
            out, seen_roles = [], set()
            for line in data or []:
                if not isinstance(line, bytes):
                    continue
                m = LIST_RE.match(line)
                if not m:
                    continue
                flags = m.group("flags").decode().lower().split()
                delim = m.group("delim").decode().strip('"')
                if delim == "NIL":
                    delim = ""
                raw = m.group("name").decode()
                if raw.startswith('"') and raw.endswith('"'):
                    raw = raw[1:-1].replace('\\"', '"').replace("\\\\", "\\")
                name = utf7.decode(raw)
                if "\\noselect" in flags or "\\nonexistent" in flags:
                    continue
                role = None
                if name.upper() == "INBOX":
                    role = "inbox"
                else:
                    for r in ("sent", "drafts", "trash", "junk", "archive", "all"):
                        if f"\\{r}" in flags:
                            role = r
                    if role is None:
                        for r, hints in NAME_HINTS.items():
                            if name.lower() in hints and r not in seen_roles:
                                role = r
                                break
                if role in seen_roles:
                    role = None
                if role:
                    seen_roles.add(role)
                out.append({"name": name, "delim": delim, "role": role,
                            "label": name.split(delim)[-1] if delim else name,
                            "unread": 0, "total": 0})
            if with_counts:
                for f in out:
                    try:
                        typ, d = c.status(_quote(utf7.encode(f["name"])), "(MESSAGES UNSEEN)")
                        if typ == "OK" and d and d[0]:
                            s = d[0].decode()
                            mu = re.search(r"UNSEEN (\d+)", s)
                            mm = re.search(r"MESSAGES (\d+)", s)
                            f["unread"] = int(mu.group(1)) if mu else 0
                            f["total"] = int(mm.group(1)) if mm else 0
                    except imaplib.IMAP4.error:
                        pass
            out.sort(key=lambda f: (SPECIAL_ORDER.index(f["role"]) if f["role"] in SPECIAL_ORDER else 99, f["name"].lower()))
            self._folders_cache = out
            return out
        return self._run(go)

    def role_folder(self, role: str) -> str | None:
        fl = self._folders_cache or self.folders(with_counts=False)
        for f in fl:
            if f["role"] == role:
                return f["name"]
        return None

    def create_folder(self, name: str):
        def go(c):
            typ, d = c.create(_quote(utf7.encode(name)))
            if typ != "OK":
                raise MailError(f"Could not create folder: {d}")
            c.subscribe(_quote(utf7.encode(name)))
        self._run(go)
        self._folders_cache = None

    def delete_folder(self, name: str):
        def go(c):
            if self.selected and self.selected[0] == name:
                c.close() if self.selected[1] is False else None
                self.selected = None
            typ, d = c.delete(_quote(utf7.encode(name)))
            if typ != "OK":
                raise MailError(f"Could not delete folder: {d}")
        self._run(go)
        self._folders_cache = None

    # -- search ------------------------------------------------------------
    @staticmethod
    def build_search(q: str) -> tuple[list[str], str | None]:
        """Translate Gmail-style query to IMAP SEARCH criteria.

        Supports: from: to: cc: subject: is:unread is:read is:starred
        has:attachment before:YYYY/MM/DD after:YYYY/MM/DD older_than:7d
        newer_than:2m and free text. Returns (criteria, utf8_text_or_None).
        """
        crit: list[str] = []
        free: list[str] = []
        tokens = re.findall(r'(\w+):"([^"]*)"|(\w+):(\S+)|"([^"]*)"|(\S+)', q or "")
        for k1, v1, k2, v2, phrase, word in tokens:
            key = (k1 or k2).lower()
            val = v1 or v2
            if key in ("from", "to", "cc", "bcc", "subject"):
                crit += [key.upper(), _quote(val)]
            elif key == "is":
                m = {"unread": "UNSEEN", "read": "SEEN", "starred": "FLAGGED",
                     "flagged": "FLAGGED", "answered": "ANSWERED"}.get(val.lower())
                if m:
                    crit.append(m)
            elif key == "has" and val.lower() in ("attachment", "attachments"):
                crit += ["HEADER", "Content-Type", _quote("multipart/mixed")]
            elif key in ("before", "after", "on"):
                try:
                    d = datetime.strptime(val.replace("-", "/"), "%Y/%m/%d")
                    crit += [{"before": "BEFORE", "after": "SINCE", "on": "ON"}[key], d.strftime("%d-%b-%Y")]
                except ValueError:
                    free.append(f"{key}:{val}")
            elif key in ("older_than", "newer_than"):
                m = re.match(r"(\d+)([dmy])", val)
                if m:
                    n, u = int(m.group(1)), m.group(2)
                    days = n * {"d": 1, "m": 30, "y": 365}[u]
                    d = (datetime.now() - timedelta(days=days)).strftime("%d-%b-%Y")
                    crit += ["BEFORE" if key == "older_than" else "SINCE", d]
            elif key:
                free.append(f"{key}:{val}")
            else:
                free.append(phrase or word)
        text = " ".join(free).strip()
        utf8 = None
        if text:
            if text.isascii():
                crit += ["TEXT", _quote(text)]
            else:
                utf8 = text
        return (crit or ["ALL"]), utf8

    # -- messages ----------------------------------------------------------
    def list_messages(self, folder: str, page=0, page_size=50, query: str = "") -> dict:
        def go(c):
            exists = self._select(c, folder, readonly=True)
            if exists == 0:
                return {"folder": folder, "total": 0, "page": page, "messages": []}
            if query or folder == "__starred__":
                crit, utf8 = self.build_search(query)
                if utf8:
                    c.literal = utf8.encode()
                    typ, d = c.uid("SEARCH", "CHARSET", "UTF-8", *crit, "TEXT")
                else:
                    typ, d = c.uid("SEARCH", *crit)
                if typ != "OK":
                    raise MailError("Search failed")
                uids = [int(x) for x in (d[0] or b"").split()]
            else:
                typ, d = c.uid("SEARCH", "ALL")
                uids = [int(x) for x in (d[0] or b"").split()]
            uids.sort(reverse=True)
            total = len(uids)
            chunk = uids[page * page_size : (page + 1) * page_size]
            if not chunk:
                return {"folder": folder, "total": total, "page": page, "messages": []}
            uidset = ",".join(map(str, chunk))
            need_preview = [u for u in chunk if (folder, self._uidvalidity, u) not in self.preview_cache]
            items = "(UID FLAGS INTERNALDATE RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (FROM TO CC SUBJECT DATE MESSAGE-ID CONTENT-TYPE)])"
            typ, data = c.uid("FETCH", uidset, items)
            parsed = {m["uid"]: m for m in _parse_fetch(data) if m["uid"]}
            if need_preview:
                typ, pdata = c.uid("FETCH", ",".join(map(str, need_preview)),
                                   "(UID BODY.PEEK[HEADER] BODY.PEEK[TEXT]<0.6000>)")
                for m in _parse_fetch(pdata):
                    hdr = m["parts"].get("BODY[HEADER]", b"")
                    txt = m["parts"].get("BODY[TEXT]", b"")
                    self.preview_cache.put((folder, self._uidvalidity, m["uid"]), _preview_from_partial(hdr, txt))
            out = []
            for u in chunk:
                m = parsed.get(u)
                if not m:
                    continue
                hdr = email.message_from_bytes(m["parts"].get(
                    "BODY[HEADER.FIELDS (FROM TO CC SUBJECT DATE MESSAGE-ID CONTENT-TYPE)]", b""),
                    policy=email.policy.compat32)
                flags = [f.lower() for f in m["flags"]]
                ct = (hdr.get("Content-Type") or "").lower()
                out.append({
                    "uid": u,
                    "from": _addrs(hdr.get("From")),
                    "to": _addrs(hdr.get("To")),
                    "subject": _dh(hdr.get("Subject")),
                    "date": _date(hdr.get("Date")) or self._idate(m["internaldate"]),
                    "seen": "\\seen" in flags,
                    "flagged": "\\flagged" in flags,
                    "answered": "\\answered" in flags,
                    "draft": "\\draft" in flags,
                    "size": m["size"],
                    "has_attachment": m["has_attachment"] or "multipart/mixed" in ct,
                    "snippet": self.preview_cache.get((folder, self._uidvalidity, u), ""),
                    "message_id": (hdr.get("Message-ID") or "").strip(),
                })
            return {"folder": folder, "total": total, "page": page, "page_size": page_size, "messages": out}
        return self._run(go)

    @staticmethod
    def _idate(s):
        if not s:
            return None
        try:
            return datetime.strptime(s, "%d-%b-%Y %H:%M:%S %z").isoformat()
        except ValueError:
            return None

    def _fetch_raw(self, c, folder, uid) -> tuple[bytes, list[str]]:
        self._select(c, folder, readonly=True)
        typ, data = c.uid("FETCH", str(uid), "(UID FLAGS BODY.PEEK[])")
        msgs = _parse_fetch(data)
        if not msgs or "BODY[]" not in msgs[0]["parts"]:
            raise MailError("Message not found")
        return msgs[0]["parts"]["BODY[]"], msgs[0]["flags"]

    def get_raw(self, folder, uid) -> bytes:
        return self._run(lambda c: self._fetch_raw(c, folder, uid))[0]

    def get_message(self, folder: str, uid: int, allow_remote=False, mark_seen=True, inspect=None) -> dict:
        raw, flags = self._run(lambda c: self._fetch_raw(c, folder, uid))
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        html_body, text_body = None, None
        attachments, cid_map = [], {}
        base = f"/api/attachment?folder={_urlq(folder)}&uid={uid}&part="
        for idx, part in enumerate(msg.walk()):
            if part.get_content_maintype() == "multipart":
                continue
            ct = part.get_content_type()
            disp = (part.get_content_disposition() or "").lower()
            fname = part.get_filename()
            cid = (part.get("Content-ID") or "").strip().strip("<>")
            if ct == "message/rfc822" and not fname:
                fname = "attached-message.eml"
            if fname or disp == "attachment" or (cid and part.get_content_maintype() == "image"):
                payload = part.get_payload(decode=True) or b""
                if cid:
                    cid_map[cid] = base + str(idx)
                if fname or disp == "attachment" or not cid:
                    att = {"part": idx, "filename": _dh(fname) or f"attachment-{idx}",
                           "content_type": ct, "size": len(payload), "inline": bool(cid)}
                    if inspect:
                        att["policy"] = inspect(att["filename"], payload)
                    attachments.append(att)
                continue
            if ct == "text/html" and html_body is None:
                html_body = _part_text(part)
            elif ct == "text/plain" and text_body is None:
                text_body = _part_text(part)
        blocked = 0
        if html_body is not None:
            body, blocked = sanitize_html(html_body, cid_map, allow_remote)
        else:
            body = text_to_html(text_body or "")
        if mark_seen and "\\Seen" not in flags:
            try:
                self.set_flags(folder, [uid], ["\\Seen"], True)
            except MailError:
                pass
        lflags = [f.lower() for f in flags]
        return {
            "uid": uid, "folder": folder,
            "message_id": msg.get("Message-ID", ""),
            "in_reply_to": msg.get("In-Reply-To", ""),
            "references": msg.get("References", ""),
            "from": _addrs(msg.get("From")), "to": _addrs(msg.get("To")),
            "cc": _addrs(msg.get("Cc")), "reply_to": _addrs(msg.get("Reply-To")),
            "subject": _dh(msg.get("Subject")), "date": _date(msg.get("Date")),
            "html": body, "text": text_body if text_body is not None else html_to_text(html_body or ""),
            "blocked_images": blocked, "attachments": attachments,
            "flagged": "\\flagged" in lflags, "seen": True,
        }

    def get_attachment(self, folder: str, uid: int, part_idx: int):
        raw = self.get_raw(folder, uid)
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        for idx, part in enumerate(msg.walk()):
            if idx == part_idx:
                if part.get_content_type() == "message/rfc822":
                    inner = part.get_payload()
                    data = inner[0].as_bytes() if isinstance(inner, list) else bytes(inner)
                else:
                    data = part.get_payload(decode=True) or b""
                return (_dh(part.get_filename()) or f"attachment-{idx}"), part.get_content_type(), data
        raise MailError("Attachment not found")

    # -- mutations ---------------------------------------------------------
    def set_flags(self, folder, uids, flags, add=True):
        def go(c):
            self._select(c, folder, readonly=False)
            typ, d = c.uid("STORE", ",".join(map(str, uids)), "+FLAGS.SILENT" if add else "-FLAGS.SILENT",
                           "(" + " ".join(flags) + ")")
            if typ != "OK":
                raise MailError("Could not update message")
        self._run(go)

    def move(self, folder, uids, dest):
        if folder == dest:
            return
        def go(c):
            self._select(c, folder, readonly=False)
            uidset = ",".join(map(str, uids))
            tgt = _quote(utf7.encode(dest))
            if "MOVE" in self.caps:
                typ, d = c.uid("MOVE", uidset, tgt)
                if typ == "OK":
                    return
            typ, d = c.uid("COPY", uidset, tgt)
            if typ != "OK":
                raise MailError(f"Could not move to {dest}")
            c.uid("STORE", uidset, "+FLAGS.SILENT", "(\\Deleted)")
            if "UIDPLUS" in self.caps:
                c.uid("EXPUNGE", uidset)
            else:
                c.expunge()
        self._run(go)

    def delete(self, folder, uids):
        """Move to Trash; permanently delete if already in Trash/Junk."""
        trash = self.role_folder("trash")
        if trash and folder not in (trash, self.role_folder("junk")):
            return self.move(folder, uids, trash)
        return self.purge(folder, uids)

    def find_uid(self, folder: str, message_id: str) -> int | None:
        def go(c):
            self.selected = None  # force re-select so new messages are visible
            self._select(c, folder, readonly=True)
            typ, d = c.uid("SEARCH", "HEADER", "Message-ID", _quote(message_id))
            ids = (d[0] or b"").split() if typ == "OK" and d else []
            return int(ids[-1]) if ids else None
        return self._run(go)

    def all_uids(self, folder: str) -> list[int]:
        def go(c):
            self._select(c, folder, readonly=True)
            typ, d = c.uid("SEARCH", "ALL")
            return [int(x) for x in (d[0] or b"").split()] if typ == "OK" else []
        return self._run(go)

    def quota(self) -> dict | None:
        """Storage usage via the IMAP QUOTA extension (RFC 2087), in MB."""
        if "QUOTA" not in self.caps:
            return None

        def go(c):
            typ, data = c.getquotaroot("INBOX")
            if typ != "OK":
                return None
            for item in data:
                for line in (item if isinstance(item, list) else [item]):
                    if isinstance(line, bytes):
                        m = re.search(rb"STORAGE (\d+) (\d+)", line)
                        if m:
                            used, limit = int(m.group(1)), int(m.group(2))
                            return {"used_mb": round(used / 1024, 1), "limit_mb": round(limit / 1024),
                                    "percent": round(100 * used / limit, 1) if limit else 0}
            return None
        return self._run(go)

    def find_uids(self, folder: str, message_ids: list[str]) -> list[int]:
        out = []
        for mid in message_ids:
            u = self.find_uid(folder, mid)
            if u:
                out.append(u)
        return out

    def purge(self, folder, uids):
        """Permanently delete messages."""
        def go(c):
            self._select(c, folder, readonly=False)
            uidset = ",".join(map(str, uids))
            c.uid("STORE", uidset, "+FLAGS.SILENT", "(\\Deleted)")
            if "UIDPLUS" in self.caps:
                c.uid("EXPUNGE", uidset)
            else:
                c.expunge()
        self._run(go)

    def append(self, folder: str, raw: bytes, flags="(\\Seen)", date_time=None):
        def go(c):
            when = date_time or imaplib.Time2Internaldate(time.time())
            typ, d = c.append(_quote(utf7.encode(folder)), flags, when, raw)
            if typ != "OK":
                reason = (d[0].decode(errors="replace") if d and isinstance(d[0], bytes) else "")
                if "OVERQUOTA" in reason.upper() or "quota" in reason.lower():
                    raise MailError("Your mailbox is full. Delete some messages to free space.")
                raise MailError(f"Could not save to {folder}: {reason}")
            self.selected = None if self.selected and self.selected[0] == folder else self.selected
        self._run(go)


def _urlq(s):
    from urllib.parse import quote
    return quote(s, safe="")
