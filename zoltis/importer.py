"""Copy a mailbox from an old IMAP server (e.g. your current Postfix + Dovecot +
Roundcube setup) into a Zoltis Mail account. Safe to run again: messages that
already exist in the destination (same Message-ID) are skipped.
"""

from __future__ import annotations

import email
import email.policy
import imaplib
import logging
import re
import threading
import time
import uuid

from .mail.imap import IMAPAccount, MailError, _parse_fetch

log = logging.getLogger("zoltis.import")
BATCH = 25


class ImportJob:
    def __init__(self, target, source_desc):
        self.id = uuid.uuid4().hex[:12]
        self.target = target
        self.source = source_desc
        self.state = "queued"           # queued | running | done | failed | cancelled
        self.folder = ""
        self.copied = self.skipped = self.failed = 0
        self.total = 0
        self.error = ""
        self.started = time.time()
        self.finished = None
        self.cancel = threading.Event()

    def as_dict(self):
        return {k: getattr(self, k) for k in ("id", "target", "source", "state", "folder", "copied", "skipped",
                                               "failed", "total", "error", "started", "finished")}


def _message_ids(acct: IMAPAccount, folder: str) -> set[str]:
    def go(c):
        acct._select(c, folder, readonly=True)
        typ, d = c.uid("SEARCH", "ALL")
        uids = (d[0] or b"").split() if typ == "OK" else []
        out = set()
        for i in range(0, len(uids), 500):
            typ, data = c.uid("FETCH", b",".join(uids[i:i + 500]).decode(),
                              "(UID BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])")
            for m in _parse_fetch(data):
                for v in m["parts"].values():
                    mm = re.search(rb"<[^>]+>", v)
                    if mm:
                        out.add(mm.group(0).decode(errors="replace"))
        return out
    return acct._run(go)


def run_import(job: ImportJob, src: IMAPAccount, dst: IMAPAccount):
    job.state = "running"
    try:
        src.connect()
        dst.connect()
        src_folders = src.folders(with_counts=True)
        dst.folders(with_counts=False)
        job.total = sum(f["total"] for f in src_folders)
        for f in src_folders:
            if job.cancel.is_set():
                job.state = "cancelled"
                return
            if f["role"] == "all":  # Gmail "All Mail" duplicates every other folder
                continue
            dest = dst.role_folder(f["role"]) if f["role"] else None
            if not dest:
                dest = f["name"] if f["role"] != "inbox" else "INBOX"
                if dest not in [x["name"] for x in (dst._folders_cache or [])]:
                    try:
                        dst.create_folder(dest)
                    except MailError:
                        pass
                    dst.folders(with_counts=False)
            job.folder = f["name"]
            existing = _message_ids(dst, dest)
            uids = src.all_uids(f["name"])
            for i in range(0, len(uids), BATCH):
                if job.cancel.is_set():
                    job.state = "cancelled"
                    return
                chunk = ",".join(map(str, uids[i:i + BATCH]))
                data = src._run(lambda c: (src._select(c, f["name"], readonly=True),
                                           c.uid("FETCH", chunk, "(UID FLAGS INTERNALDATE BODY.PEEK[])"))[1][1])
                for m in _parse_fetch(data):
                    raw = m["parts"].get("BODY[]")
                    if raw is None:
                        job.failed += 1
                        continue
                    mid = email.message_from_bytes(raw[:65536], policy=email.policy.compat32).get("Message-ID", "").strip()
                    if mid and mid in existing:
                        job.skipped += 1
                        continue
                    flags = " ".join(x for x in m["flags"] if x.lower() not in ("\\recent",))
                    when = f'"{m["internaldate"]}"' if m["internaldate"] else imaplib.Time2Internaldate(time.time())
                    try:
                        dst.append(dest, raw, f"({flags})", when)
                        job.copied += 1
                        if mid:
                            existing.add(mid)
                    except MailError as e:
                        if "mailbox is full" in str(e).lower():
                            raise MailError("The mailbox is full (storage limit reached). Import stopped.")
                        job.failed += 1
        job.state = "done"
    except Exception as e:  # noqa: BLE001 - report any failure to the admin
        job.state = "failed"
        job.error = str(e)
        log.warning("import into %s failed: %s", job.target, e)
    finally:
        job.finished = time.time()
        src.close()
        dst.close()
        log.info("import into %s: %s (%d copied, %d skipped, %d failed)", job.target, job.state,
                 job.copied, job.skipped, job.failed)
