"""Small JSON-file store for per-user settings and recent contacts.

Mail itself always stays on the IMAP server. This only keeps UI
preferences, the signature and an address book of people you've written to.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time

DEFAULT_SETTINGS = {
    "display_name": "",
    "signature": "",
    "theme": "system",        # system | light | dark
    "density": "default",     # default | comfortable | compact
    "page_size": 50,
    "load_images": "ask",     # ask | always
    "reading_pane": "right",  # right | none
    "undo_send_seconds": 5,
    "send_shortcut": True,
}


class UserStore:
    def __init__(self, data_dir: str):
        self.dir = os.path.join(data_dir, "users")
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        self.lock = threading.Lock()

    def _path(self, email: str) -> str:
        h = hashlib.sha256(email.lower().encode()).hexdigest()[:32]
        return os.path.join(self.dir, f"{h}.json")

    def load(self, email: str) -> dict:
        try:
            with open(self._path(email)) as f:
                d = json.load(f)
        except (OSError, ValueError):
            d = {}
        d.setdefault("settings", {})
        d["settings"] = {**DEFAULT_SETTINGS, **d["settings"]}
        d.setdefault("contacts", {})
        return d

    def save(self, email: str, data: dict):
        with self.lock:
            p = self._path(email)
            tmp = p + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, p)

    def update_settings(self, email: str, patch: dict) -> dict:
        d = self.load(email)
        for k, v in patch.items():
            if k in DEFAULT_SETTINGS and type(v) is type(DEFAULT_SETTINGS[k]):
                d["settings"][k] = v
        self.save(email, d)
        return d["settings"]

    def remember_contacts(self, email: str, addrs: list[tuple[str, str]]):
        if not addrs:
            return
        d = self.load(email)
        now = int(time.time())
        for name, addr in addrs:
            if not addr:
                continue
            k = addr.lower()
            c = d["contacts"].get(k, {"email": addr, "name": name, "count": 0})
            c["count"] += 1
            c["last"] = now
            if name:
                c["name"] = name
            d["contacts"][k] = c
        if len(d["contacts"]) > 5000:
            keep = sorted(d["contacts"].items(), key=lambda kv: -kv[1].get("last", 0))[:5000]
            d["contacts"] = dict(keep)
        self.save(email, d)

    def search_contacts(self, email: str, q: str, limit=8) -> list[dict]:
        q = (q or "").lower().strip()
        cs = self.load(email)["contacts"].values()
        hits = [c for c in cs if q in c["email"].lower() or q in (c.get("name") or "").lower()] if q else list(cs)
        hits.sort(key=lambda c: (-c.get("count", 0), -c.get("last", 0)))
        return [{"name": c.get("name", ""), "email": c["email"]} for c in hits[:limit]]
