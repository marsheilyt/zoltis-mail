"""Small JSON-file store for per-user settings and recent contacts.

Mail itself always stays on the IMAP server. This only keeps UI
preferences, the signature and an address book of people you've written to.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time

DEFAULT_SETTINGS = {
    "display_name": "",
    "signature": "",          # HTML signature (cleaned by the server when saved)
    "signature_text": "",     # plain-text signature
    "signature_type": "text", # text | html: which one is used. Only one is active at a time.
    "theme": "light",         # light | dark | system (follow the device)
    "density": "default",     # default | comfortable | compact
    "page_size": 50,
    "load_images": "ask",     # ask | always
    "reading_pane": "right",  # right | none
    "undo_send_seconds": 5,
    "send_shortcut": True,
    "inbox_tabs": True,       # sort the inbox into Primary / Updates / Promotions / Social / Forums
    "smart_summary": True,    # show the summary card above long messages
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
        if "signature_type" not in d["settings"] and d["settings"].get("signature"):
            d["settings"]["signature_type"] = "html"     # signatures saved before 2.3.0 were HTML
        d["settings"] = {**DEFAULT_SETTINGS, **d["settings"]}
        d.setdefault("contacts", {})
        d.setdefault("sender_categories", {})   # address (or @domain) -> category chosen by the user
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
                if k == "signature_type" and v not in ("text", "html"):
                    continue
                if k in ("signature", "signature_text"):
                    v = v[:10000]
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

    def set_sender_category(self, email: str, senders: list[str], category: str):
        d = self.load(email)
        for s in senders:
            d["sender_categories"][s.lower()] = category
        if len(d["sender_categories"]) > 2000:
            d["sender_categories"] = dict(list(d["sender_categories"].items())[-2000:])
        self.save(email, d)

    def search_contacts(self, email: str, q: str, limit=8) -> list[dict]:
        q = (q or "").lower().strip()
        cs = self.load(email)["contacts"].values()
        hits = [c for c in cs if q in c["email"].lower() or q in (c.get("name") or "").lower()] if q else list(cs)
        hits.sort(key=lambda c: (-c.get("count", 0), -c.get("last", 0)))
        return [{"name": c.get("name", ""), "email": c["email"]} for c in hits[:limit]]


TZ_RE = re.compile(r"^(UTC|[A-Za-z]+(?:/[A-Za-z0-9_+\-]+){1,2})$")


def valid_timezone(name: str) -> bool:
    """IANA time zone name such as "Asia/Dubai" (checked against the tz database when it's installed)."""
    name = (name or "").strip()
    if not TZ_RE.match(name) or len(name) > 64:
        return False
    try:
        import zoneinfo
        zoneinfo.ZoneInfo(name)
        return True
    except Exception:  # noqa: BLE001
        try:
            import zoneinfo
            return not zoneinfo.available_timezones()   # no tz database here: trust the pattern
        except Exception:  # noqa: BLE001
            return True


class SiteSettings:
    """Server-wide settings chosen in the web UI (site.json in the data directory).

    timezone: the "server time" shown on the sign-in page. Taken from the administrator's browser
    when the server is set up (or the first time an admin opens the console), changeable later.
    """

    def __init__(self, data_dir: str):
        self.path = os.path.join(data_dir, "site.json")
        self.lock = threading.Lock()

    def load(self) -> dict:
        try:
            with open(self.path) as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def update(self, **patch) -> dict:
        with self.lock:
            d = {**self.load(), **patch}
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(d, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
            return d

    def timezone(self) -> tuple[str, bool]:
        """(time zone, configured?). Falls back to the container's TZ, then UTC."""
        tz = self.load().get("timezone")
        if tz:
            return tz, True
        env = (os.environ.get("TZ") or "").strip()
        return (env if valid_timezone(env) else "UTC"), False
