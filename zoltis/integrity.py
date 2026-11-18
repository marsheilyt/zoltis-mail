"""Code integrity: is this server running the Zoltis Mail release exactly as published?

Every release ships zoltis/RELEASE.manifest: the SHA-256 of every core file (the Python package and
the whole web/ folder, logos included), signed with the Zoltis release key (same Ed25519 keys as
license keys, different signing context). The server checks its own files at startup and every
CHECK_SECONDS:

    ok        every file matches the signed manifest
    modified  a core file was changed, added or deleted (the list of file NAMES is kept)
    unsigned  no manifest, a manifest not signed by Zoltis, or one for another version

The result is reported in the daily license check-in (status, code fingerprint, changed file names;
never file contents). When enforcement is on, anything other than "ok" locks the service like a
suspension: nobody can sign in (webmail, IMAP, SMTP) and incoming mail is still stored. Putting the
original files back unlocks it at the next check.

Enforcement ([integrity] enforce / ZOLTIS_INTEGRITY_ENFORCE):
    auto (default)  on when this copy carries a genuine signed manifest, or when license enforcement is on
                    and the build trusts a Zoltis release key; off for development checkouts
    true / false    always / never

Note: in source-available software this detects and reports changes; it can't make the code
impossible to change. The licensing portal (ZOcc) should treat a server that reports "modified" or
"unsigned", or that stops checking in, as out of license.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time

from . import licensing as L

log = logging.getLogger("zoltis.integrity")

RELEASE_CONTEXT = b"zoltis-release-v1\n"
MANIFEST_NAME = "RELEASE.manifest"
CHECK_SECONDS = 600
SKIP_DIRS = {"__pycache__", ".pytest_cache"}
SKIP_EXT = {".pyc", ".pyo"}
MODIFIED_MESSAGE = ("This mail service is locked because its program files were changed. "
                    "Reinstall the official Zoltis Mail release, or contact Zoltis via the customer portal.")


def package_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def compute(pkg_dir: str, web_dir: str) -> dict[str, str]:
    """{"zoltis/server.py": sha256, "web/img/logo.svg": sha256, ...} for every core file."""
    out = {}
    for prefix, root in (("zoltis", pkg_dir), ("web", web_dir)):
        root = os.path.realpath(root)
        for d, dirs, files in os.walk(root):
            dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
            for f in sorted(files):
                if os.path.splitext(f)[1] in SKIP_EXT:
                    continue
                full = os.path.join(d, f)
                rel = prefix + "/" + os.path.relpath(full, root).replace(os.sep, "/")
                if rel == f"zoltis/{MANIFEST_NAME}":
                    continue
                h = hashlib.sha256()
                with open(full, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 16), b""):
                        h.update(chunk)
                out[rel] = h.hexdigest()
    return out


def fingerprint(files: dict[str, str]) -> str:
    return hashlib.sha256("".join(f"{k}\0{v}\n" for k, v in sorted(files.items())).encode()).hexdigest()


def sign_manifest(files: dict[str, str], version: str, seed: bytes, kid: str) -> str:
    """Used by devtools/release_sign.py at release time (needs the private key), never by the app."""
    return L.encode_token({"v": 1, "kid": kid, "version": version, "files": files}, seed, RELEASE_CONTEXT)


def verify(pkg_dir: str, web_dir: str, version: str, keys: dict | None = None) -> dict:
    files = compute(pkg_dir, web_dir)
    res = {"status": "ok", "fingerprint": fingerprint(files), "changed": [], "added": [], "missing": [],
           "problem": None, "signed": False, "checked": time.time()}
    try:
        with open(os.path.join(pkg_dir, MANIFEST_NAME)) as f:
            m = L.decode_token(f.read(), RELEASE_CONTEXT, keys)
        if m.get("v") != 1 or not isinstance(m.get("files"), dict):
            raise L.LicenseError("the release manifest is damaged")
        if m.get("version") != version:
            raise L.LicenseError(f"the release manifest is for version {m.get('version')}, not {version}")
    except FileNotFoundError:
        res.update(status="unsigned", problem="no signed release manifest (not an official build)")
        return res
    except (OSError, L.LicenseError) as e:
        res.update(status="unsigned", problem=f"release manifest not genuine: {e}")
        return res
    res["signed"] = True
    want = m["files"]
    res["changed"] = sorted(k for k in files if k in want and files[k] != want[k])
    res["added"] = sorted(k for k in files if k not in want)
    res["missing"] = sorted(k for k in want if k not in files)
    if res["changed"] or res["added"] or res["missing"]:
        res["status"] = "modified"
        res["problem"] = f"{len(res['changed']) + len(res['added']) + len(res['missing'])} core file(s) differ from the release"
    return res


class IntegrityMonitor:
    """Checks the code now and every CHECK_SECONDS; tells the license manager about the result."""

    def __init__(self, cfg, license_mgr, web_dir: str, pkg_dir: str | None = None):
        from . import __version__
        self.cfg, self.license = cfg, license_mgr
        self.web_dir, self.pkg_dir, self.version = web_dir, pkg_dir or package_dir(), __version__
        self.result: dict = {}
        self._thread = None
        self.check()

    @property
    def enforced(self) -> bool:
        mode = (self.cfg.get("integrity", "enforce") or "auto").strip().lower()
        if mode in ("1", "true", "yes", "on"):
            return True
        if mode in ("0", "false", "no", "off"):
            return False
        # auto: a genuinely signed build always enforces. An unsigned or re-signed copy is locked only once this
        # build trusts a Zoltis release key (L.TRUSTED_KEYS is filled in for official releases), so development
        # checkouts and builds made before the first signed release keep working.
        return bool(self.result.get("signed")) or (self.license.enabled and bool(L.TRUSTED_KEYS))

    def check(self) -> dict:
        try:
            r = verify(self.pkg_dir, self.web_dir, self.version)
        except OSError as e:
            r = {"status": "modified", "problem": f"could not read the program files: {e}", "changed": [],
                 "added": [], "missing": [], "fingerprint": None, "signed": False, "checked": time.time()}
        before = (self.result or {}).get("status")
        self.result = r
        self.license.integrity = self.report()
        self.license.integrity_locked = self.enforced and r["status"] != "ok"
        if r["status"] != before:
            (log.info if r["status"] == "ok" else log.warning)("code integrity: %s%s", r["status"],
                                                                f" ({r['problem']})" if r["problem"] else "")
            if before is not None:
                self.license.report_soon()   # tell the licensing portal now, not at the next daily check-in
        self.license._notify()
        return r

    def report(self) -> dict:
        """What the license check-in sends: status, fingerprint and file names only (max 50)."""
        r = self.result
        names = (r.get("changed", []) + r.get("added", []) + r.get("missing", []))[:50]
        return {"status": r.get("status"), "fingerprint": r.get("fingerprint"), "files": names,
                "enforced": self.enforced}

    def public(self) -> dict:
        return {**self.report(), "problem": self.result.get("problem"), "checked": self.result.get("checked"),
                "changed": self.result.get("changed", []), "added": self.result.get("added", []),
                "missing": self.result.get("missing", [])}

    def start(self):
        if self._thread:
            return
        self._thread = threading.Thread(target=self._loop, name="integrity", daemon=True)
        self._thread.start()

    def _loop(self):
        while True:
            time.sleep(CHECK_SECONDS)
            try:
                self.check()
            except Exception:  # noqa: BLE001
                log.exception("integrity check failed")
