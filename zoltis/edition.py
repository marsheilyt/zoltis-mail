"""Edition & module system (open-core).

Community Edition  : webmail (IMAP/SMTP), search, labels/folders, compose,
                     attachments, signatures, contact autocomplete,
                     deliverability doctor. Free for everyone.
Enterprise Edition : adds modules shipped in the separate `zoltis.enterprise`
                     package (calendar, drive, contact sync (CardDAV),
                     CalDAV sync, mobile-app API, admin console, SSO).

A module is any object with:
    name: str
    features: list[str]
    def register(router) -> None      # router.add(method, path, handler)

The Enterprise package exposes `load(license_info) -> list[module]` and is
only activated when a valid, signed license key is present.
"""

from __future__ import annotations

import logging

log = logging.getLogger("zoltis.edition")

COMMUNITY_FEATURES = [
    "mail", "search", "folders", "compose", "attachments", "signatures",
    "contacts_autocomplete", "keyboard_shortcuts", "dark_mode", "deliverability_doctor",
    "admin_console", "mail_server", "antivirus", "attachment_blocker", "mailbox_import",
]
# Community Edition limits (Enterprise limits come from the license).
# postmaster@<domain> aliases don't count towards max_aliases (every domain needs one for DMARC reports).
COMMUNITY_LIMITS = {"max_accounts": 10, "max_aliases": 5, "max_quota_mb": 720, "drive": False}
ENTERPRISE_FEATURES = [
    "calendar", "drive", "contacts", "carddav", "caldav", "mobile_api",
    "sso", "shared_mailboxes", "audit_log", "group_policies", "multi_server",
]


class Edition:
    def __init__(self, cfg):
        self.name = "community"
        self.features = list(COMMUNITY_FEATURES)
        self.modules = []
        self.license = None
        self.limits = dict(COMMUNITY_LIMITS)
        self._load_enterprise(cfg)

    def _load_enterprise(self, cfg):
        try:
            from . import enterprise  # noqa: F401  (absent in community builds)
        except ImportError:
            return
        if not hasattr(enterprise, "load"):
            return
        try:
            info = enterprise.verify_license(cfg.get("license", "key_file"))
        except Exception as e:  # invalid/expired license -> stay community
            log.warning("Enterprise package present but license invalid: %s", e)
            return
        self.license = info
        self.name = "enterprise"
        self.limits = {"max_accounts": int(info.get("seats") or 0) or None,
                       "max_quota_mb": int(info.get("max_quota_mb") or 0) or None, "drive": True}
        self.modules = enterprise.load(info)
        for m in self.modules:
            self.features += [f for f in m.features if f not in self.features]

    def register(self, router):
        for m in self.modules:
            m.register(router)

    def public(self) -> dict:
        return {"edition": self.name, "features": self.features, "limits": self.limits,
                "licensed_to": (self.license or {}).get("customer")}
