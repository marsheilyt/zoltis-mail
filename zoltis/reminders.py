"""License reminders for administrators: a notice in each admin's Inbox at key moments.

Registration (no key yet, 7-day grace period): when the server is installed, with 3 days left, on the last
day, and once the period is over. Renewal (Community keys last one year): 30 days and 7 days before the end,
and when it has passed. Each notice is sent once (remembered in license.reminders in the data directory).
"""

from __future__ import annotations

import json
import logging
import os
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

log = logging.getLogger("zoltis.reminders")

STEPS = """To get your free license key:
  1. Sign in at {site} (create an account if you don't have one).
  2. Open My account > License keys > Community Edition.
  3. Enter this server's IP address: {ip}
  4. Copy the key, then paste it in Admin console > License and click Activate.
     The key is checked with the Zoltis Mail licensing server; it only works on this server's IP."""


def _due(lic, now) -> tuple[str, str, str] | None:
    """(id, subject, body) of the reminder that is due now, or None."""
    from .licensing import SITE
    st = lic.state()
    site, ip = SITE, lic.public_ip or "(the server's public IP address)"
    steps = STEPS.format(site=site, ip=ip)
    if st in ("grace", "missing"):
        left = (lic.grace_until - now) / 86400
        day = time.strftime("%d %B %Y", time.gmtime(lic.grace_until))
        if st == "missing":
            return ("reg-over", "Action needed: add your Zoltis Mail license key",
                    f"The 7 days to register this server ended on {day}. Mail keeps working, but you can't create new "
                    f"email accounts or domains until a license key is added.\n\n{steps}")
        if left <= 1:
            return ("reg-last", "Last day to add your Zoltis Mail license key",
                    f"Add the license key by {day}. After that, creating email accounts and domains is paused "
                    f"until a key is added.\n\n{steps}")
        if left <= 3:
            return ("reg-3", f"{int(left + 0.99)} days left to add your Zoltis Mail license key",
                    f"Register this server by {day}.\n\n{steps}")
        return ("reg-start", "Welcome to Zoltis Mail: add your free license key within 7 days",
                f"Every Zoltis Mail server needs a free license key. Add it by {day}.\n\n{steps}")
    b = lic.billing() if lic.cert else None
    if not b or b["plan"] != "community" or not b["paid_until"]:
        return None
    end = time.strftime("%d %B %Y", time.gmtime(b["paid_until"]))
    tag = time.strftime("%Y%m%d", time.gmtime(b["paid_until"]))     # a new period gets new reminders
    renew = (f"Renew it free at {site}: My account > License keys > Community Edition > Renew. "
             "Your key stays the same; this server picks up the new date at its next daily check.")
    if b["status"] == "renewal_due":
        return (f"renew-over-{tag}", "Your Zoltis Mail license has expired",
                f"The license ended on {end}. Mail keeps working, but new accounts and domains are paused until "
                f"you renew.\n\n{renew}")
    days = b["days_left"]
    if days is not None and days < 7:
        return (f"renew-7-{tag}", "Your Zoltis Mail license ends in less than a week", f"It ends on {end}.\n\n{renew}")
    if days is not None and days < 30:
        return (f"renew-30-{tag}", "Renew your Zoltis Mail license",
                f"Your license ends on {end}. You can renew it now (renewal opens 30 days before the end).\n\n{renew}")
    return None


def run(app, now: float | None = None) -> str | None:
    """Send the reminder that is due (if any) to every enabled administrator. Returns its id."""
    lic = app.license
    if not lic.enabled or app.mode != "bundled":
        return None
    now = now or time.time()
    due = _due(lic, now)
    if not due:
        return None
    rid, subject, body = due
    path = os.path.join(app.data_dir, "license.reminders")
    try:
        with open(path) as f:
            sent = set(json.load(f))
    except (OSError, ValueError):
        sent = set()
    if rid in sent:
        return None
    admins = [a["email"] for a in app.accounts.accounts() if a["is_admin"] and a["enabled"]]
    if not admins:
        return None            # setup not finished yet; try again later
    for email in admins:
        m = EmailMessage()
        m["From"] = f"Zoltis Mail <postmaster@{email.split('@')[1]}>"
        m["To"] = email
        m["Subject"] = subject
        m["Date"] = formatdate(localtime=False)
        m["Message-ID"] = make_msgid(domain=email.split("@")[1])
        m["Auto-Submitted"] = "auto-generated"
        m.set_content(body + "\n\n-- \nThis notice was sent by your Zoltis Mail server.\n")
        try:
            app.mailserver.deliver_notice(email, m.as_bytes())
        except Exception as e:  # noqa: BLE001
            log.warning("could not deliver the license reminder to %s: %s", email, e)
            return None
    sent.add(rid)
    with open(path, "w") as f:
        json.dump(sorted(sent), f)
    log.info("license reminder '%s' sent to %s", rid, ", ".join(admins))
    return rid
