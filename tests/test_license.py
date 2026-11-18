"""Community Edition license keys: signatures, activation, domain binding, enforcement."""

import json
import os
import shutil
import subprocess
import tempfile
import time

import pytest

import license_dev
from zoltis import config, licensing as L
from zoltis.accounts import AccountDB, NotLicensed


def manager(data_dir=None):
    return L.LicenseManager(config.Config({}), data_dir or tempfile.mkdtemp())


# ------------------------------------------------------------------ crypto
def test_ed25519_matches_openssl():
    d = tempfile.mkdtemp()
    try:
        k, m = os.path.join(d, "k.pem"), os.path.join(d, "m")
        if subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", k], capture_output=True).returncode:
            pytest.skip("openssl without ed25519")
        der = subprocess.run(["openssl", "pkey", "-in", k, "-outform", "DER"], capture_output=True, check=True).stdout
        pub = subprocess.run(["openssl", "pkey", "-in", k, "-pubout", "-outform", "DER"], capture_output=True, check=True).stdout
        open(m, "wb").write(b"zoltis")
        sig = subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", k, "-rawin", "-in", m],
                             capture_output=True, check=True).stdout
    finally:
        shutil.rmtree(d)
    seed, pub = der[-32:], pub[-32:]
    assert L.ed25519_public_key(seed) == pub
    assert L.ed25519_sign(seed, b"zoltis") == sig
    assert L.ed25519_verify(pub, b"zoltis", sig)
    assert not L.ed25519_verify(pub, b"zoltiS", sig)


# ------------------------------------------------------------------ keys
def test_key_parses_and_normalises_domains(portal):
    info = L.parse_key(portal.issue("Acme.COM", "b.org.", customer="Acme"))
    assert info["domains"] == ["acme.com", "b.org"] and info["customer"] == "Acme"


def test_edited_key_is_rejected(portal):
    pre, body, sig = portal.issue("acme.com").split(".")
    p = json.loads(L._b64d(body))
    p["domains"].append("stolen.com")                       # try to add a domain
    forged = ".".join([pre, L._b64e(json.dumps(p).encode()), sig])
    with pytest.raises(L.LicenseError, match="not genuine"):
        L.parse_key(forged)


def test_key_signed_by_someone_else_is_rejected(portal):
    other = os.urandom(32)
    with pytest.raises(L.LicenseError, match="not genuine"):
        L.parse_key(license_dev.issue_key(other, "test", ["acme.com"]))
    with pytest.raises(L.LicenseError, match="unknown key"):
        L.parse_key(license_dev.issue_key(other, "nope", ["acme.com"]))


def test_bad_and_expired_keys(portal):
    for bad in ("", "hello", "ZM1.@@@.###", "XX1.a.b"):
        with pytest.raises(L.LicenseError):
            L.parse_key(bad)
    with pytest.raises(L.LicenseError, match="expired"):
        L.parse_key(portal.issue("acme.com", days=1), now=time.time() + 2 * 86400)


def test_key_survives_copy_paste_whitespace(portal):
    k = portal.issue("acme.com")
    assert L.parse_key(k[:20] + "\n  " + k[20:] + " \n")["domains"] == ["acme.com"]


# ------------------------------------------------------------------ activation
def test_activation_and_domain_binding(portal):
    m = manager()
    assert m.state() == "missing" and not m.active
    with pytest.raises(L.LicenseRequired, match="Add your license key"):
        m.require("acme.com")
    m.activate(portal.issue("acme.com"))
    assert m.state() == "active"
    m.require("acme.com")
    with pytest.raises(L.LicenseRequired, match="covers acme.com only"):
        m.require("other.com")


def test_key_cannot_be_reused_on_a_second_server(portal):
    key = portal.issue("acme.com")
    manager().activate(key)
    with pytest.raises(L.LicenseError, match="already in use"):
        manager().activate(key)


def test_reactivating_same_server_is_fine_and_state_persists(portal):
    d = tempfile.mkdtemp()
    key = portal.issue("acme.com")
    manager(d).activate(key)
    again = manager(d)                       # restart: loads from disk, offline
    assert again.state() == "active"
    again.activate(key)                      # same install id -> allowed


def test_activation_copied_to_another_install_is_rejected(portal):
    a, b = tempfile.mkdtemp(), tempfile.mkdtemp()
    manager(a).activate(portal.issue("acme.com"))
    for f in ("license.key", "license.activation"):     # copy the license, not the whole install
        shutil.copy(os.path.join(a, f), b)
    assert manager(b).state() == "inactive"


def test_cloned_install_reports_a_different_instance(portal):
    """Copying the whole data folder copies the install ID, but each running copy has its own instance ID."""
    a, b = tempfile.mkdtemp(), tempfile.mkdtemp()
    m1 = manager(a)
    m1.activate(portal.issue("acme.com"))
    shutil.rmtree(b)
    shutil.copytree(a, b)                                   # full clone, install.id included
    m2 = manager(b)
    assert m2.install_id == m1.install_id and m2.instance_id != m1.instance_id
    portal.calls.clear()
    m1.refresh(); m2.refresh()
    seen = {c[1]["instance_id"] for c in portal.calls if c[0] == "/v1/activate"}
    assert seen == {m1.instance_id, m2.instance_id}          # the portal sees two copies of one install


def test_forged_activation_is_rejected(portal):
    m = manager()
    key = portal.issue("acme.com")
    info = L.parse_key(key)
    fake = license_dev.issue_activation(os.urandom(32), "test", info["lid"], m.install_id)
    with pytest.raises(L.LicenseError, match="not genuine"):
        m._check_cert(fake, info)


def test_revocation_takes_effect_on_renewal(portal):
    m = manager()
    m.activate(portal.issue("acme.com"))
    portal.revoked.add(m.info["lid"])
    with pytest.raises(L.LicenseError, match="revoked"):
        m.refresh()
    assert m.state() == "inactive" and "revoked" in m.problem
    with pytest.raises(L.LicenseRequired, match="revoked"):
        m.require("acme.com")
    assert manager(m.data_dir).state() == "inactive"     # also after a restart


def test_portal_outage_keeps_current_activation(portal):
    m = manager()
    m.activate(portal.issue("acme.com"))
    portal.down = True
    try:
        with pytest.raises(ConnectionError):
            m.refresh()
        assert m.state() == "active"
        with pytest.raises(L.LicenseError, match="activation failed"):
            manager().activate(portal.issue("acme.com"))   # but a new key can't be activated offline
    finally:
        portal.down = False


def test_activation_expires_if_never_renewed(portal):
    m = manager()
    m.activate(portal.issue("acme.com"))
    m.cert["valid_until"] = time.time() - 1
    assert m.state() == "lapsed"
    with pytest.raises(L.LicenseRequired, match="couldn't confirm"):
        m.require("acme.com")


def test_running_server_sees_key_activated_by_cli(portal):
    d = tempfile.mkdtemp()
    server = manager(d)
    assert server.state() == "missing"
    manager(d).activate(portal.issue("acme.com"))       # `zoltis license activate` in another process
    assert server.state() == "active" and server.domains == ["acme.com"]


def test_replacing_key_releases_the_old_one(portal):
    m = manager()
    old = portal.issue("acme.com")
    m.activate(old)
    m.activate(portal.issue("acme.com", "new.com"))
    assert m.domains == ["acme.com", "new.com"]
    assert any(path == "/v1/deactivate" and body["license_key"] == old for path, body in portal.calls)
    manager().activate(old)                              # freed for another server


# ------------------------------------------------------------------ enforcement in the account DB
def test_account_db_requires_license(portal):
    d = tempfile.mkdtemp()
    m = manager(d)
    db = AccountDB(os.path.join(d, "a.db"), {"max_accounts": 10, "max_quota_mb": 720}, "bundled", m)
    with pytest.raises(NotLicensed):
        db.add_domain("acme.com")
    m.activate(portal.issue("acme.com"))
    db.add_domain("acme.com")
    db.create_account("ann@acme.com", "Ann-pass-123")
    with pytest.raises(NotLicensed):
        db.add_domain("other.com")


def test_external_mode_new_sign_ins_need_license(portal):
    d = tempfile.mkdtemp()
    m = manager(d)
    db = AccountDB(os.path.join(d, "a.db"), {"max_accounts": 10}, "external", m)
    with pytest.raises(NotLicensed):
        db.ensure_seat("bob@acme.com")
    m.activate(portal.issue("acme.com"))
    assert db.ensure_seat("bob@acme.com")["is_admin"]
    with pytest.raises(NotLicensed):
        db.ensure_seat("eve@other.com")


def test_key_needed_within_7_days_of_installing(monkeypatch):
    """From 2.3.0 licensing is on by default: 7 days to add a key, then new accounts and domains are paused."""
    monkeypatch.delenv("ZOLTIS_LICENSE_REQUIRED", raising=False)
    monkeypatch.setenv("ZOLTIS_LICENSE_GRACE_DAYS", "7")
    d = tempfile.mkdtemp()
    m = manager(d)
    assert m.enabled and m.state() == "grace" and m.active
    assert 6.9 * 86400 < m.grace_until - time.time() <= 7 * 86400
    assert m.public()["grace_until"] == m.grace_until
    db = AccountDB(os.path.join(d, "a.db"), {"max_accounts": 10, "max_quota_mb": 720}, "bundled", m)
    db.add_domain("acme.com")                                     # everything works during the 7 days
    db.create_account("ann@acme.com", "Ann-pass-123")
    assert manager(d).grace_start == m.grace_start                # the start is remembered across restarts
    with open(os.path.join(d, "license.grace"), "w") as f:        # 8 days later
        f.write(str(int(time.time() - 8 * 86400)))
    m2 = manager(d)
    assert m2.state() == "missing" and not m2.active
    db2 = AccountDB(os.path.join(d, "a.db"), {"max_accounts": 10, "max_quota_mb": 720}, "bundled", m2)
    with pytest.raises(NotLicensed, match="zoltismail.com"):
        db2.create_account("bob@acme.com", "Bob-pass-123")


def test_licensing_can_still_be_turned_off_for_development(monkeypatch):
    monkeypatch.setenv("ZOLTIS_LICENSE_REQUIRED", "false")
    m = manager()
    assert not m.enabled and m.state() == "disabled" and m.active
    m.start()
    assert m._thread is None


def test_key_is_tied_to_the_server_ip(portal):
    m = manager()
    key = portal.issue("acme.com", ips=("203.0.113.9",))
    with pytest.raises(L.LicenseError, match="203.0.113.9"):        # the licensing server sees 127.0.0.1
        m.activate(key)
    m.public_ip = "198.51.100.7"                                  # known IP: refused before asking the server
    portal.calls.clear()
    with pytest.raises(L.LicenseError, match="this server's IP is 198.51.100.7"):
        m.activate(portal.issue("acme.com"))
    assert not portal.calls
    m.public_ip = "127.0.0.1"
    m.activate(portal.issue("acme.com"))
    assert m.state() == "active" and m.cert["ip"] == "127.0.0.1"
    with pytest.raises(L.LicenseError, match="isn't tied to a server IP"):
        L.parse_key(portal.issue("acme.com", ips=()))


def test_license_valid_one_year_from_activation(portal):
    m = manager()
    m.activate(portal.issue("acme.com"))
    b = m.billing()
    assert b["plan"] == "community" and 364 <= b["days_left"] <= 365 and b["status"] == "ok"
    assert m.billing(now=b["paid_until"] - 20 * 86400)["status"] == "renew_soon"   # renewal opens 30 days before
    assert m.billing(now=b["paid_until"] + 86400)["status"] == "renewal_due"


def test_community_allows_two_domains(monkeypatch):
    from zoltis.accounts import LimitReached
    from zoltis.edition import COMMUNITY_LIMITS
    monkeypatch.setenv("ZOLTIS_LICENSE_REQUIRED", "false")
    d = tempfile.mkdtemp()
    db = AccountDB(os.path.join(d, "a.db"), dict(COMMUNITY_LIMITS), "bundled", manager(d))
    db.add_domain("one.com")
    db.add_domain("two.com")
    with pytest.raises(LimitReached):
        db.add_domain("three.com")
    db.delete_domain("two.com")
    db.add_domain("three.com")  # freed slot can be reused


def test_daily_check_in_reports_license_id_and_edition_only(portal):
    """The portal learns that this server is live, its license ID and its edition - nothing about users or mail."""
    m = manager()
    m.edition = "community"
    key = portal.issue("acme.com")
    portal.calls.clear()
    m.activate(key)
    path, body = portal.calls[-1]
    assert path == "/v1/activate"
    assert set(body) == {"license_key", "license_id", "install_id", "edition", "app_version", "hostname", "integrity", "instance_id", "server_ip"}
    assert body["license_id"] == m.info["lid"] and body["edition"] == "community" and body["install_id"] == m.install_id
    m.refresh()                                       # the daily renewal sends the same check-in
    assert portal.calls[-1][1]["license_id"] == m.info["lid"]


DAY = 86400


def test_community_yearly_renewal_keeps_the_same_key(portal):
    m = manager()
    key = portal.issue("acme.com")
    lid = L.parse_key(key)["lid"]
    portal.billing[lid] = {"plan": "community", "paid_until": time.time() + 300 * DAY}
    m.activate(key)
    assert m.state() == "active" and m.billing()["status"] == "ok"
    portal.billing[lid]["paid_until"] = time.time() + 10 * DAY        # renewal date coming up
    m.refresh()
    assert m.state() == "active" and m.billing()["status"] == "renew_soon"
    portal.billing[lid]["paid_until"] = time.time() - DAY             # not renewed in time
    m.refresh()
    assert m.state() == "renewal_due" and not m.locked                # mail keeps working ...
    with pytest.raises(L.LicenseRequired, match="key stays the same"):
        m.require("acme.com")                                         # ... but no new accounts
    portal.billing[lid]["paid_until"] = time.time() + 365 * DAY       # renewed on the portal
    m.refresh()
    assert m.state() == "active" and m.key == key                     # same key, nothing to re-enter


def test_managed_plan_grace_period_then_suspension(portal):
    m = manager()
    key = portal.issue("acme.com")
    lid = L.parse_key(key)["lid"]
    due = time.time() - 3 * DAY
    portal.billing[lid] = {"plan": "managed", "paid_until": due, "status": "overdue"}
    m.activate(key)
    b = m.billing()
    assert b["status"] == "overdue" and not m.locked and abs(b["lock_at"] - (due + 10 * DAY)) < 1
    assert m.billing(now=due + 10 * DAY + 1)["status"] == "suspended"   # day 10: locked even before ZOcc says so
    portal.billing[lid]["status"] = "suspended"
    seen = []
    m.on_change = seen.append
    m.refresh()
    assert m.locked and m.state() == "suspended" and seen == [True]
    assert m.public()["suspended"] and "customer portal" in m.public()["message"]
    # only the portal (ZOcc) can lift it
    portal.billing[lid] = {"plan": "managed", "paid_until": time.time() + 30 * DAY, "status": "active"}
    m.refresh()
    assert not m.locked and m.state() == "active" and seen == [True, False]


def test_managed_plan_locks_when_portal_unreachable_past_grace(portal):
    m = manager()
    key = portal.issue("acme.com")
    lid = L.parse_key(key)["lid"]
    portal.billing[lid] = {"plan": "managed", "paid_until": time.time() + 5 * DAY, "status": "active"}
    m.activate(key)
    later = time.time() + 40 * DAY                                     # activation lapsed, no contact
    assert m.billing(now=later)["status"] == "suspended"
    assert m.billing(now=time.time() + 6 * DAY)["status"] == "ok"      # portal said active, still fresh


def test_admin_reminders_sent_once_at_each_step(monkeypatch):
    """Notices land in every admin's Inbox: at install, 3 days left, last day, after the deadline; each only once."""
    import email
    from zoltis import reminders
    monkeypatch.delenv("ZOLTIS_LICENSE_REQUIRED", raising=False)
    monkeypatch.setenv("ZOLTIS_LICENSE_GRACE_DAYS", "7")
    d = tempfile.mkdtemp()
    m = manager(d)
    m.public_ip = "203.0.113.9"
    got = []

    class App:
        data_dir, mode, license = d, "bundled", m
        accounts = type("A", (), {"accounts": staticmethod(lambda: [
            {"email": "boss@acme.com", "is_admin": True, "enabled": True},
            {"email": "ann@acme.com", "is_admin": False, "enabled": True}])})
        mailserver = type("M", (), {"deliver_notice": staticmethod(lambda to, raw: got.append((to, raw)))})

    now = m.grace_start + 60
    assert reminders.run(App, now) == "reg-start"
    assert reminders.run(App, now + 3600) is None                       # not twice
    assert [t for t, _ in got] == ["boss@acme.com"]                     # admins only
    msg = email.message_from_bytes(got[0][1])
    body = msg.get_payload()
    assert "within 7 days" in msg["Subject"] and "203.0.113.9" in body and "zoltismail.com" in body
    assert msg["Auto-Submitted"] == "auto-generated"
    assert reminders.run(App, m.grace_start + 4.5 * 86400) == "reg-3"
    assert reminders.run(App, m.grace_start + 6.5 * 86400) == "reg-last"
    with open(os.path.join(d, "license.grace"), "w") as f:
        f.write(str(int(time.time() - 8 * 86400)))
    App.license = manager(d)
    assert reminders.run(App) == "reg-over" and len(got) == 4


def test_rate_limited_check_in_keeps_the_license(portal, monkeypatch):
    """A 429 from zoltismail.com means "try later": the server must not drop its activation."""
    m = manager()
    m.activate(portal.issue("acme.com"))
    real = portal.handle
    monkeypatch.setattr(portal, "handle", lambda *a, **k: (429, {"error": "slow down"}))
    with pytest.raises(ConnectionError):
        m.refresh()
    assert m.state() == "active" and m.cert
    monkeypatch.setattr(portal, "handle", real)
