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
    with pytest.raises(L.LicenseRequired, match="Register"):
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


def test_licensing_off_by_default_allows_everything(monkeypatch):
    monkeypatch.delenv("ZOLTIS_LICENSE_REQUIRED", raising=False)
    d = tempfile.mkdtemp()
    m = manager(d)
    assert not m.enabled
    assert m.state() == "disabled" and m.active
    assert m.public()["required"] is False
    m.start()  # must not start the portal renewal thread
    assert m._thread is None
    db = AccountDB(os.path.join(d, "a.db"), {"max_accounts": 10, "max_quota_mb": 720}, "bundled", m)
    db.add_domain("acme.com")
    db.add_domain("other.com")
    db.create_account("ann@other.com", "Ann-pass-123")
