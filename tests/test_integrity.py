"""Code integrity: changed core files are detected, reported at the license check-in and lock the service."""

import os
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from zoltis import __version__, integrity as I, licensing as L  # noqa: E402

SEED = bytes(range(32))
KEYS = {"rel": L.ed25519_public_key(SEED).hex()}


@pytest.fixture
def tree():
    """A copy of the real zoltis/ and web/ folders, signed like a release."""
    d = tempfile.mkdtemp()
    pkg, web = os.path.join(d, "zoltis"), os.path.join(d, "web")
    ign = shutil.ignore_patterns("__pycache__", "*.pyc", I.MANIFEST_NAME)
    shutil.copytree(os.path.join(ROOT, "zoltis"), pkg, ignore=ign)
    shutil.copytree(os.path.join(ROOT, "web"), web, ignore=ign)
    with open(os.path.join(pkg, I.MANIFEST_NAME), "w") as f:
        f.write(I.sign_manifest(I.compute(pkg, web), __version__, SEED, "rel"))
    yield pkg, web
    shutil.rmtree(d)


def test_untouched_release_is_ok(tree):
    r = I.verify(*tree, __version__, KEYS)
    assert r["status"] == "ok" and r["signed"] and len(r["fingerprint"]) == 64
    assert "web/img/logo.svg" in I.compute(*tree)          # the logo is part of the protected files


def test_changed_added_and_deleted_files_are_listed(tree):
    pkg, web = tree
    with open(os.path.join(web, "img/logo.svg"), "a") as f:
        f.write("<!-- my logo -->")
    open(os.path.join(pkg, "backdoor.py"), "w").write("x = 1\n")
    os.remove(os.path.join(pkg, "totp.py"))
    os.makedirs(os.path.join(pkg, "__pycache__"), exist_ok=True)
    open(os.path.join(pkg, "__pycache__", "x.cpython-312.pyc"), "wb").write(b"cache")   # ignored
    r = I.verify(pkg, web, __version__, KEYS)
    assert r["status"] == "modified"
    assert r["changed"] == ["web/img/logo.svg"] and r["added"] == ["zoltis/backdoor.py"] and r["missing"] == ["zoltis/totp.py"]


def test_unsigned_forged_or_wrong_version_manifest(tree):
    pkg, web = tree
    assert I.verify(pkg, web, "9.9.9", KEYS)["status"] == "unsigned"                  # manifest from another version
    forged = I.sign_manifest(I.compute(pkg, web), __version__, os.urandom(32), "rel")  # someone re-signs edited code
    open(os.path.join(pkg, I.MANIFEST_NAME), "w").write(forged)
    assert I.verify(pkg, web, __version__, KEYS)["status"] == "unsigned"
    os.remove(os.path.join(pkg, I.MANIFEST_NAME))
    r = I.verify(pkg, web, __version__, KEYS)
    assert r["status"] == "unsigned" and not r["signed"]


def test_community_edition_always_shows_zoltis_mail_name():
    from zoltis.edition import Edition
    from zoltis import config
    e = Edition(config.load(None))
    assert e.name == "community" and not e.custom_branding
    assert e.app_name("Acme Webmail") == "Zoltis Mail" and e.app_name("") == "Zoltis Mail"
    e.name, e.features = "enterprise", e.features + ["custom_branding"]
    assert e.app_name("Acme Webmail") == "Acme Webmail"


def test_unsigned_build_locks_only_once_a_release_key_is_trusted(tree, monkeypatch):
    """Before the first signed release (no Zoltis key in the build) an unsigned copy must keep working."""
    from zoltis import config
    pkg, web = tree
    os.remove(os.path.join(pkg, I.MANIFEST_NAME))                       # unsigned copy
    monkeypatch.setenv("ZOLTIS_INTEGRITY_ENFORCE", "auto")

    class Lic:
        enabled, integrity, integrity_locked = True, {}, False
        report_soon = _notify = lambda self: None

    monkeypatch.setattr(L, "TRUSTED_KEYS", {})
    lic = Lic()
    mon = I.IntegrityMonitor(config.Config({}), lic, web, pkg)
    assert mon.result["status"] == "unsigned" and not mon.enforced and not lic.integrity_locked
    monkeypatch.setattr(L, "TRUSTED_KEYS", dict(KEYS))                  # official build trusts the Zoltis key
    mon.check()
    assert mon.enforced and lic.integrity_locked
