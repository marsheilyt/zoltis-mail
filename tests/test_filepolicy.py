"""Tests for the attachment blocker (zoltis/mail/filepolicy.py) and its API wiring."""

import base64
import gzip
import io
import os
import sys
import tarfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from zoltis.config import Config  # noqa: E402
from zoltis.mail.filepolicy import FilePolicy  # noqa: E402
from test_zoltis import client, mail, server  # noqa: E402,F401  (fixtures)

PE = b"MZ" + b"\0" * 512
ELF = b"\x7fELF" + b"\0" * 60


def mkzip(files, method=zipfile.ZIP_DEFLATED):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", method) as z:
        for n, d in files:
            z.writestr(n, d)
    return b.getvalue()


def mktar(files, mode="w"):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode=mode) as t:
        for n, d in files:
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            t.addfile(ti, io.BytesIO(d))
    return b.getvalue()


def encrypt_flag(zbytes):
    """Set the 'encrypted' general-purpose flag on every entry (simulates a password zip)."""
    b = bytearray(zbytes)
    i = 0
    while True:
        i = b.find(b"PK\x03\x04", i)
        if i < 0:
            break
        b[i + 6] |= 1
        i += 4
    i = 0
    while True:
        i = b.find(b"PK\x01\x02", i)
        if i < 0:
            break
        b[i + 8] |= 1
        i += 4
    return bytes(b)


P = FilePolicy()


def v(name, data=None, pol=P):
    return pol.check(name, data)["verdict"]


@pytest.mark.parametrize("name", ["setup.exe", "run.bat", "a.cmd", "x.scr", "y.js", "z.vbs", "p.ps1",
                                  "i.msi", "j.jar", "s.lnk", "d.iso", "h.hta", "lib.dll", "SETUP.EXE", "c.com"])
def test_blocked_extensions(name):
    assert v(name) == "block"


@pytest.mark.parametrize("name", ["report.pdf", "photo.JPG", "notes.txt", "budget.xlsx", "slides.pptx",
                                  "archive.zip", "data.csv", "script.py", "readme"])
def test_safe_names_allowed(name):
    assert v(name) == "allow"


def test_double_extension_and_tricks():
    r = P.check("invoice.pdf.exe")
    assert r["verdict"] == "block" and "disguised" in r["summary"]
    assert v("photo‮gpj.exe") == "block"        # right-to-left override
    assert v("report.pdf‮") == "block"
    assert v("document.pdf .") == "block"             # trailing dot/space trick
    assert v("statement.pdf                    .exe") == "block"


def test_renamed_executables_detected_by_content():
    assert v("holiday.jpg", PE) == "block"
    assert v("notes.txt", ELF) == "block"
    assert v("noext", PE) == "block"
    assert v("photo.jpg", b"\xff\xd8\xff\xe0 real jpeg") == "allow"
    assert v("install.sh", b"#!/bin/sh\necho") == "warn"


def test_archives_are_inspected_recursively():
    assert v("photos.zip", mkzip([("a.jpg", b"x"), ("b/c.png", b"y")])) == "allow"
    r = P.check("project.zip", mkzip([("project/readme.txt", b"x"), ("project/bin/tool.exe", PE)]))
    assert r["verdict"] == "block" and "project/bin/tool.exe" in r["summary"]
    nested = mkzip([("l1.zip", mkzip([("l2.zip", mkzip([("evil.vbs", b"x")]))]))])
    assert v("nested.zip", nested) == "block"
    assert v("renamed.zip", mkzip([("pic.jpg", PE)])) == "block"   # renamed exe inside archive


def test_archive_depth_limit():
    pol = FilePolicy(Config({"attachments": {"archive_max_depth": "1"}}))
    deep = mkzip([("inner.zip", mkzip([("ok.txt", b"x")]))])
    assert v("deep.zip", deep, pol) == "block"


def test_tar_and_gzip():
    assert v("src.tar.gz", gzip.compress(mktar([("src/main.c", b"int main(){}")]))) == "allow"
    assert v("bad.tgz", gzip.compress(mktar([("bin/payload.exe", PE)]))) == "block"
    assert v("traverse.tar", mktar([("../../etc/passwd", b"x")])) == "block"
    assert v("prog.exe.gz", gzip.compress(PE)) == "block"


def test_zip_path_traversal_and_bomb():
    assert v("slip.zip", mkzip([("../../.bashrc", b"x")])) == "block"
    bomb = mkzip([("zeros.bin", b"\0" * (40 * 1024 * 1024))])
    r = P.check("bomb.zip", bomb)
    assert r["verdict"] == "block" and "zip bomb" in r["summary"]


def test_encrypted_archive_policy():
    enc = encrypt_flag(mkzip([("secret.pdf", b"x" * 100)], zipfile.ZIP_STORED))
    r = P.check("secret.zip", enc)
    assert r["verdict"] == "block" and "password" in r["summary"]
    lenient = FilePolicy(Config({"attachments": {"encrypted_archives": "warn"}}))
    assert v("secret.zip", enc, lenient) == "warn"
    # names inside an encrypted archive are still checked
    enc_exe = encrypt_flag(mkzip([("setup.exe", PE)], zipfile.ZIP_STORED))
    assert any("setup.exe" in f["path"] and f["level"] == "block" for f in lenient.check("x.zip", enc_exe)["findings"])


def test_office_macros():
    clean = mkzip([("[Content_Types].xml", b"x"), ("word/document.xml", b"x")])
    hidden = mkzip([("[Content_Types].xml", b"x"), ("word/vbaProject.bin", b"x")])
    assert v("letter.docx", clean) == "allow"
    assert v("letter.docx", hidden) == "warn"
    assert v("model.xlsm", hidden) == "warn"
    strict = FilePolicy(Config({"attachments": {"macro_documents": "block"}}))
    assert v("letter.docx", hidden, strict) == "block"
    assert v("model.xlsm", None, strict) == "block"


def test_opaque_archives():
    assert v("files.rar", b"Rar!\x1a\x07\x00rest") == "warn"
    assert v("files.zip", b"7z\xbc\xaf\x27\x1crest") == "warn"   # 7z disguised as zip


def test_admin_overrides():
    pol = FilePolicy(Config({"attachments": {"extra_blocked_extensions": "py, .apk2", "allowed_extensions": "iso"}}))
    assert v("tool.py", None, pol) == "block"
    assert v("x.apk2", None, pol) == "block"
    assert v("ubuntu.iso", None, pol) == "allow"
    strict = FilePolicy(Config({"attachments": {"strict_scripts": "true"}}))
    assert v("deploy.sh", None, strict) == "block" and v("tool.py", None, strict) == "block"
    off = FilePolicy(Config({"attachments": {"enabled": "false"}}))
    assert v("setup.exe", PE, off) == "allow"


# ------------------------------------------------------------------ API
def b64(d):
    return base64.b64encode(d).decode()


def test_api_send_blocks_risky_attachment(client):  # noqa: F811
    import devmail
    n = len(devmail.STORE.outbox)
    for name, data in [("invoice.pdf.exe", PE), ("project.zip", mkzip([("p/run.bat", b"x")])), ("cat.jpg", PE)]:
        st, r, _ = client.call("POST", "/api/send", {"to": "alex@example.com", "subject": "x", "html": "x",
                                                     "attachments": [{"filename": name, "data": b64(data)}]})
        assert st == 422 and name in r["error"], (name, r)
    assert len(devmail.STORE.outbox) == n


def test_api_send_allows_clean_folder_zip(client):  # noqa: F811
    st, r, _ = client.call("POST", "/api/send", {"to": "alex@example.com", "subject": "folder", "html": "x",
                                                 "attachments": [{"filename": "Docs.zip", "data": b64(mkzip([("Docs/a.txt", b"x")]))}]})
    assert st == 200, r


def test_api_drafts_also_blocked(client):  # noqa: F811
    st, r, _ = client.call("POST", "/api/draft", {"subject": "d", "html": "x",
                                                  "attachments": [{"filename": "x.exe", "data": b64(PE)}]})
    assert st == 422


def test_api_check_endpoint(client):  # noqa: F811
    st, r, _ = client.call("POST", "/api/attachments/check", {"files": [
        {"name": "Folder/a.txt"}, {"name": "Folder/sub/b.scr"}, {"name": "x.zip", "data": b64(mkzip([("y.exe", PE)]))}]})
    verdicts = [x["verdict"] for x in r["results"]]
    assert verdicts == ["allow", "block", "block"]


def test_api_incoming_blocked_and_flagged(client):  # noqa: F811
    _, body, _ = client.call("GET", "/api/messages?folder=INBOX&q=subject:%22Project%20files%22")
    uid = body["messages"][0]["uid"]
    _, msg, _ = client.call("GET", f"/api/message?folder=INBOX&uid={uid}")
    att = msg["attachments"][0]
    assert att["policy"]["verdict"] == "block" and "setup.exe" in att["policy"]["summary"]
    st, r, _ = client.call("GET", f"/api/attachment?folder=INBOX&uid={uid}&part={att['part']}&download=1")
    assert st == 403 and "blocked" in r["error"]
    st, r, _ = client.call("GET", f"/api/scan?folder=INBOX&uid={uid}&part={att['part']}")
    assert r["status"] == "skipped"


def test_api_incoming_macro_is_warning_not_blocked(client):  # noqa: F811
    _, body, _ = client.call("GET", "/api/messages?folder=INBOX&q=subject:Budget")
    uid = body["messages"][0]["uid"]
    _, msg, _ = client.call("GET", f"/api/message?folder=INBOX&uid={uid}")
    att = msg["attachments"][0]
    assert att["policy"]["verdict"] == "warn"
    st, data, _ = client.call("GET", f"/api/attachment?folder=INBOX&uid={uid}&part={att['part']}&download=1")
    assert st == 200


def test_api_config_exposes_policy(server):  # noqa: F811
    from test_zoltis import Client
    st, cfg, _ = Client(server[0]).call("GET", "/api/config")
    assert "exe" in cfg["attachments"]["blocked_extensions"] and cfg["attachments"]["enabled"]
