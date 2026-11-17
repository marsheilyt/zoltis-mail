"""Admin console + bundled mail server (emulated by devmail reading the rendered files)."""

import os
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "devtools"))

import pytest  # noqa: E402

import devmail  # noqa: E402
from test_zoltis import Client, free_port, mail  # noqa: E402,F401

ADMIN = ("boss@acme.test", "Adm1n-Secret!")


@pytest.fixture(scope="module")
def bundled(mail, portal):  # noqa: F811
    data = tempfile.mkdtemp()
    conf = os.path.join(data, "mailconf")
    port = free_port()
    env = {
        "ZOLTIS_SERVER_PORT": str(port), "ZOLTIS_SERVER_DATA_DIR": data,
        "ZOLTIS_IMAP_HOST": "127.0.0.1", "ZOLTIS_IMAP_PORT": str(mail["imap"]), "ZOLTIS_IMAP_SECURITY": "plain",
        "ZOLTIS_SMTP_HOST": "127.0.0.1", "ZOLTIS_SMTP_PORT": str(mail["smtp"]), "ZOLTIS_SMTP_SECURITY": "plain",
        "ZOLTIS_MAIL_SERVER_MODE": "bundled", "ZOLTIS_MAIL_SERVER_CONF_DIR": conf,
        "ZOLTIS_MAIL_SERVER_IMAP_HOST": "127.0.0.1", "ZOLTIS_MAIL_SERVER_IMAP_PORT": str(mail["imap"]),
        "ZOLTIS_MAIL_SERVER_HOSTNAME": "mail.acme.test", "ZOLTIS_SETUP_TOKEN": "TEST1234",
        "ZOLTIS_BRANDING_DEFAULT_DOMAIN": "",
    }
    saved = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    devmail.STORE.conf_dir = conf
    from http.server import ThreadingHTTPServer
    from zoltis import config
    from zoltis.server import App, make_handler
    app = App(config.load(None))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}", app, conf
    httpd.shutdown()
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def login(base, email, pw):
    c = Client(base)
    st, body, _ = c.call("POST", "/api/login", {"email": email, "password": pw})
    return c, st, body


@pytest.fixture(scope="module")
def admin(bundled, portal):
    base = bundled[0]
    c = Client(base)
    st, cfg, _ = c.call("GET", "/api/config")
    assert cfg["setup_needed"] and cfg["mail_mode"] == "bundled"
    st, r, _ = c.call("POST", "/api/setup", {"token": "WRONG", "email": ADMIN[0], "password": ADMIN[1]})
    assert st == 403
    assert cfg["license"]["state"] == "missing"
    st, r, _ = c.call("POST", "/api/setup", {"token": "test1234", "email": ADMIN[0], "password": ADMIN[1]})
    assert st == 400 and "license key" in r["error"]                        # a key is required
    st, r, _ = c.call("POST", "/api/setup", {"token": "test1234", "email": ADMIN[0], "password": ADMIN[1],
                                             "license_key": portal.issue("other.test")})
    assert st == 400 and "other.test" in r["error"]                          # key must cover the admin's domain
    st, r, _ = c.call("POST", "/api/setup", {"token": "test1234", "email": ADMIN[0], "password": ADMIN[1],
                                             "license_key": "ZM1.forged.key"})
    assert st == 400
    assert bundled[1].accounts.count() == 0
    st, r, _ = c.call("POST", "/api/setup", {"token": "test1234", "email": ADMIN[0], "password": ADMIN[1], "name": "Boss",
                                             "license_key": portal.issue("acme.test", "second.test", customer="Acme")})
    assert st == 200, r
    st, r, _ = c.call("POST", "/api/setup", {"token": "TEST1234", "email": "x@acme.test", "password": ADMIN[1]})
    assert st == 409
    c, st, body = login(base, *ADMIN)
    assert st == 200, body
    return c


def test_setup_created_domain_dkim_and_files(admin, bundled):
    _, _, conf = bundled
    users = open(os.path.join(conf, "dovecot/users")).read()
    assert users.startswith(f"{ADMIN[0]}:{{SHA512-CRYPT}}$6$") and "userdb_quota_rule=*:storage=720M" in users
    assert os.path.exists(os.path.join(conf, "dkim/keys/acme.test.private"))
    assert "zoltis._domainkey.acme.test" in open(os.path.join(conf, "dkim/KeyTable")).read()
    assert "acme.test OK" in open(os.path.join(conf, "postfix/domains")).read()
    st, me, _ = admin.call("GET", "/api/me")
    assert me["is_admin"] and me["limits"]["max_accounts"] == 10 and me["limits"]["max_quota_mb"] == 720


def test_domains_and_dns_records(admin):
    st, r, _ = admin.call("GET", "/api/admin/domains")
    d = r["domains"][0]
    types = {x["type"] + ":" + x["name"] for x in d["dns"]}
    assert "MX:acme.test" in types and "TXT:_dmarc.acme.test" in types and "TXT:zoltis._domainkey.acme.test" in types
    dk = next(x for x in d["dns"] if "_domainkey" in x["name"])
    assert dk["value"].startswith("v=DKIM1; k=rsa; p=MII")
    st, r, _ = admin.call("POST", "/api/admin/domains", {"name": "second.test"})
    assert st == 200 and r["dkim_selector"] == "zoltis"
    st, r, _ = admin.call("POST", "/api/admin/domains", {"name": "not a domain"})
    assert st == 400


def test_create_account_defaults_and_quota_cap(admin, bundled):
    st, a, _ = admin.call("POST", "/api/admin/accounts", {"email": "ann@acme.test", "password": "Ann-pass-123", "name": "Ann"})
    assert st == 200 and a["quota_mb"] == 720 and not a["is_admin"]
    st, r, _ = admin.call("POST", "/api/admin/accounts", {"email": "big@acme.test", "password": "Big-pass-123", "quota_mb": 1000})
    assert st == 402 and "720" in r["error"]
    st, r, _ = admin.call("POST", "/api/admin/accounts", {"email": "weak@acme.test", "password": "short"})
    assert st == 400
    st, r, _ = admin.call("POST", "/api/admin/accounts", {"email": "x@nodomain.test", "password": "Good-pass-123"})
    assert st == 400 and "domain" in r["error"].lower()
    c, st, _ = login(bundled[0], "ann@acme.test", "Ann-pass-123")
    assert st == 200
    st, me, _ = c.call("GET", "/api/me")
    assert not me["is_admin"]
    assert c.call("GET", "/api/admin/accounts")[0] == 403      # non-admins can't use the console
    st, q, _ = c.call("GET", "/api/account/quota")
    assert q["quota"]["limit_mb"] == 720


def test_10_account_limit(admin):
    st, r, _ = admin.call("GET", "/api/admin/accounts?usage=0")
    have = len(r["accounts"])
    for i in range(10 - have):
        st, a, _ = admin.call("POST", "/api/admin/accounts", {"email": f"u{i}@acme.test", "password": f"Pass-word-{i}x", "quota_mb": 100})
        assert st == 200, a
    st, r, _ = admin.call("POST", "/api/admin/accounts", {"email": "one-too-many@acme.test", "password": "Pass-word-99x"})
    assert st == 402 and "10" in r["error"]
    # deleting frees a seat
    st, r, _ = admin.call("POST", "/api/admin/accounts/delete", {"email": "u0@acme.test"})
    assert st == 200
    st, r, _ = admin.call("POST", "/api/admin/accounts", {"email": "one-too-many@acme.test", "password": "Pass-word-99x"})
    assert st == 200
    st, ov, _ = admin.call("GET", "/api/admin/overview")
    assert ov["accounts"] == 10 and ov["limits"]["max_accounts"] == 10


def test_quota_enforced(admin, bundled):
    admin.call("POST", "/api/admin/accounts/update", {"email": "u1@acme.test", "quota_mb": 10})
    devmail.STORE.sync()
    box = devmail.STORE.boxes["u1@acme.test"]["INBOX"]
    box.add(b"Subject: big\r\n\r\n" + b"x" * (10 * 1024 * 1024 + 100))
    c, st, _ = login(bundled[0], "u1@acme.test", "Pass-word-1x")
    st, q, _ = c.call("GET", "/api/account/quota")
    assert q["quota"]["percent"] >= 100
    # incoming mail to a full mailbox is refused
    c2, _, _ = login(bundled[0], "ann@acme.test", "Ann-pass-123")
    st, r, _ = c2.call("POST", "/api/send", {"to": "u1@acme.test", "subject": "hi", "html": "x"})
    assert st == 502 and "full" in r["error"].lower()
    # saving a draft in the full mailbox fails with a clear message
    st, r, _ = c.call("POST", "/api/draft", {"subject": "d", "html": "x"})
    assert st == 502 and "full" in r["error"].lower()
    st, accts, _ = admin.call("GET", "/api/admin/accounts")
    u1 = next(a for a in accts["accounts"] if a["email"] == "u1@acme.test")
    assert u1["usage"]["percent"] >= 100


def test_disable_reset_password_and_sessions(admin, bundled):
    c, st, _ = login(bundled[0], "u2@acme.test", "Pass-word-2x")
    assert st == 200
    st, r, _ = admin.call("GET", "/api/admin/sessions")
    assert any(x["email"] == "u2@acme.test" for x in r["sessions"])
    admin.call("POST", "/api/admin/accounts/update", {"email": "u2@acme.test", "enabled": False})
    assert c.call("GET", "/api/folders")[0] == 401                        # kicked out
    _, st, body = login(bundled[0], "u2@acme.test", "Pass-word-2x")
    assert st == 403 and "disabled" in body["error"]
    admin.call("POST", "/api/admin/accounts/update", {"email": "u2@acme.test", "enabled": True, "password": "Brand-new-pass1"})
    assert login(bundled[0], "u2@acme.test", "Pass-word-2x")[1] == 401
    assert login(bundled[0], "u2@acme.test", "Brand-new-pass1")[1] == 200
    st, r, _ = admin.call("POST", "/api/admin/accounts/update", {"email": ADMIN[0], "is_admin": False})
    assert st == 400                                                         # can't demote yourself


def test_user_changes_own_password(bundled, admin):
    c, st, _ = login(bundled[0], "u3@acme.test", "Pass-word-3x")
    st, r, _ = c.call("POST", "/api/account/password", {"current": "wrong", "new": "Another-pass-3"})
    assert st == 403
    st, r, _ = c.call("POST", "/api/account/password", {"current": "Pass-word-3x", "new": "Another-pass-3"})
    assert st == 200
    assert c.call("GET", "/api/folders")[0] == 200                          # current session survives
    assert login(bundled[0], "u3@acme.test", "Another-pass-3")[1] == 200


def test_aliases_and_sender_rules(admin, bundled):
    st, r, _ = admin.call("POST", "/api/admin/aliases", {"source": "info@acme.test", "destinations": "ann@acme.test, u4@acme.test"})
    assert st == 200
    c, _, _ = login(bundled[0], "u5@acme.test", "Pass-word-5x")
    before = len(devmail.STORE.boxes["ann@acme.test"]["INBOX"].msgs)
    st, r, _ = c.call("POST", "/api/send", {"to": "info@acme.test", "subject": "to alias", "html": "x"})
    assert st == 200, r
    assert len(devmail.STORE.boxes["ann@acme.test"]["INBOX"].msgs) == before + 1
    assert "info@acme.test ann@acme.test,u4@acme.test" in open(os.path.join(bundled[2], "postfix/senders")).read()


def test_delete_account_purges_mail(admin):
    devmail.STORE.sync()
    devmail.STORE.boxes["u6@acme.test"]["INBOX"].add(b"Subject: keep?\r\n\r\nbody")
    st, r, _ = admin.call("POST", "/api/admin/accounts/delete", {"email": "u6@acme.test"})
    assert st == 200 and r["purged"]
    assert devmail.STORE.boxes["u6@acme.test"]["INBOX"].msgs == []
    st, r, _ = admin.call("POST", "/api/admin/accounts/delete", {"email": ADMIN[0]})
    assert st == 400                                                         # can't delete yourself
    st, r, _ = admin.call("POST", "/api/admin/domains/delete", {"name": "acme.test"})
    assert st == 400 and "account" in r["error"]


def test_import_from_old_server(admin, bundled):
    src_count = sum(len(mb.msgs) for mb in devmail.STORE.boxes["alex@example.com"].values())
    st, j, _ = admin.call("POST", "/api/admin/import", {"email": "u7@acme.test", "host": "127.0.0.1",
                                                        "port": devmail_port(), "security": "plain",
                                                        "username": "alex@example.com", "password": "wrong"})
    assert st == 400
    st, j, _ = admin.call("POST", "/api/admin/import", {"email": "u7@acme.test", "host": "127.0.0.1",
                                                        "port": devmail_port(), "security": "plain",
                                                        "username": "alex@example.com", "password": "alex"})
    assert st == 200, j
    job = wait_job(admin, j["id"])
    assert job["state"] == "done" and job["copied"] == src_count, job
    # second run copies nothing new
    st, j, _ = admin.call("POST", "/api/admin/import", {"email": "u7@acme.test", "host": "127.0.0.1",
                                                        "port": devmail_port(), "security": "plain",
                                                        "username": "alex@example.com", "password": "alex"})
    job = wait_job(admin, j["id"])
    assert job["copied"] == 0 and job["skipped"] == src_count


def test_license_tab_and_unlicensed_domain(admin):
    st, L, _ = admin.call("GET", "/api/admin/license")
    assert st == 200 and L["state"] == "active" and L["domains"] == ["acme.test", "second.test"] and L["customer"] == "Acme"
    st, r, _ = admin.call("POST", "/api/admin/domains", {"name": "unlicensed.test"})
    assert st == 403 and "acme.test" in r["error"]
    st, r, _ = admin.call("POST", "/api/admin/license", {"key": "nonsense"})
    assert st == 400
    st, r, _ = admin.call("POST", "/api/admin/license/refresh")
    assert st == 200 and r["state"] == "active"


def test_audit_log(admin):
    st, r, _ = admin.call("GET", "/api/admin/audit")
    actions = {e["action"] for e in r["events"]}
    assert {"account.create", "account.update", "account.delete", "domain.add", "alias.set", "import.start"} <= actions


def devmail_port():
    return int(os.environ["ZOLTIS_MAIL_SERVER_IMAP_PORT"])


def wait_job(c, jid, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        st, r, _ = c.call("GET", "/api/admin/import")
        job = next(j for j in r["jobs"] if j["id"] == jid)
        if job["state"] not in ("queued", "running"):
            return job
        time.sleep(0.2)
    raise AssertionError("import timed out")


def test_dns_records_in_cloudflare_form():
    from zoltis.mailserver import BundledMailServer
    ms = object.__new__(BundledMailServer)
    ms.hostname, ms.web_hostname = "mail.acme.test", "webmail.acme.test"
    recs = {(r["type"], r["host"]): r for r in ms.dns_records(
        {"name": "acme.test", "dkim_selector": "zoltis", "dkim_public": "MIIB"}, "203.0.113.25")}
    mx = recs[("MX", "@")]
    assert mx["content"] == "mail.acme.test" and mx["priority"] == 10 and mx["value"] == "10 mail.acme.test."
    assert recs[("A", "mail")]["proxy"] == "DNS only" and recs[("A", "webmail")]["proxy"] == "DNS only"
    assert recs[("TXT", "@")]["content"].startswith("v=spf1 mx")
    assert ("TXT", "_dmarc") in recs and recs[("TXT", "zoltis._domainkey")]["content"].endswith("p=MIIB")
    assert recs[("PTR", "203.0.113.25")]["zone"] is None
    # a second domain served by the first domain's mail host: the A record lives in the other zone
    other = {(r["type"], r["host"]): r for r in ms.dns_records({"name": "second.test"}, "203.0.113.25")}
    assert other[("A", "mail")]["zone"] == "acme.test" and other[("MX", "@")]["content"] == "mail.acme.test"


def test_domains_api_reports_postmaster(admin):
    st, r, _ = admin.call("GET", "/api/admin/domains")
    d = next(x for x in r["domains"] if x["name"] == "acme.test")
    assert d["postmaster_ok"] is False and all("host" in x and "content" in x for x in d["dns"])
    admin.call("POST", "/api/admin/aliases", {"source": "postmaster@acme.test", "destinations": ADMIN[0]})
    st, r, _ = admin.call("GET", "/api/admin/domains")
    assert next(x for x in r["domains"] if x["name"] == "acme.test")["postmaster_ok"] is True


def test_5_alias_limit_and_upgrade_link(admin):
    st, r, _ = admin.call("GET", "/api/admin/aliases")
    assert r["max_aliases"] == 5 and "from=community" in r["upgrade_url"] and "acme.test" in r["upgrade_url"]
    for i in range(5 - r["counted"]):
        st, a, _ = admin.call("POST", "/api/admin/aliases", {"source": f"team{i}@acme.test", "destinations": "ann@acme.test"})
        assert st == 200, a
    st, r, _ = admin.call("POST", "/api/admin/aliases", {"source": "sixth@acme.test", "destinations": "ann@acme.test"})
    assert st == 402 and "5 aliases" in r["error"] and "Mail Pro" in r["error"]
    # editing an existing alias and postmaster@ are still allowed at the limit
    st, r, _ = admin.call("POST", "/api/admin/aliases", {"source": "info@acme.test", "destinations": "ann@acme.test"})
    assert st == 200
    st, r, _ = admin.call("POST", "/api/admin/aliases", {"source": "postmaster@second.test", "destinations": ADMIN[0]})
    assert st == 200
    st, ov, _ = admin.call("GET", "/api/admin/overview")
    assert ov["aliases_counted"] == 5 and ov["limits"]["max_aliases"] == 5
    # deleting frees a slot
    admin.call("POST", "/api/admin/aliases/delete", {"source": "team0@acme.test"})
    st, r, _ = admin.call("POST", "/api/admin/aliases", {"source": "sixth@acme.test", "destinations": "ann@acme.test"})
    assert st == 200


def test_export_import_round_trip(admin, bundled):
    """Everything needed to move to a managed server survives export -> delete -> import."""
    from zoltis import migration
    base, app, _ = bundled
    pw = "correct horse battery"
    c, st, _ = login(base, "ann@acme.test", "Ann-pass-123")
    assert st == 200
    c.call("POST", "/api/folders", {"name": "Projects"})
    c.call("POST", "/api/settings", {"signature": "Ann from Acme", "theme": "dark"})
    devmail.STORE.sync()
    box = devmail.STORE.boxes["ann@acme.test"]
    box["Projects"].add(b"Message-ID: <p1@acme.test>\r\nSubject: plan\r\n\r\nsee attached", {"\\Flagged", "\\Seen"})
    box["INBOX"].add(b"Message-ID: <in1@acme.test>\r\nSubject: unread one\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n"
                     b"--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b\r\nContent-Type: application/pdf\r\n"
                     b"Content-Disposition: attachment; filename=a.pdf\r\n\r\n%PDF-1.4\r\n--b--\r\n", set())
    before = {f: len(mb.msgs) for f, mb in box.items()}

    path = os.path.join(tempfile.mkdtemp(), "acme.zmexport")
    job = migration.MigrationJob("export", path)
    migration.export_all(app, path, pw, job)
    assert job.state == "done" and job.accounts == app.accounts.count() and job.messages >= 2, job.as_dict()
    assert open(path, "rb").read(8) == b"Salted__"              # encrypted, not a readable tar

    bad = migration.MigrationJob("import", path)
    with pytest.raises(migration.MigrationError, match="passphrase"):
        migration.import_all(app, path, "wrong passphrase!", bad)

    # the customer moves: the account and its mail are gone from "this" server
    assert admin.call("POST", "/api/admin/accounts/delete", {"email": "ann@acme.test"})[0] == 200
    devmail.STORE.sync()
    job = migration.MigrationJob("import", path)
    migration.import_all(app, path, pw, job)
    assert job.state == "done", job.as_dict()
    devmail.STORE.sync()
    box = devmail.STORE.boxes["ann@acme.test"]
    assert {f: len(mb.msgs) for f, mb in box.items() if mb.msgs} == {f: n for f, n in before.items() if n}
    plan = box["Projects"].msgs[0]
    assert {"\\Flagged", "\\Seen"} <= set(plan.flags)
    assert not any("\\Seen" in m.flags for m in box["INBOX"].msgs if b"unread one" in m.raw)
    assert any(b"filename=a.pdf" in m.raw for m in box["INBOX"].msgs)           # attachment intact
    c, st, _ = login(base, "ann@acme.test", "Ann-pass-123")                     # same password as before
    assert st == 200
    st, me, _ = c.call("GET", "/api/me")
    assert me["settings"]["signature"] == "Ann from Acme" and me["settings"]["theme"] == "dark"

    # running it again duplicates nothing
    again = migration.MigrationJob("import", path)
    migration.import_all(app, path, pw, again)
    assert again.state == "done" and again.messages == 0 and again.skipped >= job.messages


def test_migration_api_files(admin, bundled):
    st, r, _ = admin.call("POST", "/api/admin/migration/export", {"passphrase": "short"})
    assert st == 400
    st, j, _ = admin.call("POST", "/api/admin/migration/export", {"passphrase": "a long passphrase"})
    assert st == 200, j
    end = time.time() + 30
    while time.time() < end:
        st, r, _ = admin.call("GET", "/api/admin/migration")
        job = next(x for x in r["jobs"] if x["id"] == j["id"])
        if job["state"] not in ("queued", "running"):
            break
        time.sleep(0.2)
    assert job["state"] == "done", job
    f = next(x for x in r["files"] if x["file"] == job["file"])
    st, data, hdr = admin.call("GET", "/api/admin/migration/download?file=" + f["file"])
    assert st == 200 and len(data) == f["size"] and "attachment" in hdr["Content-Disposition"]
    assert admin.call("GET", "/api/admin/migration/download?file=../accounts.db")[0] == 400
    st, r, _ = admin.call("POST", "/api/admin/migration/delete", {"file": f["file"]})
    assert st == 200 and not os.path.exists(os.path.join(bundled[1].export_dir, f["file"]))
