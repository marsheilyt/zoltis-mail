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
        "ZOLTIS_MAIL_SERVER_INTERNAL_SECURITY": "plain",   # the test IMAP server has no TLS
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
    assert cfg["policies"]["version"] == "1.0" and cfg["policies"]["url"].endswith(".md")
    st, r, _ = c.call("POST", "/api/setup", {"token": "test1234", "email": ADMIN[0], "password": ADMIN[1]})
    assert st == 400 and "policies" in r["error"]                            # the policies must be accepted
    st, r, _ = c.call("POST", "/api/setup", {"token": "test1234", "email": ADMIN[0], "password": ADMIN[1], "accept_policies": "0.9"})
    assert st == 400 and "policies" in r["error"]                            # ... the current version
    pol = Client(base).call("GET", cfg["policies"]["url"])
    assert pol[0] == 200 and b"Acceptable use" in pol[1] and b"Encryption" not in pol[1]
    st, r, _ = c.call("POST", "/api/setup", {"token": "test1234", "email": ADMIN[0], "password": ADMIN[1], "accept_policies": "1.0"})
    assert st == 400 and "license key" in r["error"]                        # a key is required
    st, r, _ = c.call("POST", "/api/setup", {"token": "test1234", "email": ADMIN[0], "password": ADMIN[1],
                                             "license_key": portal.issue("other.test"), "accept_policies": "1.0"})
    assert st == 400 and "other.test" in r["error"]                          # key must cover the admin's domain
    st, r, _ = c.call("POST", "/api/setup", {"token": "test1234", "email": ADMIN[0], "password": ADMIN[1],
                                             "license_key": "ZM1.forged.key", "accept_policies": "1.0"})
    assert st == 400
    assert bundled[1].accounts.count() == 0
    st, r, _ = c.call("POST", "/api/setup", {"token": "test1234", "email": ADMIN[0], "password": ADMIN[1], "name": "Boss",
                                             "license_key": portal.issue("acme.test", "second.test", customer="Acme"), "accept_policies": "1.0", "timezone": "Asia/Dubai"})
    assert st == 200, r
    st, r, _ = c.call("POST", "/api/setup", {"token": "TEST1234", "email": "x@acme.test", "password": ADMIN[1]})
    assert st == 409
    pst = bundled[1].accounts.policy_status()
    assert pst["accepted"] and pst["accepted_by"] == ADMIN[0] and pst["version"] == "1.0"   # who accepted, when
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


def test_mta_sts_records_policy_and_modes(admin, bundled):
    import urllib.request
    base, app, _ = bundled
    st, r, _ = admin.call("GET", "/api/admin/domains")
    d = next(x for x in r["domains"] if x["name"] == "acme.test")
    recs = {(x["type"], x["host"]): x for x in d["dns"]}
    assert d["mta_sts"] == "testing"
    assert recs[("CNAME", "mta-sts")]["content"] == "mail.acme.test" and recs[("CNAME", "mta-sts")]["proxy"] == "DNS only"
    assert recs[("TXT", "_mta-sts")]["content"].startswith("v=STSv1; id=")
    assert recs[("TXT", "_smtp._tls")]["content"] == "v=TLSRPTv1; rua=mailto:postmaster@acme.test"

    def policy(host):
        req = urllib.request.Request(base + "/.well-known/mta-sts.txt", headers={"Host": host})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, ""
    st, body = policy("mta-sts.acme.test")
    assert st == 200 and "mode: testing\r\n" in body and "mx: mail.acme.test\r\n" in body and "max_age: 86400" in body
    assert policy("mta-sts.unknown.test")[0] == 404 and policy("acme.test")[0] == 404
    # Caddy's on-demand certificate check
    c = Client(base)
    assert c.call("GET", "/api/internal/tls-allowed?domain=mta-sts.acme.test")[0] == 200
    assert c.call("GET", "/api/internal/tls-allowed?domain=evil.example")[0] == 404

    old_id = recs[("TXT", "_mta-sts")]["content"]
    st, r, _ = admin.call("POST", "/api/admin/domains/mta-sts", {"name": "acme.test", "mode": "enforce"})
    assert st == 200 and r["mta_sts"] == "enforce" and r["mta_sts_id"]
    st, body = policy("mta-sts.acme.test")
    assert "mode: enforce" in body and "max_age: 604800" in body
    st, r, _ = admin.call("GET", "/api/admin/domains")
    d = next(x for x in r["domains"] if x["name"] == "acme.test")
    assert next(x for x in d["dns"] if x["host"] == "_mta-sts")["content"] != old_id
    assert admin.call("POST", "/api/admin/domains/mta-sts", {"name": "acme.test", "mode": "strict"})[0] == 400
    admin.call("POST", "/api/admin/domains/mta-sts", {"name": "acme.test", "mode": "off"})
    assert policy("mta-sts.acme.test")[0] == 404
    st, r, _ = admin.call("GET", "/api/admin/domains")
    d = next(x for x in r["domains"] if x["name"] == "acme.test")
    assert not any(x["host"] in ("mta-sts", "_mta-sts", "_smtp._tls") for x in d["dns"])
    admin.call("POST", "/api/admin/domains/mta-sts", {"name": "acme.test", "mode": "testing"})


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


# ---------------------------------------------------------------- 2-step verification & app passwords
def test_totp_rfc6238_vector():
    from zoltis import totp
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"            # "12345678901234567890"
    assert totp.now_code(secret, at=59) == "287082"           # RFC 6238 (last 6 of 94287082)
    assert totp.now_code(secret, at=1111111109) == "081804"
    step = totp.verify(secret, "081804", at=1111111109)
    assert step == 1111111109 // 30
    assert totp.verify(secret, "081804", last_counter=step, at=1111111109) is None   # no reuse
    assert totp.verify(secret, "000000", at=1111111109) is None
    assert totp.normalize_recovery("ABCDE 23456") == "abcde-23456"
    assert all(len(c) == 11 for c in totp.new_recovery_codes())


def test_default_theme_is_light(tmp_path):
    from zoltis.store import UserStore
    assert UserStore(str(tmp_path)).load("new@acme.test")["settings"]["theme"] == "light"


def test_two_step_verification_and_app_password(admin, bundled):
    import plistlib
    import re
    from zoltis import totp
    base, app, conf = bundled
    who, pw = "ann@acme.test", "Ann-pass-123"
    users = lambda: open(os.path.join(conf, "dovecot/users")).read()
    app_pws = lambda: open(os.path.join(conf, "dovecot/app-passwords")).read()
    line = lambda: next(l for l in users().splitlines() if l.startswith(who + ":"))

    c, st, r = login(base, who, pw)
    assert st == 200 and "twofa_required" not in r
    st, r, _ = c.call("GET", "/api/account/security")
    assert r == {"available": True, "twofa": False, "recovery_left": 0, "app_password": False, "app_password_created": None}

    # turn it on
    assert c.call("POST", "/api/account/2fa/start", {"password": "wrong"})[0] == 403
    st, r, _ = c.call("POST", "/api/account/2fa/start", {"password": pw})
    assert st == 200 and r["uri"].startswith("otpauth://totp/") and f"secret={r['secret']}" in r["uri"]
    secret = r["secret"]
    assert c.call("POST", "/api/account/2fa/enable", {"code": "000000"})[0] == 400
    enable_code = totp.now_code(secret)
    st, r, _ = c.call("POST", "/api/account/2fa/enable", {"code": enable_code})
    assert st == 200 and len(r["recovery_codes"]) == 10
    codes = r["recovery_codes"]
    assert "allow_nets=" in line() and "allow_nets" not in next(l for l in users().splitlines() if l.startswith(ADMIN[0]))
    st, accts, _ = admin.call("GET", "/api/admin/accounts")
    a = next(x for x in accts["accounts"] if x["email"] == who)
    assert a["twofa"] is True and "totp_secret" not in a and "recovery_codes" not in a

    # the account password alone no longer gives mail apps access (only the webmail's network)
    assert devmail.STORE.authenticate(who, pw, "203.0.113.5")[0] is None
    assert devmail.STORE.authenticate(who, pw, "127.0.0.1")[0] == who

    # sign-in needs the second step
    c2, st, r = login(base, who, pw)
    assert st == 200 and r["twofa_required"] and r["ticket"]
    assert c2.call("GET", "/api/me")[0] == 401
    ticket = r["ticket"]
    assert c2.call("POST", "/api/login/2fa", {"ticket": ticket, "code": "123456"})[0] == 401
    assert c2.call("POST", "/api/login/2fa", {"ticket": ticket, "code": enable_code})[0] == 401  # used at enable
    assert c2.call("POST", "/api/login/2fa", {"ticket": "bogus", "code": codes[0]})[0] == 401
    st, r, _ = c2.call("POST", "/api/login/2fa", {"ticket": ticket, "code": codes[0].upper().replace("-", " ")})
    assert st == 200 and r["recovery_left"] == 9
    assert c2.call("GET", "/api/me")[0] == 200
    assert c2.call("POST", "/api/login/2fa", {"ticket": ticket, "code": codes[1]})[0] == 401     # ticket is single-use

    c3, st, r = login(base, who, pw)
    assert c3.call("POST", "/api/login/2fa", {"ticket": r["ticket"], "code": codes[0]})[0] == 401  # recovery code is single-use
    st, r2, _ = c3.call("POST", "/api/login/2fa", {"ticket": r["ticket"], "code": totp.now_code(secret, time.time() + 30)})
    assert st == 200, r2
    st, r, _ = c3.call("POST", "/api/send", {"to": ADMIN[0], "subject": "sent with 2fa on", "html": "<p>hi</p>"})
    assert st == 200, r                                                           # webmail still sends

    # app password for mail apps
    st, r, _ = c3.call("POST", "/api/account/app-password", {"password": pw})
    assert st == 200 and re.fullmatch(r"[a-z]{4}(-[a-z]{4}){3}", r["app_password"])
    apw = r["app_password"]
    assert app_pws().startswith(who + ":{SHA512-CRYPT}$6$")
    assert devmail.STORE.authenticate(who, apw, "203.0.113.5")[0] == who
    assert c3.call("POST", "/api/login", {"email": who, "password": apw})[1].get("twofa_required")  # IMAP accepts it, 2FA still asked

    # mail app setup info + Apple profile
    st, m, _ = c3.call("GET", "/api/account/mail-setup")
    assert m["imap"] == {"host": "mail.acme.test", "port": 993, "security": "SSL/TLS"} and m["smtp"]["port"] == 587
    assert m["twofa"] and m["app_password"] and m["username"] == who
    st, data, hdr = c3.call("GET", "/api/account/apple-profile")
    assert st == 200 and hdr.get_content_type() == "application/x-apple-aspen-config"
    p = plistlib.loads(data)["PayloadContent"][0]
    assert p["EmailAddress"] == who and p["IncomingMailServerHostName"] == "mail.acme.test" and p["IncomingMailServerPortNumber"] == 993
    assert pw not in data.decode() and apw not in data.decode()

    # admin turns it off (lost phone)
    st, r, _ = admin.call("POST", "/api/admin/accounts/update", {"email": who, "reset_2fa": True})
    assert st == 200 and r["twofa"] is False and r["has_app_password"] is False
    assert "allow_nets" not in line() and who not in app_pws()
    assert devmail.STORE.authenticate(who, pw, "203.0.113.5")[0] == who
    c4, st, r = login(base, who, pw)
    assert st == 200 and "twofa_required" not in r


def test_mobile_app_api_token_and_discovery(admin, bundled):
    """The future Zoltis Mail app: find the server, sign in for a bearer token (with 2FA), use the API."""
    import json as _json
    import urllib.error
    import urllib.request
    from zoltis import totp
    base = bundled[0]
    who, pw = "app-user@acme.test", "App-pass-1234"
    assert admin.call("POST", "/api/admin/accounts", {"email": who, "password": pw})[0] == 200

    def raw(method, path, body=None, token=None, csrf=True):
        req = urllib.request.Request(base + path, data=_json.dumps(body).encode() if body is not None else None, method=method)
        req.add_header("Content-Type", "application/json")
        if csrf:
            req.add_header("X-Zoltis", "1")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req) as r:   # no cookie jar, like a native app
                return r.status, _json.loads(r.read()), r.headers
        except urllib.error.HTTPError as e:
            return e.code, _json.loads(e.read()), e.headers

    st, d, _ = raw("GET", "/.well-known/zoltis-mail.json")
    assert st == 200 and d["service"] == "zoltis-mail" and d["api_version"] == 1
    assert d["auth"]["scheme"] == "Bearer" and d["imap"] == {"host": "mail.acme.test", "port": 993, "security": "ssl"}
    assert d["features"]["two_factor"] and raw("GET", "/api/client")[1] == d

    # sign in as the app: a token in the body, no cookie
    st, r, h = raw("POST", "/api/login", {"email": who, "password": pw, "client": "app"})
    assert st == 200 and r["token_type"] == "Bearer" and r["token"] and r["expires_in"] > 0 and not h.get("Set-Cookie")
    tok = r["token"]
    st, me, _ = raw("GET", "/api/me", token=tok)
    assert st == 200 and me["email"] == who
    assert raw("GET", "/api/folders", token=tok)[0] == 200
    assert raw("GET", "/api/me", token="not-a-token")[0] == 401
    # the browser sign-in is unchanged (cookie, no token)
    st, r, h = raw("POST", "/api/login", {"email": who, "password": pw})
    assert st == 200 and "token" not in r and "zm_sid=" in h.get("Set-Cookie", "")

    # with 2-step verification on, the app finishes sign-in with the code and gets its token then
    c, _, _ = login(base, who, pw)
    secret = c.call("POST", "/api/account/2fa/start", {"password": pw})[1]["secret"]
    assert c.call("POST", "/api/account/2fa/enable", {"code": totp.now_code(secret)})[0] == 200
    st, r, h = raw("POST", "/api/login", {"email": who, "password": pw, "client": "app"})
    assert st == 200 and r["twofa_required"] and "token" not in r
    st, r, h = raw("POST", "/api/login/2fa", {"ticket": r["ticket"], "code": totp.now_code(secret, time.time() + 30)})
    assert st == 200 and r["token"] and not h.get("Set-Cookie")
    tok = r["token"]
    assert raw("GET", "/api/me", token=tok)[0] == 200

    # sign out ends the token
    assert raw("POST", "/api/logout", {}, token=tok)[0] == 200
    assert raw("GET", "/api/me", token=tok)[0] == 401
    admin.call("POST", "/api/admin/accounts/delete", {"email": who})


def test_managed_plan_suspension_locks_webmail_and_mail_apps(admin, bundled, portal):
    base, app, conf = bundled
    lic = app.license
    lid = lic.info["lid"]
    users = lambda: open(os.path.join(conf, "dovecot/users")).read()
    who, pw = ADMIN

    def zocc(**billing):        # what ZOcc puts in the next activation certificate
        portal.billing[lid] = billing
        lic.refresh()

    c, st, _ = login(base, who, pw)
    assert st == 200
    zocc(plan="managed", paid_until=time.time() - 2 * 86400, status="overdue")
    assert not lic.locked and c.call("GET", "/api/me")[0] == 200                 # grace period: still works
    st, ov, _ = c.call("GET", "/api/admin/license")
    assert ov["billing"]["status"] == "overdue" and ov["billing"]["lock_at"]
    zocc(plan="managed", paid_until=time.time() - 11 * 86400, status="suspended")
    assert lic.locked
    assert c.call("GET", "/api/me")[0] == 401                                    # signed-in users are thrown out
    _, st, r = login(base, who, pw)
    assert st == 423 and "customer portal" in r["error"]                         # nobody can sign in
    assert all("nologin=y" in l and "Service_suspended" in l for l in users().splitlines() if l)
    assert devmail.STORE.authenticate(who, pw)[0] is None                        # IMAP/SMTP refused
    assert f"{who} OK" in open(os.path.join(conf, "postfix/mailboxes")).read()   # incoming mail still accepted
    st, cfg, _ = Client(base).call("GET", "/api/config")
    assert cfg["license"]["suspended"]                                           # login page can explain why
    zocc(plan="managed", paid_until=time.time() + 30 * 86400, status="active")   # unlocked from ZOcc
    assert not lic.locked and "Service_suspended" not in users()
    assert login(base, who, pw)[1] == 200
    zocc()                                                                       # back to a plain community certificate


def test_modified_code_locks_service_and_is_reported(admin, bundled, portal, monkeypatch):
    """Changed program files (e.g. a replaced logo): reported to the licensing portal, every sign-in
    refused while enforced, incoming mail still stored; putting the original file back unlocks."""
    import shutil
    from zoltis import __version__, integrity as I, licensing as L
    base, app, conf = bundled
    who, pw = ADMIN
    seed = os.urandom(32)
    monkeypatch.setitem(L.TRUSTED_KEYS, "rel", L.ed25519_public_key(seed).hex())
    d = tempfile.mkdtemp()
    pkg, web = os.path.join(d, "zoltis"), os.path.join(d, "web")
    ign = shutil.ignore_patterns("__pycache__", "*.pyc", I.MANIFEST_NAME)
    shutil.copytree(os.path.join(ROOT, "zoltis"), pkg, ignore=ign)
    shutil.copytree(os.path.join(ROOT, "web"), web, ignore=ign)
    open(os.path.join(pkg, I.MANIFEST_NAME), "w").write(I.sign_manifest(I.compute(pkg, web), __version__, seed, "rel"))
    mon = app.integrity
    monkeypatch.setattr(mon, "pkg_dir", pkg)
    monkeypatch.setattr(mon, "web_dir", web)
    monkeypatch.setenv("ZOLTIS_INTEGRITY_ENFORCE", "auto")      # signed build -> enforced
    users = lambda: open(os.path.join(conf, "dovecot/users")).read()

    assert mon.check()["status"] == "ok" and mon.enforced and not app.license.locked
    c, st, _ = login(base, who, pw)
    assert st == 200
    assert c.call("GET", "/api/admin/license")[1]["integrity"]["status"] == "ok"

    logo = os.path.join(web, "img/logo.svg")
    original = open(logo).read()
    open(logo, "w").write(original.replace("#0e1b33", "#ff0000"))   # someone swaps the logo colours
    portal.calls.clear()
    mon.check()
    assert app.license.locked and app.license.state() == "modified"
    for _ in range(50):                                              # reported to the portal right away
        if portal.calls:
            break
        time.sleep(0.05)
    path, body = portal.calls[-1]
    assert path == "/v1/activate" and body["integrity"]["status"] == "modified"
    assert body["integrity"]["files"] == ["web/img/logo.svg"] and body["license_id"] == app.license.info["lid"]
    assert c.call("GET", "/api/me")[0] == 401                        # signed-in users thrown out
    _, st, r = login(base, who, pw)
    assert st == 423 and "program files were changed" in r["error"]
    assert all("nologin=y" in l for l in users().splitlines() if l)  # IMAP/SMTP refused
    assert f"{who} OK" in open(os.path.join(conf, "postfix/mailboxes")).read()
    assert Client(base).call("GET", "/api/config")[1]["license"]["suspended"]

    open(logo, "w").write(original)                                  # official file restored
    mon.check()
    assert not app.license.locked and login(base, who, pw)[1] == 200

    monkeypatch.setenv("ZOLTIS_INTEGRITY_ENFORCE", "false")         # detection only: reported, not locked
    open(logo, "w").write("changed")
    assert mon.check()["status"] == "modified" and not app.license.locked
    monkeypatch.undo()
    mon.check()
    shutil.rmtree(d)
    assert not app.license.locked


def test_new_policy_version_must_be_accepted_before_more_accounts(admin, bundled, monkeypatch):
    """Section 8: when the policies change, the admin accepts the new version before creating accounts or domains."""
    app = bundled[1]
    admin, st, _ = login(bundled[0], *ADMIN)      # earlier tests may have signed everyone out
    assert st == 200
    monkeypatch.setattr(app.accounts, "policy_version", "1.1")
    st, r, _ = admin.call("GET", "/api/admin/overview")
    assert st == 200, r
    assert r["policies"]["required"] and not r["policies"]["accepted"]
    st, r, _ = admin.call("POST", "/api/admin/accounts", {"email": "pol@acme.test", "password": "Pol-pass-123"})
    assert st == 428 and "policies" in r["error"]
    assert admin.call("POST", "/api/admin/domains", {"name": "pol.test"})[0] == 428
    assert admin.call("POST", "/api/admin/policies/accept", {"version": "1.0"})[0] == 400      # old version
    st, r, _ = admin.call("POST", "/api/admin/policies/accept", {"version": "1.1"})
    assert st == 200 and r["accepted"] and r["accepted_by"] == ADMIN[0]
    st, r, _ = admin.call("POST", "/api/admin/accounts", {"email": "pol@acme.test", "password": "Pol-pass-123"})
    assert st in (200, 402), r                                              # no longer blocked by the policies
    if st == 200:
        admin.call("POST", "/api/admin/accounts/delete", {"email": "pol@acme.test", "purge": True})
    assert any(e["action"] == "policies.accept" for e in admin.call("GET", "/api/admin/audit")[1]["events"])


def test_server_time_zone_from_setup_and_admin(bundled):
    """The sign-in page shows "Server time" in the zone taken from the admin's browser at setup."""
    base, app, _ = bundled
    st, cfg, _ = Client(base).call("GET", "/api/config")
    t = cfg["server_time"]
    assert t["timezone"] == "Asia/Dubai" and t["configured"] and abs(t["now"] - time.time()) < 5
    c, st, _ = login(base, *ADMIN)
    assert st == 200
    assert c.call("POST", "/api/admin/timezone", {"timezone": "Not/A Zone"})[0] == 400
    assert c.call("POST", "/api/admin/timezone", {"timezone": "../etc/passwd"})[0] == 400
    st, r, _ = c.call("POST", "/api/admin/timezone", {"timezone": "Europe/London"})
    assert st == 200 and r["timezone"] == "Europe/London"
    assert Client(base).call("GET", "/api/config")[1]["server_time"]["timezone"] == "Europe/London"
    assert c.call("GET", "/api/admin/overview")[1]["server_time"]["timezone"] == "Europe/London"
    c.call("POST", "/api/admin/timezone", {"timezone": "Asia/Dubai"})
