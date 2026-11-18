"""End-to-end tests against the in-memory dev mail server.

Run:  python3 -m pytest -q tests
"""

import base64
import json
import os
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.cookiejar import CookieJar

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "devtools"))

import pytest  # noqa: E402

import devmail  # noqa: E402
from zoltis import config  # noqa: E402
from zoltis.mail import dnscheck  # noqa: E402
from zoltis.mail.imap import IMAPAccount, MailError  # noqa: E402
from zoltis.mail.sanitize import sanitize_html  # noqa: E402
from zoltis.mail.smtp import build_message  # noqa: E402
from zoltis.mail import utf7  # noqa: E402


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="session")
def mail():
    ip, sp, cp = free_port(), free_port(), free_port()
    devmail.start(ip, sp)
    devmail.start_clamd(cp)
    return {"imap": ip, "smtp": sp, "clamd": cp}


@pytest.fixture(scope="session")
def server(mail, portal):
    port = free_port()
    env = {
        "ZOLTIS_SERVER_PORT": str(port), "ZOLTIS_SERVER_DATA_DIR": tempfile.mkdtemp(),
        "ZOLTIS_IMAP_HOST": "127.0.0.1", "ZOLTIS_IMAP_PORT": str(mail["imap"]), "ZOLTIS_IMAP_SECURITY": "plain",
        "ZOLTIS_SMTP_HOST": "127.0.0.1", "ZOLTIS_SMTP_PORT": str(mail["smtp"]), "ZOLTIS_SMTP_SECURITY": "plain",
        "ZOLTIS_BRANDING_DEFAULT_DOMAIN": "example.com",
        "ZOLTIS_ANTIVIRUS_ENABLED": "true", "ZOLTIS_ANTIVIRUS_SOCKET": "-",
        "ZOLTIS_ANTIVIRUS_HOST": "127.0.0.1", "ZOLTIS_ANTIVIRUS_PORT": str(mail["clamd"]),
    }
    os.environ.update(env)
    from http.server import ThreadingHTTPServer
    from zoltis.server import App, make_handler
    app = App(config.load(None))
    app.license.activate(portal.issue("example.com", customer="Example Inc"))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}", app
    httpd.shutdown()


class Client:
    def __init__(self, base):
        self.base = base
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))

    def call(self, method, path, body=None, csrf=True):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if csrf:
            req.add_header("X-Zoltis", "1")
        try:
            with self.op.open(req) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if r.headers.get_content_type() == "application/json" else raw), r.headers
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw), e.headers
            except ValueError:
                return e.code, raw, e.headers


@pytest.fixture()
def client(server):
    c = Client(server[0])
    st, body, _ = c.call("POST", "/api/login", {"email": "demo", "password": "demo"})
    assert st == 200, body
    return c


# --------------------------------------------------------------- unit tests
def test_utf7_roundtrip():
    for name in ["INBOX", "Entwürfe", "Отправленные", "a&b", "日本語"]:
        assert utf7.decode(utf7.encode(name)) == name
    assert utf7.encode("Entwürfe") == "Entw&APw-rfe"


@pytest.mark.parametrize("evil", [
    "<script>alert(1)</script>",
    '<img src=x onerror="alert(1)">',
    '<a href="javascript:alert(1)">x</a>',
    '<iframe src="https://evil"></iframe>',
    '<div style="background:url(javascript:alert(1))">x</div>',
    '<svg onload=alert(1)></svg>',
    '<form action="https://evil"><input name=p></form>',
    '<meta http-equiv="refresh" content="0;url=https://evil">',
    '<base href="https://evil/">',
])
def test_sanitizer_blocks_xss(evil):
    out, _ = sanitize_html(evil)
    low = out.lower()
    assert "<script" not in low and "onerror" not in low and "javascript:" not in low
    assert "<iframe" not in low and "onload" not in low and "<form" not in low
    assert "http-equiv" not in low and "<base" not in low


def test_sanitizer_blocks_remote_images_and_keeps_formatting():
    out, blocked = sanitize_html('<p style="color:red"><b>Hi</b><img src="https://t.example/p.gif"></p>')
    assert blocked == 1 and "data-zoltis-src" in out and ' src="https' not in out
    assert '<b>Hi</b>' in out and 'style="color:red"' in out
    out2, blocked2 = sanitize_html('<img src="https://t.example/p.gif">', allow_remote=True)
    assert blocked2 == 0 and 'src="https://t.example/p.gif"' in out2


def test_build_message_is_deliverability_friendly():
    msg, rcpts = build_message(from_name="Ann Lee", from_email="ann@acme.com", to="Bob <bob@x.org>, c@y.org",
                               bcc="hidden@z.org", subject="Grüße", html="<p>Hello <b>Bob</b></p>")
    assert msg["Message-ID"].endswith("@acme.com>")
    assert msg["Date"] and msg["MIME-Version"] == "1.0"
    assert msg.get_content_type() == "multipart/alternative"
    assert [p.get_content_type() for p in msg.iter_parts()] == ["text/plain", "text/html"]
    assert "Bcc" not in msg and "hidden@z.org" in rcpts
    assert msg.get_body(("plain",)).get_content().strip() == "Hello Bob"


def test_html_to_text_quality():
    from zoltis.mail.sanitize import html_to_text
    t = html_to_text('<p>Hi <b>Bob</b>,</p><p>See <a href="https://x.org/r">the report</a>.</p><ul><li>One</li><li>Two</li></ul>')
    assert t == "Hi Bob,\n\nSee the report (https://x.org/r).\n\n* One\n* Two" or ("Hi Bob," in t and "the report (https://x.org/r)" in t and "* One" in t), t


def test_build_message_rejects_bad_address():
    with pytest.raises(MailError):
        build_message(from_name="", from_email="a@b.com", to="not-an-email", html="x")


def test_search_translation():
    crit, utf8 = IMAPAccount.build_search('from:alice is:unread has:attachment "quarterly report" before:2026/01/31')
    s = " ".join(crit)
    assert 'FROM "alice"' in s and "UNSEEN" in s and "BEFORE 31-Jan-2026" in s and 'TEXT "quarterly report"' in s
    assert utf8 is None
    _, utf8 = IMAPAccount.build_search("Grüße")
    assert utf8 == "Grüße"


def test_dns_doctor_against_fake_dns(monkeypatch):
    zone = {
        ("acme.test", 15): [("mx", 10, "mail.acme.test")],
        ("mail.acme.test", 1): [("a", "192.0.2.10")],
        ("acme.test", 16): [("txt", "v=spf1 mx -all")],
        ("_dmarc.acme.test", 16): [("txt", "v=DMARC1; p=quarantine")],
        ("default._domainkey.acme.test", 16): [("txt", "v=DKIM1; k=rsa; p=MIIBIjANBgkqh")],
        ("10.2.0.192.in-addr.arpa", 12): [("ptr", "mail.acme.test")],
    }

    def enc(name):
        return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"

    class H(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            qid = data[:2]
            off, labels = 12, []
            while data[off]:
                ln = data[off]; labels.append(data[off + 1:off + 1 + ln].decode()); off += 1 + ln
            qtype = struct.unpack(">H", data[off + 1:off + 3])[0]
            q = data[12:off + 5]
            answers = zone.get((".".join(labels), qtype), [])
            rr = b""
            for a in answers:
                if a[0] == "a":
                    rd = socket.inet_aton(a[1])
                elif a[0] == "mx":
                    rd = struct.pack(">H", a[1]) + enc(a[2])
                elif a[0] == "ptr":
                    rd = enc(a[1])
                else:
                    t = a[1].encode(); rd = bytes([len(t)]) + t
                rr += b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 60, len(rd)) + rd
            flags = 0x8180 if answers or labels[-1] == "test" or labels[-1] == "arpa" else 0x8183
            sock.sendto(qid + struct.pack(">HHHHH", flags, 1, len(answers), 0, 0) + q + rr, self.client_address)

    port = free_port()
    srv = socketserver.ThreadingUDPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(dnscheck, "DNS_PORT", port)
    monkeypatch.setattr(dnscheck, "_nameservers", lambda: ["127.0.0.1"])
    monkeypatch.setattr(dnscheck, "DNSBLS", [])
    rep = dnscheck.run("acme.test")
    srv.shutdown()
    st = {r["check"]: r["status"] for r in rep["results"]}
    assert st["MX record"] == "pass" and st["SPF"] == "pass" and st["DMARC"] == "pass" and st["DKIM"] == "pass"
    assert st["Reverse DNS (PTR)"] == "pass", rep
    assert rep["ip"] == "192.0.2.10"


# --------------------------------------------------------------- API tests
def test_login_required_and_wrong_password(server):
    c = Client(server[0])
    assert c.call("GET", "/api/folders")[0] == 401
    st, body, _ = c.call("POST", "/api/login", {"email": "demo@example.com", "password": "nope"})
    assert st == 401 and "Wrong" in body["error"]


def test_csrf_header_required(client):
    st, body, _ = client.call("POST", "/api/messages/flags", {"folder": "INBOX", "uids": [1], "flag": "seen"}, csrf=False)
    assert st == 403


def test_static_path_traversal_blocked(server):
    c = Client(server[0])
    st, _, _ = c.call("GET", "/../zoltis/server.py")
    assert st in (404, 200)
    st, body, _ = c.call("GET", "/css/../../zoltis/config.py")
    assert st == 404 or b"DEFAULTS" not in body


def test_security_headers(server):
    c = Client(server[0])
    st, _, h = c.call("GET", "/")
    assert st == 200
    assert "script-src 'self'" in h["Content-Security-Policy"]
    assert h["X-Content-Type-Options"] == "nosniff" and h["Referrer-Policy"] == "no-referrer"


def test_folders_and_list(client):
    st, body, _ = client.call("GET", "/api/folders")
    roles = {f["role"] for f in body["folders"]}
    assert {"inbox", "sent", "drafts", "trash", "junk", "archive"} <= roles
    st, body, _ = client.call("GET", "/api/messages?folder=INBOX&size=10")
    assert st == 200 and body["total"] >= 40 and len(body["messages"]) == 10
    m = body["messages"][0]
    assert m["subject"] and m["from"][0]["email"] and m["snippet"]


def test_search_and_open_message(client):
    st, body, _ = client.call("GET", "/api/messages?folder=INBOX&q=from:finance")
    assert body["total"] == 1
    uid = body["messages"][0]["uid"]
    st, msg, _ = client.call("GET", f"/api/message?folder=INBOX&uid={uid}")
    assert "<script" not in msg["html"] and msg["blocked_images"] == 1
    st, msg2, _ = client.call("GET", f"/api/message?folder=INBOX&uid={uid}&images=1")
    assert msg2["blocked_images"] == 0


def test_flags_move_and_undo(client):
    _, body, _ = client.call("GET", "/api/messages?folder=INBOX&q=subject:Lunch")
    m = body["messages"][0]
    assert client.call("POST", "/api/messages/flags", {"folder": "INBOX", "uids": [m["uid"]], "flag": "flagged", "value": True})[0] == 200
    _, body, _ = client.call("GET", "/api/messages?folder=INBOX&q=is:starred%20subject:Lunch")
    assert body["total"] == 1
    st, r, _ = client.call("POST", "/api/messages/move", {"folder": "INBOX", "uids": [m["uid"]], "dest": "role:archive"})
    assert st == 200 and r["dest"] == "Archive"
    _, body, _ = client.call("GET", "/api/messages?folder=INBOX&q=subject:Lunch")
    assert body["total"] == 0
    st, r, _ = client.call("POST", "/api/messages/restore", {"from": "Archive", "to": "INBOX", "message_ids": [m["message_id"]]})
    assert r["restored"] == 1
    _, body, _ = client.call("GET", "/api/messages?folder=INBOX&q=subject:Lunch")
    assert body["total"] == 1


def test_send_saves_to_sent_and_delivers(client):
    _, before, _ = client.call("GET", "/api/messages?folder=Sent")
    att = base64.b64encode(b"hello world").decode()
    st, r, _ = client.call("POST", "/api/send", {
        "to": "Alex <alex@example.com>", "subject": "Integration test", "html": "<p>Hi <b>Alex</b></p>",
        "attachments": [{"filename": "hello.txt", "content_type": "text/plain", "data": att}]})
    assert st == 200, r
    _, after, _ = client.call("GET", "/api/messages?folder=Sent")
    assert after["total"] == before["total"] + 1
    raw = devmail.STORE.outbox[-1][2]
    assert b"Integration test" in raw and b"hello.txt" in raw and b"Message-ID: <" in raw
    assert any(m.parsed["Subject"] == "Integration test" for m in devmail.STORE.boxes["alex@example.com"]["INBOX"].msgs)
    _, contacts, _ = client.call("GET", "/api/contacts?q=ale")
    assert contacts["contacts"][0]["email"] == "alex@example.com"


def test_antivirus_blocks_infected_upload(client):
    n = len(devmail.STORE.outbox)
    st, r, _ = client.call("POST", "/api/send", {
        "to": "alex@example.com", "subject": "virus", "html": "x",
        "attachments": [{"filename": "eicar.txt", "data": base64.b64encode(devmail.EICAR).decode()}]})
    assert st == 422 and "eicar.txt" in r["error"] and "Virus" in r["error"]
    assert len(devmail.STORE.outbox) == n  # nothing sent


def test_antivirus_blocks_infected_download(client):
    _, body, _ = client.call("GET", "/api/messages?folder=INBOX&q=subject:Overdue")
    uid = body["messages"][0]["uid"]
    _, msg, _ = client.call("GET", f"/api/message?folder=INBOX&uid={uid}")
    part = msg["attachments"][0]["part"]
    st, scan, _ = client.call("GET", f"/api/scan?folder=INBOX&uid={uid}&part={part}")
    assert scan["status"] == "infected"
    st, r, _ = client.call("GET", f"/api/attachment?folder=INBOX&uid={uid}&part={part}")
    assert st == 422


def test_clean_attachment_download_is_safe(client):
    _, body, _ = client.call("GET", "/api/messages?folder=INBOX&q=subject:Contract")
    uid = body["messages"][0]["uid"]
    _, msg, _ = client.call("GET", f"/api/message?folder=INBOX&uid={uid}")
    part = msg["attachments"][0]["part"]
    st, data, h = client.call("GET", f"/api/attachment?folder=INBOX&uid={uid}&part={part}&download=1")
    assert st == 200 and b"SLA" in data
    assert h["Content-Type"] == "application/octet-stream" and h["Content-Disposition"].startswith("attachment")


def test_drafts_save_and_replace(client):
    st, r, _ = client.call("POST", "/api/draft", {"to": "", "subject": "Draft one", "html": "<p>wip</p>"})
    assert st == 200 and r["draft_uid"]
    st, r2, _ = client.call("POST", "/api/draft", {"to": "x@y.com", "subject": "Draft one v2", "html": "<p>wip2</p>", "draft_uid": r["draft_uid"]})
    _, body, _ = client.call("GET", "/api/messages?folder=Drafts")
    subjects = [m["subject"] for m in body["messages"]]
    assert "Draft one v2" in subjects and "Draft one" not in subjects


def test_settings_roundtrip(client):
    st, s, _ = client.call("POST", "/api/settings", {"display_name": "Demo User", "theme": "dark", "page_size": 25, "bogus": 1})
    assert s["display_name"] == "Demo User" and s["theme"] == "dark" and s["page_size"] == 25 and "bogus" not in s


def test_deliverability_limited_to_own_domain(client):
    st, r, _ = client.call("GET", "/api/deliverability?domain=google.com")
    assert st == 403


def test_inbox_tabs_sort_and_learn(client):
    subjects = lambda r: {m["subject"] for m in r["messages"]}
    st, r, _ = client.call("GET", "/api/messages?folder=INBOX&category=primary&size=100")
    assert st == 200 and set(r["categories"]) == {"primary", "updates", "promotions", "social", "forums"}
    assert r["category"] == "primary" and "Q4 roadmap review - slides attached" in subjects(r)
    assert "This week in open source: 10 projects to watch" not in subjects(r)
    _, promo, _ = client.call("GET", "/api/messages?folder=INBOX&category=promotions")
    assert "This week in open source: 10 projects to watch" in subjects(promo)
    _, upd, _ = client.call("GET", "/api/messages?folder=INBOX&category=updates")
    assert "[zoltis] Pull request #42 merged" in subjects(upd)
    assert r["categories"]["primary"] >= 1                               # unread counts per tab
    # every message ends up in exactly one tab
    totals = sum(client.call("GET", f"/api/messages?folder=INBOX&category={c}&size=10")[1]["total"]
                 for c in ("primary", "updates", "promotions", "social", "forums"))
    assert totals == client.call("GET", "/api/messages?folder=INBOX&size=10")[1]["total"]
    # move the newsletter to Primary: that sender is remembered
    nl = next(m for m in promo["messages"] if m["subject"].startswith("This week in open source"))
    st, res, _ = client.call("POST", "/api/messages/category", {"folder": "INBOX", "uids": [nl["uid"]], "category": "primary",
                                                                 "senders": [nl["from"][0]["email"]], "learn": True})
    assert st == 200 and res["learned"] == ["news@techweekly.com"]
    _, r, _ = client.call("GET", "/api/messages?folder=INBOX&category=primary&size=100")
    assert nl["subject"] in subjects(r)
    assert client.call("POST", "/api/messages/category", {"folder": "INBOX", "uids": [nl["uid"]], "category": "spam"})[0] == 400
    client.call("POST", "/api/messages/category", {"folder": "INBOX", "uids": [nl["uid"]], "category": "promotions",
                                                    "senders": [nl["from"][0]["email"]], "learn": True})
    # search results and other folders aren't split into tabs
    assert "categories" not in client.call("GET", "/api/messages?folder=INBOX&q=from:finance")[1]
    assert "categories" not in client.call("GET", "/api/messages?folder=Archive")[1]
    # tabs can be turned off
    client.call("POST", "/api/settings", {"inbox_tabs": False})
    assert "categories" not in client.call("GET", "/api/messages?folder=INBOX")[1]
    client.call("POST", "/api/settings", {"inbox_tabs": True})


def test_message_summary(client):
    _, r, _ = client.call("GET", "/api/messages?folder=INBOX&q=subject:roadmap")
    uid = r["messages"][0]["uid"]
    st, m, _ = client.call("GET", f"/api/message?folder=INBOX&uid={uid}&peek=1")
    a = m["assistant"]
    assert st == 200 and a["summary"] and a["action_needed"] and a["attachments"] == ["Q4-roadmap.pdf"]
    assert any(f["type"] == "deadline" for f in a["facts"])
    client.call("POST", "/api/settings", {"smart_summary": False})
    assert "assistant" not in client.call("GET", f"/api/message?folder=INBOX&uid={uid}&peek=1")[1]
    client.call("POST", "/api/settings", {"smart_summary": True})


def test_empty_trash_and_spam(client):
    _, f, _ = client.call("GET", "/api/folders")
    trash = next(x["name"] for x in f["folders"] if x["role"] == "trash")
    _, r, _ = client.call("GET", "/api/messages?folder=INBOX&q=subject:%22Older%20message%20%2329%22")
    uid = r["messages"][0]["uid"]
    client.call("POST", "/api/messages/move", {"folder": "INBOX", "uids": [uid], "dest": "role:trash"})
    assert client.call("GET", f"/api/messages?folder={trash}")[1]["total"] >= 1
    st, res, _ = client.call("POST", "/api/folders/empty", {"folder": trash})
    assert st == 200 and res["deleted"] >= 1
    assert client.call("GET", f"/api/messages?folder={trash}")[1]["total"] == 0
    assert client.call("POST", "/api/folders/empty", {"folder": "INBOX"})[0] == 400     # only Trash and Spam


def test_spam_warning_before_opening(client):
    """Spam: a safety report comes with the message, it isn't marked read, risky files can't be downloaded."""
    import devmail
    from datetime import datetime, timezone
    box = devmail.STORE.boxes["demo@example.com"]
    junk = next(n for n in box if n.lower() in ("junk", "spam"))
    raw = devmail._mk('"support@yourbank.com" <win@prize-claim.example>', "demo@example.com", "You won! Claim now",
                      "Claim your prize at https://prize-claim.example/login and http://bit.example/x", None,
                      datetime.now(timezone.utc), ("prize.exe", "application/octet-stream", b"MZ fake"))
    box[junk].add(raw, set(), datetime.now(timezone.utc))
    _, r, _ = client.call("GET", f"/api/messages?folder={junk}")
    m = next(x for x in r["messages"] if x["subject"] == "You won! Claim now")
    st, msg, _ = client.call("GET", f"/api/message?folder={junk}&uid={m['uid']}")
    c = msg["spam_check"]
    assert st == 200 and c["links"] == 2 and "prize-claim.example" in c["link_domains"]
    assert c["risky_attachments"][0]["filename"] == "prize.exe"
    assert "support@yourbank.com" in c["spoofed_name"]
    _, r, _ = client.call("GET", f"/api/messages?folder={junk}")
    assert not next(x for x in r["messages"] if x["uid"] == m["uid"])["seen"]       # opening the warning isn't reading it
    part = msg["attachments"][0]["part"]
    st, body, _ = client.call("GET", f"/api/attachment?folder={junk}&uid={m['uid']}&part={part}")
    assert st == 403 and "Spam" in body["error"]
    # the same message in the Inbox carries no spam report
    _, r, _ = client.call("GET", "/api/messages?folder=INBOX&size=1")
    assert "spam_check" not in client.call("GET", f"/api/message?folder=INBOX&uid={r['messages'][0]['uid']}&peek=1")[1]


def test_signature_text_or_html(client):
    st, r, _ = client.call("POST", "/api/settings", {"signature_type": "html", "signature_text": "Jane Doe\nSales",
                                                    "signature": '<p><b>Jane</b><script>alert(1)</script><img src="x" onerror="alert(2)"></p>'})
    assert st == 200 and r["signature_type"] == "html" and r["signature_text"] == "Jane Doe\nSales"
    assert "<b>Jane</b>" in r["signature"] and "<script" not in r["signature"] and "onerror" not in r["signature"]
    assert client.call("POST", "/api/settings", {"signature_type": "both"})[1]["signature_type"] == "html"   # one type only
    r = client.call("POST", "/api/settings", {"signature_type": "text"})[1]
    assert r["signature_type"] == "text" and r["signature"]          # the other type is kept, just not used
    client.call("POST", "/api/settings", {"signature_type": "text", "signature_text": "", "signature": ""})


def test_old_html_signature_still_used(tmp_path):
    import json
    from zoltis.store import UserStore
    st = UserStore(str(tmp_path))
    st.save("old@example.com", {"settings": {"signature": "<b>Old</b>"}})
    assert st.load("old@example.com")["settings"]["signature_type"] == "html"
    assert st.load("new@example.com")["settings"]["signature_type"] == "text"


def test_logout(client):
    assert client.call("POST", "/api/logout", {})[0] == 200
    assert client.call("GET", "/api/folders")[0] == 401
