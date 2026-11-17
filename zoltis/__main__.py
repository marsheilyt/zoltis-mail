"""Command line: python3 -m zoltis <command>

  serve       Run the web server (default)
  doctor      Check DNS/deliverability for a domain (SPF, DKIM, DMARC, PTR, blocklists)
  check       Test IMAP/SMTP connectivity with the configured servers
  accounts    list | add | passwd | quota | disable | enable | admin | delete
  domains     list | add | delete | dns
  license     status | activate <KEY> | refresh   (Community Edition license key)
  export      create <FILE|-> | import <FILE|->      move all accounts and mail to another server
  setup-code  Show the first-run setup code
  version     Print version and edition

In Docker:  docker compose exec web zoltis accounts list
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
import time

from . import __version__, config


def main(argv=None):
    ap = argparse.ArgumentParser(prog="zoltis", description="Zoltis Mail webmail")
    ap.add_argument("-c", "--config", help="path to zoltis.ini")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="run the web server")
    d = sub.add_parser("doctor", help="check email deliverability DNS for a domain")
    d.add_argument("domain")
    d.add_argument("--ip", help="public IP your mail server sends from")
    d.add_argument("--dkim-selector", help="your DKIM selector (e.g. 'default' or 'mail')")
    d.add_argument("--json", action="store_true")
    c = sub.add_parser("check", help="test login against the configured IMAP/SMTP servers")
    c.add_argument("email")
    sub.add_parser("version")
    ac = sub.add_parser("accounts", help="manage mail accounts")
    ac.add_argument("action", choices=["list", "add", "passwd", "quota", "disable", "enable", "admin", "delete"])
    ac.add_argument("email", nargs="?")
    ac.add_argument("--name", default="")
    ac.add_argument("--quota-mb", type=int)
    ac.add_argument("--admin", action="store_true")
    dm = sub.add_parser("domains", help="manage mail domains")
    dm.add_argument("action", choices=["list", "add", "delete", "dns"])
    dm.add_argument("domain", nargs="?")
    li = sub.add_parser("license", help="show or activate the license key")
    li.add_argument("action", choices=["status", "activate", "refresh"])
    li.add_argument("key", nargs="?")
    ex = sub.add_parser("export", help="export / import all accounts, settings and mail")
    ex.add_argument("action", choices=["create", "import"])
    ex.add_argument("file", help="path of the .zmexport file, or - for stdout/stdin")
    ex.add_argument("--passphrase-file", help="read the passphrase from this file (else ZOLTIS_EXPORT_PASSPHRASE or a prompt)")
    sub.add_parser("setup-code")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = config.load(args.config)
    cmd = args.cmd or "serve"

    if cmd == "version":
        from .edition import Edition
        print(f"Zoltis Mail {__version__} ({Edition(cfg).name} edition)")
    elif cmd == "doctor":
        from .mail import dnscheck
        rep = dnscheck.run(args.domain, args.ip, args.dkim_selector)
        if args.json:
            print(json.dumps(rep, indent=2))
        else:
            dnscheck.print_report(rep)
        sys.exit(0 if all(r["status"] != "fail" for r in rep["results"]) else 1)
    elif cmd == "check":
        from .server import App
        from .mail.imap import IMAPAccount
        import smtplib, ssl
        app = App(cfg)
        domain = args.email.split("@")[-1]
        pw = getpass.getpass(f"Password for {args.email}: ")
        i = app._server_for("imap", domain)
        print(f"IMAP {i['host']}:{i['port']} ({i['security']}) ... ", end="", flush=True)
        a = IMAPAccount(i["host"], i["port"], i["security"], i["verify_cert"], args.email, pw, i["timeout"])
        a.connect()
        print(f"OK, {len(a.folders(with_counts=False))} folders, caps: {' '.join(sorted(a.caps))[:120]}")
        a.close()
        s = app._server_for("smtp", domain)
        print(f"SMTP {s['host']}:{s['port']} ({s['security']}) ... ", end="", flush=True)
        ctx = ssl.create_default_context()
        if s["security"] == "ssl":
            conn = smtplib.SMTP_SSL(s["host"], s["port"], context=ctx, timeout=s["timeout"])
        else:
            conn = smtplib.SMTP(s["host"], s["port"], timeout=s["timeout"])
            if s["security"] == "starttls":
                conn.starttls(context=ctx)
        if s["auth"]:
            conn.login(args.email, pw)
        conn.quit()
        print("OK")
    elif cmd == "license":
        from .server import App
        from .licensing import LicenseError
        app = App(cfg)
        lic = app.license
        try:
            if args.action == "activate":
                key = args.key or input("Paste your license key: ")
                lic.activate(key)
                print("License activated.")
            elif args.action == "refresh":
                lic.refresh()
                print("License renewed.")
        except (LicenseError, ConnectionError) as e:
            print(f"error: {e}")
            sys.exit(1)
        st = lic.public(full=True)
        fmt = lambda t: time.strftime("%Y-%m-%d", time.localtime(float(t))) if t else "-"
        print(f"State:          {st['state']}")
        if st.get("license_id"):
            print(f"License:        {st['license_id']}  ({st.get('customer') or '-'}, {st.get('email') or '-'})")
            print(f"Domains:        {', '.join(st['domains'])}")
            print(f"Key expires:    {fmt(st.get('expires')) if st.get('expires') else 'never'}")
            print(f"Activated until {fmt(st.get('activated_until'))} (renewed daily while the server runs)")
        if st.get("problem"):
            print(f"Problem:        {st['problem']}")
        if st["state"] == "missing":
            print(f"Register for a free key at {st['register_url']}, then run: zoltis license activate <KEY>")
        print(f"Install ID:     {st['install_id']}")
        sys.exit(0 if st["active"] else 2)
    elif cmd == "export":
        _export_cmd(args, cfg)
    elif cmd in ("accounts", "domains", "setup-code"):
        from .server import App
        from .accounts import AccountError
        app = App(cfg)
        db = app.accounts
        try:
            if cmd == "setup-code":
                print(app.setup_token or "Setup already completed.")
            elif cmd == "domains":
                if args.action == "list":
                    for d in db.domains():
                        print(f"{d['name']:<30} {d['accounts']} account(s)  DKIM: {d.get('dkim_selector') or '-'}")
                elif args.action == "add":
                    db.add_domain(args.domain, actor="cli")
                    sel, pub = app.mailserver.generate_dkim(args.domain.lower())
                    if sel:
                        db.set_dkim(args.domain.lower(), sel, pub)
                    app._apply()
                    print(f"Added {args.domain}. Publish these DNS records:")
                    args.action = "dns"
                if args.action == "dns":
                    print(f"{'Type':<5} {'Name (Cloudflare)':<28} {'Prio':<5} {'Proxy':<9} Content")
                    for r in app.mailserver.dns_records(db.domain(args.domain), app.public_ip or None):
                        where = "" if r["zone"] in (None, args.domain.lower()) else f"   (in zone {r['zone']})"
                        if r["type"] == "PTR":
                            where = "   (set at your hosting provider, not in Cloudflare)"
                        print(f"{r['type']:<5} {r['host']:<28} {r['priority'] or '':<5} {r['proxy'] or '':<9} {r['content']}{where}")
                elif args.action == "delete":
                    db.delete_domain(args.domain, actor="cli")
                    app._apply()
                    print("Deleted.")
            else:
                lim = db.limits
                if args.action == "list":
                    rows = db.accounts()
                    print(f"{len(rows)} of {lim.get('max_accounts') or 'unlimited'} accounts")
                    for a in rows:
                        q = app.mailserver.quota(a["email"]) or {}
                        used = f"{q.get('used_mb', '?')}/{a['quota_mb']} MB"
                        flags = ("admin " if a["is_admin"] else "") + ("" if a["enabled"] else "DISABLED")
                        print(f"{a['email']:<36} {used:<16} {flags}")
                elif args.action == "add":
                    pw = getpass.getpass(f"Password for {args.email}: ") if app.mode == "bundled" else None
                    db.create_account(args.email, pw, args.name, args.quota_mb, args.admin, actor="cli")
                    app._apply()
                    print(f"Created {args.email}")
                elif args.action == "passwd":
                    db.update_account(args.email, actor="cli", password=getpass.getpass("New password: "))
                    app._apply()
                    print("Password changed.")
                elif args.action == "quota":
                    db.update_account(args.email, actor="cli", quota_mb=args.quota_mb)
                    app._apply()
                    print(f"Storage limit set to {args.quota_mb} MB.")
                elif args.action in ("disable", "enable"):
                    db.update_account(args.email, actor="cli", enabled=args.action == "enable")
                    app._apply()
                    print(f"{args.email} {args.action}d.")
                elif args.action == "admin":
                    db.update_account(args.email, actor="cli", is_admin=True)
                    print(f"{args.email} is now an administrator.")
                elif args.action == "delete":
                    if input(f"Type the address to permanently delete {args.email} and its mail: ").strip().lower() != args.email.lower():
                        print("Cancelled.")
                        return
                    if app.mode == "bundled":
                        try:
                            app.mailserver.purge_mailbox(args.email)
                        except Exception as e:  # noqa: BLE001
                            print(f"warning: mailbox content not removed: {e}")
                    db.delete_account(args.email, actor="cli")
                    app._apply()
                    print("Deleted.")
        except AccountError as e:
            print(f"error: {e}")
            sys.exit(1)
    else:
        from .server import serve
        serve(cfg)


def _export_cmd(args, cfg):
    import threading
    from . import migration
    from .server import App
    err = sys.stderr                 # stdout may carry the export itself
    if args.passphrase_file:
        with open(args.passphrase_file) as f:
            pw = f.read().strip()
    else:
        pw = os.environ.get("ZOLTIS_EXPORT_PASSPHRASE") or ""
        if not pw:
            if not sys.stdin.isatty() and args.file == "-" and args.action == "import":
                print("error: give the passphrase with --passphrase-file or ZOLTIS_EXPORT_PASSPHRASE", file=err)
                sys.exit(1)
            pw = getpass.getpass("Export passphrase: ")
            if args.action == "create" and getpass.getpass("Repeat passphrase: ") != pw:
                print("error: passphrases don't match", file=err)
                sys.exit(1)
    app = App(cfg)
    job = migration.MigrationJob(args.action if args.action == "import" else "export", args.file)
    fn = migration.export_all if args.action == "create" else migration.import_all
    stream = (sys.stdout.buffer if args.action == "create" else sys.stdin.buffer) if args.file == "-" else None
    done = threading.Event()

    def run():
        try:
            if args.action == "create":
                fn(app, args.file, pw, job, out_stream=stream)
            else:
                fn(app, args.file, pw, job, in_stream=stream)
        except migration.MigrationError as e:
            job.state, job.error = "failed", str(e)
        finally:
            done.set()
    threading.Thread(target=run, daemon=True).start()
    try:
        while not done.wait(2):
            print(f"\r{job.kind}: {job.current[:40]:<40} {job.messages}/{job.total or '?'} messages", end="", file=err, flush=True)
    except KeyboardInterrupt:
        job.cancel.set()
        done.wait(30)
    print(file=err)
    for w in job.warnings:
        print(f"warning: {w}", file=err)
    if job.state != "done":
        print(f"error: {job.kind} {job.state}: {job.error}", file=err)
        sys.exit(1)
    print(f"{job.kind} done: {job.accounts} accounts, {job.messages} messages"
          + (f", {job.skipped} already there" if job.skipped else "")
          + (f", {job.failed} failed" if job.failed else ""), file=err)


if __name__ == "__main__":
    main()
