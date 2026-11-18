"""Deliverability "doctor": checks the DNS records that decide whether mail
from your domain lands in the inbox or in spam.

Pure standard library: includes a tiny DNS client (UDP, falls back to TCP).
"""

from __future__ import annotations

import ipaddress
import random
import socket
import struct

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
COMMON_DKIM_SELECTORS = ["default", "mail", "dkim", "s1", "s2", "selector1", "selector2",
                         "google", "k1", "smtp", "email", "mx", "zoltis"]
DNS_PORT = 53
DNSBLS = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"]


def _nameservers() -> list[str]:
    ns = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                p = line.split()
                if len(p) >= 2 and p[0] == "nameserver":
                    ns.append(p[1])
    except OSError:
        pass
    return ns or ["1.1.1.1", "8.8.8.8"]


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("idna")
        out += bytes([len(b)]) + b
    return out + b"\0"


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    labels, jumped, end = [], False, off
    for _ in range(128):
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            jumped, off = True, ptr
            continue
        labels.append(data[off + 1:off + 1 + ln].decode(errors="replace"))
        off += 1 + ln
    return ".".join(labels), (end if jumped else off)


class DNSError(OSError):
    pass


class NXDomain(Exception):
    pass


def query(name: str, qtype: str, timeout=4.0) -> list:
    """Return answers ([] when the name or record doesn't exist)."""
    try:
        return _query(name, qtype, timeout)
    except NXDomain:
        return []


def _query(name: str, qtype: str, timeout=4.0) -> list:
    t = TYPES[qtype]
    qid = random.randint(0, 0xFFFF)
    pkt = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _encode_name(name) + struct.pack(">HH", t, 1)
    data = None
    for ns in _nameservers():
        try:
            fam = socket.AF_INET6 if ":" in ns else socket.AF_INET
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(pkt, (ns, DNS_PORT))
                data, _ = s.recvfrom(4096)
            if data[2] & 0x02:  # truncated -> TCP
                with socket.create_connection((ns, DNS_PORT), timeout=timeout) as s:
                    s.sendall(struct.pack(">H", len(pkt)) + pkt)
                    ln = struct.unpack(">H", s.recv(2))[0]
                    data = b""
                    while len(data) < ln:
                        chunk = s.recv(ln - len(data))
                        if not chunk:
                            break
                        data += chunk
            break
        except OSError:
            continue
    if data is None:
        raise OSError("No DNS server reachable")
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    rcode = flags & 0xF
    if rcode == 3:
        raise NXDomain(name)
    if rcode != 0:
        raise DNSError(f"DNS server error for {name} (rcode {rcode})")
    off = 12
    for _ in range(qd):
        _, off = _read_name(data, off)
        off += 4
    out = []
    for _ in range(an):
        _, off = _read_name(data, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rd = data[off:off + rdlen]
        if rtype == t:
            if rtype == 1:
                out.append(socket.inet_ntop(socket.AF_INET, rd))
            elif rtype == 28:
                out.append(socket.inet_ntop(socket.AF_INET6, rd))
            elif rtype in (2, 5, 12):
                out.append(_read_name(data, off)[0])
            elif rtype == 15:
                pref = struct.unpack(">H", rd[:2])[0]
                out.append((pref, _read_name(data, off + 2)[0]))
            elif rtype == 16:
                parts, i = [], 0
                while i < len(rd):
                    ln = rd[i]
                    parts.append(rd[i + 1:i + 1 + ln].decode(errors="replace"))
                    i += 1 + ln
                out.append("".join(parts))
        off += rdlen
    return out


def _check(status, title, detail, fix=""):
    return {"status": status, "check": title, "detail": detail, "fix": fix}


def run(domain: str, sending_ip: str | None = None, dkim_selector: str | None = None) -> dict:
    """Return a report dict: {domain, score, results:[{status, check, detail, fix}]}.

    status is one of: pass, warn, fail.
    """
    domain = domain.strip().lower().rstrip(".")
    res = []

    # Does the domain resolve at all?
    try:
        _query(domain, "NS")
        mx = sorted(query(domain, "MX"))
    except NXDomain:
        return {"domain": domain, "ip": None, "score": 0, "results": [_check(
            "fail", "Domain", f"{domain} was not found in DNS (or this server cannot reach a DNS resolver).",
            "Check the spelling, that the domain is registered, and that /etc/resolv.conf points to a working resolver")]}
    except OSError as e:
        return {"domain": domain, "ip": None, "score": 0, "results": [_check("fail", "DNS", f"DNS lookup failed: {e}")]}
    if mx:
        res.append(_check("pass", "MX record", ", ".join(f"{p} {h}" for p, h in mx)))
    else:
        res.append(_check("fail", "MX record", "No MX record: nobody can send mail to this domain.",
                          f"{domain}. IN MX 10 mail.{domain}."))

    # Determine sending IP: explicit, else A record of the first MX.
    ip = sending_ip
    mx_host = mx[0][1] if mx else f"mail.{domain}"
    if not ip:
        try:
            a = query(mx_host, "A")
            ip = a[0] if a else None
        except OSError:
            ip = None

    # SPF
    txt = query(domain, "TXT")
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if len(spf) > 1:
        res.append(_check("fail", "SPF", "Multiple SPF records found (this is invalid and causes failures).",
                          "Merge them into ONE TXT record starting with v=spf1"))
    elif spf:
        s = spf[0]
        if s.endswith("+all") or " +all" in s:
            res.append(_check("fail", "SPF", s, "Never use +all. End the record with -all or ~all"))
        elif "-all" in s or "~all" in s:
            res.append(_check("pass", "SPF", s))
        else:
            res.append(_check("warn", "SPF", s, "End the record with -all (strict) or ~all (soft)"))
    else:
        rec = f"v=spf1 mx{' ip4:' + ip if ip and ':' not in ip else ''} -all"
        res.append(_check("fail", "SPF", "No SPF record. Receivers can't verify your server may send for this domain.",
                          f'{domain}. IN TXT "{rec}"'))

    # DKIM
    selectors = [dkim_selector] if dkim_selector else COMMON_DKIM_SELECTORS
    found = None
    for sel in selectors:
        try:
            recs = [t for t in query(f"{sel}._domainkey.{domain}", "TXT") if "p=" in t]
        except OSError:
            recs = []
        if recs:
            found = (sel, recs[0])
            break
    if found:
        sel, rec = found
        if "p=;" in rec.replace(" ", "") or rec.replace(" ", "").endswith("p="):
            res.append(_check("fail", "DKIM", f"Selector '{sel}' has an empty (revoked) key."))
        else:
            res.append(_check("pass", "DKIM", f"Selector '{sel}' found ({len(rec)} chars)."))
    else:
        res.append(_check("fail" if dkim_selector else "warn", "DKIM",
                          "No DKIM key found" + (f" for selector '{dkim_selector}'." if dkim_selector else
                                                 " on common selectors (pass --dkim-selector to check yours)."),
                          "Enable DKIM signing on your mail server (OpenDKIM/Rspamd) and publish "
                          f"<selector>._domainkey.{domain} TXT \"v=DKIM1; k=rsa; p=<public key>\""))

    # DMARC
    dm = [t for t in query(f"_dmarc.{domain}", "TXT") if t.lower().startswith("v=dmarc1")]
    if dm:
        pol = dm[0].replace(" ", "").lower()
        if "p=none" in pol:
            res.append(_check("warn", "DMARC", dm[0],
                              "p=none only monitors. Once SPF and DKIM pass, move to p=quarantine, then p=reject"))
        else:
            res.append(_check("pass", "DMARC", dm[0]))
    else:
        res.append(_check("fail", "DMARC", "No DMARC record. Gmail and Yahoo require one for bulk senders.",
                          f'_dmarc.{domain}. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@{domain}; fo=1"'))

    # PTR / reverse DNS
    if ip:
        try:
            rev = ipaddress.ip_address(ip).reverse_pointer
            ptr = query(rev, "PTR")
        except (OSError, ValueError):
            ptr = []
        if not ptr:
            res.append(_check("fail", "Reverse DNS (PTR)", f"{ip} has no PTR record.",
                              f"Ask your hosting provider to set the PTR of {ip} to {mx_host}"))
        else:
            fwd = []
            try:
                fwd = query(ptr[0], "A") + query(ptr[0], "AAAA")
            except OSError:
                pass
            if ip in fwd:
                res.append(_check("pass", "Reverse DNS (PTR)", f"{ip} -> {ptr[0]} -> {ip} (forward-confirmed)"))
            else:
                res.append(_check("warn", "Reverse DNS (PTR)", f"{ip} -> {ptr[0]}, but {ptr[0]} does not resolve back to {ip}",
                                  f"Add an A record {ptr[0]} -> {ip}, or change the PTR to a matching hostname"))

        # Blocklists (IPv4 only)
        if ":" not in ip:
            rev4 = ".".join(reversed(ip.split(".")))
            listed, unknown = [], []
            for bl in DNSBLS:
                try:
                    r = query(f"{rev4}.{bl}", "A")
                    # Spamhaus returns 127.255.255.x when queried via public resolvers (not a listing)
                    real = [x for x in r if x.startswith("127.0.0.")]
                    if real:
                        listed.append(bl)
                    elif r:
                        unknown.append(bl)
                except OSError:
                    unknown.append(bl)
            if listed:
                res.append(_check("fail", "Blocklists", f"{ip} is listed on: {', '.join(listed)}",
                                  "Find and fix the cause (compromised account, open relay), then request delisting"))
            else:
                extra = f" (could not query {', '.join(unknown)} from this resolver)" if unknown else ""
                res.append(_check("pass", "Blocklists", f"{ip} not listed{extra}"))
    else:
        res.append(_check("warn", "Reverse DNS (PTR)", "Could not determine the sending IP. Pass --ip to check it."))

    # MTA-STS / TLS-RPT: make other servers use (and report on) encrypted delivery
    sts = [t for t in query(f"_mta-sts.{domain}", "TXT") if t.lower().startswith("v=stsv1")]
    res.append(_check("pass" if sts else "warn", "MTA-STS", sts[0] if sts else "Not published: senders may fall back to unencrypted delivery.",
                      "" if sts else f"Publish the _mta-sts.{domain} TXT and mta-sts.{domain} CNAME records shown in Domains & DNS"))
    rpt = [t for t in query(f"_smtp._tls.{domain}", "TXT") if t.lower().startswith("v=tlsrptv1")]
    res.append(_check("pass" if rpt else "warn", "TLS reporting", rpt[0] if rpt else "Not published (you won't hear about failed encrypted deliveries).",
                      "" if rpt else f"Publish the _smtp._tls.{domain} TXT record shown in Domains & DNS"))

    weights = {"pass": 1.0, "warn": 0.5, "fail": 0.0}
    score = round(100 * sum(weights[r["status"]] for r in res) / max(1, len(res)))
    return {"domain": domain, "ip": ip, "score": score, "results": res}


def print_report(rep: dict):
    icons = {"pass": "\033[32m✔\033[0m", "warn": "\033[33m!\033[0m", "fail": "\033[31m✘\033[0m"}
    print(f"\nDeliverability report for {rep['domain']}  (sending IP: {rep.get('ip') or 'unknown'})")
    print(f"Score: {rep['score']}/100\n")
    for r in rep["results"]:
        print(f" {icons[r['status']]} {r['check']:<20} {r['detail']}")
        if r.get("fix"):
            print(f"   {'':<20} fix: {r['fix']}")
    print()
