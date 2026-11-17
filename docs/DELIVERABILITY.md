# Making sure your mail doesn't land in spam

Gmail, Outlook and Yahoo decide whether to trust a message by looking at **who sent it, from which server,
and whether the domain vouches for that server**. The webmail can't override that; your DNS and mail server
decide it. Work through this list once per domain. **Admin console → Domains & DNS → Check DNS** (or `docker compose exec web zoltis doctor example.com`) checks most of it automatically,
and shows the exact records Zoltis Mail generated for your domain.

## 1. SPF: which servers may send for your domain
Publish **one** TXT record on the domain:
```
example.com.  TXT  "v=spf1 mx ip4:203.0.113.10 -all"
```
List every service that sends as your domain (your server, a newsletter tool, the CRM) using `include:`.
Keep it under 10 DNS lookups. Never use `+all`.

## 2. DKIM: cryptographically sign every message
Zoltis Mail creates a 2048-bit DKIM key for every domain you add and signs all outgoing mail with OpenDKIM.
You only need to publish the `zoltis._domainkey` TXT record shown in the admin console. (If your DNS provider
limits TXT values to 255 characters, paste it as several quoted strings; most providers do this automatically.)

Publish the public key:
```
default._domainkey.example.com.  TXT  "v=DKIM1; k=rsa; p=MIIBIjANBgkq..."
```
Use 2048-bit keys. Run `zoltis doctor example.com --dkim-selector default` to verify.

## 3. DMARC: tell receivers what to do when SPF/DKIM fail
```
_dmarc.example.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.com; fo=1"
```
Start with `p=none` and read the reports for 2–4 weeks. Then move to `p=quarantine`, and finally `p=reject`.
Gmail and Yahoo **require** DMARC for bulk senders.

## 4. Reverse DNS (PTR)
The sending IP must have a PTR record that matches the server's hostname, and that hostname must resolve back to the same IP:
```
203.0.113.10  ->  mail.example.com  ->  203.0.113.10
```
Set the PTR record in your hosting provider's panel (Hetzner, OVH, AWS Elastic IP and others support this).
Postfix's `myhostname` (the HELO name) should also be `mail.example.com`.

## 5. IP reputation
- Check that the IP isn't on a blocklist (the doctor checks Spamhaus, SpamCop and Barracuda).
- Avoid residential IP ranges and port-25-blocked cloud IPs. Many cheap VPS ranges start with poor reputation.
- Never run an **open relay**. Require SMTP AUTH on port 587.
- Warm up new IPs: send low volumes for the first weeks.
- Register with **Google Postmaster Tools** and **Microsoft SNDS** to monitor your reputation.

## 6. TLS everywhere
Use valid certificates on SMTP (STARTTLS on 25/587, or 465). Optionally add **MTA-STS** and **TLS-RPT**.

## 7. Content and behaviour
Zoltis Mail already produces clean MIME: a text+HTML alternative, a Message-ID on your own domain, and correct Date and threading headers.
Users can still hurt deliverability by:
- sending mass mail from a personal mailbox (use a proper newsletter tool with List-Unsubscribe)
- using URL shorteners or many links, or image-only messages
- sending to bought lists, which causes bounces and spam complaints

## 8. Inbound spam (protecting your users)
Run **Rspamd** (recommended) or SpamAssassin on the mail server. Messages it flags go to the Junk folder,
which Zoltis Mail shows as **Spam**. When users click *Report spam*, the message moves to Junk. If you enable
Rspamd's IMAP learning (e.g. via Dovecot `imap_sieve`), each report also trains the filter.
