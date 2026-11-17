# Architecture

```
 Internet ──▶ caddy (80/443, Let's Encrypt) ──▶ web (Zoltis Mail: webmail + admin console)
          ──▶ postfix (25/465/587) ── LMTP / SASL / quota-status ──▶ dovecot (993)
                                                       ▲                  ▲
 web ── IMAP 143 / master login (private network) ─────┘                  │
 web ── SMTP 10587 (private) ──▶ postfix                                  │
 web ── renders users, maps, DKIM keys ──▶ [mailconf volume] ──▶ postfix + dovecot (watchers reload)
 web ── clamd INSTREAM ──▶ clamav
```

All containers share a private Docker network (`172.28.0.0/24`). The web container has the fixed address
`172.28.0.10`, and only that address may use Dovecot's plaintext port 143 and master login.

**Single source of truth.** `accounts.db` (SQLite) in the web container stores domains, accounts, aliases and the audit log.
After every change `zoltis/mailserver.py` renders plain files into the shared `mailconf` volume:

| File | Read by | Purpose |
|---|---|---|
| `dovecot/users` | Dovecot passwd-file | mailboxes, SHA512-CRYPT passwords, per-user `quota_rule` (≤ 720 MB), `nologin` for disabled accounts |
| `dovecot/master-users` | Dovecot master passdb | internal login used for quota, import and purge (allowed only from 172.28.0.10) |
| `postfix/domains`, `mailboxes`, `aliases` | Postfix virtual maps | what mail the server accepts and where it goes |
| `postfix/senders` | `smtpd_sender_login_maps` | anti-spoofing: who may send as which address |
| `dkim/KeyTable`, `SigningTable`, `keys/*.private` | OpenDKIM | per-domain DKIM signing |
| `serial` | watcher loops | a change triggers `postmap` + `postfix reload` / OpenDKIM restart; Dovecot re-reads passwd-files by itself |

No container needs privileges in another container. The postfix and dovecot entrypoints poll `serial` every 5 seconds and
write `applied.<service>`, which the admin console shows as "Configuration: Applied".

**Limits.** `edition.py` defines Community limits (10 accounts, 720 MB). `accounts.py` enforces them when accounts are
created or edited, and Dovecot enforces the storage quota on delivery (LMTP), on IMAP APPEND, and at SMTP time through
`quota-status`, so mail for a full mailbox is refused with `552 5.2.2 Mailbox is full`.

**Modes.** `ZOLTIS_MAIL_SERVER_MODE=bundled` (Docker default) or `external` (webmail only for an existing IMAP/SMTP server;
the admin console then manages webmail seats, which are still limited to 10).

## IMAP compatibility
- Uses UIDs everywhere, so actions stay correct when other clients change the mailbox at the same time.
- Detects special folders via SPECIAL-USE (`\Sent`, `\Trash`, …), with name heuristics for older servers
  (`Sent Items`, `INBOX.Sent`, `[Gmail]/Sent Mail`, …).
- Uses MOVE and UIDPLUS when the server supports them, and falls back to COPY + `\Deleted` + EXPUNGE otherwise.
- Folder names are encoded as IMAP modified UTF-7, so non-English folder names work.
- Gmail-style search syntax (`from: to: subject: is:unread is:starred has:attachment before: after: older_than:`)
  is translated to IMAP SEARCH.

## Per-domain servers (hosting providers)
`[domain:client.com]` sections in the config route each email domain to its own IMAP/SMTP host.
Setting `host = auto` uses `mail.<domain>`.

## HTTP API
All endpoints are JSON. Every non-GET request must send the header `X-Zoltis: 1`. Authentication uses the
`zm_sid` cookie, or `Authorization: Bearer <session id>` for mobile apps and scripts.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/config` | Branding, edition, feature flags (no auth) |
| POST | `/api/login` `{email,password}` | Sign in (validates against IMAP) |
| POST | `/api/logout` | Sign out |
| GET | `/api/me` | Current user, settings, features |
| GET/POST/DELETE | `/api/folders` | List (with unread counts) / create / delete |
| GET | `/api/messages?folder&page&size&q` | Message list with snippets |
| GET | `/api/message?folder&uid[&images=1][&peek=1]` | Full message (sanitized HTML, attachments) |
| GET | `/api/attachment?folder&uid&part[&download=1]` | Attachment (antivirus-checked) |
| GET | `/api/scan?folder&uid&part` | Antivirus verdict for one attachment |
| GET | `/api/raw?folder&uid` | Original message source |
| POST | `/api/messages/flags` `{folder,uids,flag,value}` | Mark seen/flagged/answered |
| POST | `/api/messages/move` `{folder,uids,dest}` | Move; `dest` may be `role:archive`, `role:trash`, `role:junk` |
| POST | `/api/messages/restore` `{from,to,message_ids}` | Undo a move |
| POST | `/api/messages/delete` `{folder,uids}` | Move to Trash, or delete permanently from Trash/Spam |
| POST | `/api/send` | Send (to, cc, bcc, subject, html, attachments[base64], reply metadata) |
| POST | `/api/draft` | Save or replace a draft (returns `draft_uid`) |
| GET/POST | `/api/settings` | User preferences |
| GET | `/api/contacts?q` | Autocomplete |
| GET | `/api/deliverability[?ip&selector]` | DNS check of the user's own domain |
| GET | `/api/antivirus` | Scanner status |
| POST | `/api/attachments/check` `{files:[{name, data?}]}` | Attachment-policy verdicts (name-only, or deep check with base64 data) |
| GET/POST | `/api/setup` | First-run: create the first admin (needs the setup code) |
| POST | `/api/account/password` | User changes own password (bundled mode) |
| GET | `/api/account/quota` | User's storage usage |
| GET | `/api/admin/overview` | Counts, limits, server/antivirus status (admin only) |
| GET/POST | `/api/admin/accounts`, `/accounts/update`, `/accounts/delete` | Manage accounts |
| GET/POST | `/api/admin/domains`, `/domains/delete`, `/dns-check` | Domains, DKIM, DNS records and checks |
| GET/POST | `/api/admin/aliases`, `/aliases/delete` | Aliases |
| GET/POST | `/api/admin/sessions`, `/sessions/revoke` | Active sessions |
| GET | `/api/admin/audit` | Activity log |
| GET/POST | `/api/admin/import`, `/import/cancel` | Import mail from an old IMAP server |
| GET | `/healthz` | Liveness probe |

## Editions and modules
`zoltis/edition.py` loads the optional `zoltis.enterprise` package. That package is **not included** in
Community builds (`./build.sh` strips it). It is activated only when `enterprise.verify_license()` accepts the
signed key at `[license] key_file`.

The package exposes:

```python
def verify_license(path) -> dict          # {"customer": ..., "seats": ..., "expires": ...}; raise if invalid
def load(license_info) -> list[Module]

class Module:
    name = "calendar"
    features = ["calendar", "caldav"]
    def register(self, router):           # router.add("GET", "/api/calendar/events", handler)
        ...
```

On the front end, a module registers a view with `window.ZoltisModules.calendar = (container, {api, snack, S}) => {...}`.
The sidebar shows an entry for every feature that `/api/me` reports.
