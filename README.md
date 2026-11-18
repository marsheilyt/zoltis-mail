<p align="center"><img src="web/img/logo.svg" width="72" alt=""></p>

# Zoltis Mail – Community Edition

A complete, self-hosted email server with a Gmail-style webmail and an admin console. It runs entirely in Docker
on your own Ubuntu or Linux server.

- **Webmail** that works like Gmail: search, labels, stars, archive and undo, drafts, signatures (plain text or HTML, one at a time), light theme by default (dark mode optional), mobile layout, keyboard shortcuts
- **Mail assistant** (built in, no AI service, nothing leaves the server): inbox tabs (Primary, Promotions, Social,
  Updates, Forums) sorted from mail headers and senders, learning from where you move mail; a summary card with the key
  sentences, dates, amounts, deadlines, codes and questions asked of you; spell check while writing (the browser's own)
- **Spam and Trash**: Spam opens behind a warning screen listing its links, restricted attachments (blocked from
  download) and fake sender names; links ask before opening. Trash empties itself after 7 days and Spam after 10 days
  (opened or not), or empty either one now
- **Admin console**: create and manage email accounts, domains, aliases and sessions, import mail from an old server, view the activity log
- **Built-in mail server**: Postfix (SMTP) + Dovecot (IMAP) + OpenDKIM, with automatic HTTPS (Let's Encrypt)
- **Security**: 2-step verification (authenticator app codes + recovery codes) with app passwords for mail apps, ClamAV antivirus, a risky-attachment blocker, tracking-image blocking, anti-spoofing, DKIM signing on every message
- **Works with every mail app**: iPhone, Android, Outlook and Thunderbird over IMAP 993 and SMTP 587. *Settings → Mail apps*
- **Ready for the Zoltis Mail app**: sign-in with bearer tokens and a discovery URL (`/.well-known/zoltis-mail.json`). See [docs/MOBILE-APP.md](docs/MOBILE-APP.md)
  shows each user their exact settings with step-by-step guides, plus a one-tap setup profile for iPhone/iPad Mail

| Community Edition limits | |
|---|---|
| Email accounts | **up to 10** |
| Domains | **up to 2** (accounts and aliases are shared across them) |
| Aliases (info@, sales@ …) | **up to 5** (`postmaster@` doesn't count) |
| Mailbox size | **up to 720 MB per account**, including attachments |
| Drive / file storage | not included |
| Hosting | you run it on your own server |

Need more accounts and aliases, with Zoltis managing the server for you? Upgrade to **Zoltis Mail Pro** from
**Admin console → Upgrade to Mail Pro**, which takes you to the Zoltis sign-up page with your license and domains filled in.
Moving is one step: **Admin console → Export & move** creates one encrypted file with every account (passwords
included), alias, setting and email, which Zoltis imports for you ([docs/MIGRATION.md](docs/MIGRATION.md)).
See the [edition comparison](docs/EDITIONS.md).

---

## Requirements

- A Linux server (Ubuntu 22.04/24.04 or Debian 12 recommended) with a **public IPv4 address**
- **2 GB RAM**. Antivirus (ClamAV) is turned on only on servers with **4 GB RAM or more**. 10 GB+ disk (10 × 720 MB is about 7 GB of mail)
- Docker with Compose v2. The installer can install it for you.
- A domain name you control (for example `yourcompany.com`)
- **Outbound port 25 open.** Some cloud providers block it until you ask.
- Reverse DNS (PTR) for the server IP. You set this in your hosting provider's panel.

## Install

### Step 1: connect your domain to Cloudflare first (recommended)

Do this **before** installing. HTTPS certificates and mail delivery need DNS that already works.

1. At [dash.cloudflare.com](https://dash.cloudflare.com), click **Add a domain** and choose the **Free** plan.
2. At your registrar, replace the nameservers with the two Cloudflare gives you
   (Namecheap: *Domain List → Manage → Nameservers → Custom DNS*).
3. **Wait about 30 minutes**, until Cloudflare shows the domain as **Active**.
4. In *DNS → Records*, add two **A** records pointing at your server, with Proxy status **DNS only (grey cloud)**:
   `webmail` and `mail`. Delete old MX records, and turn off Cloudflare *Email Routing*.

Mail can't pass through Cloudflare's proxy (orange cloud), so the `mail` record must always be DNS only.
The installer checks this and warns you.

### Step 2: install

```bash
git clone https://github.com/marsheilyt/zoltis-mail.git
cd zoltis-mail
sudo ./install.sh
```

The installer asks for your webmail address (e.g. `webmail.yourcompany.com`) and mail server name
(`mail.yourcompany.com`), writes `.env`, builds the containers and starts them. It prints a **setup code**.

1. Point two DNS **A records** at the server: `webmail.yourcompany.com` and `mail.yourcompany.com`.
2. Open `https://webmail.yourcompany.com`, enter the setup code, and create your administrator account.
3. Open **Admin console → Setup guide**. It lists every record (MX, SPF, DKIM, DMARC) exactly as Cloudflare's
   *Add record* form asks for it (Name, Content, Priority, Proxy status), plus reverse DNS (PTR), port 25 and
   mail app settings. Add them in Cloudflare, wait 5–30 minutes, then click **Check DNS**.
4. Create accounts in **Admin console → Accounts**.

Manual install: `cp .env.example .env`, edit it, then run `docker compose up -d --build`.

### Small VPS (1 CPU, 1 GB RAM, 20 GB disk)

Zoltis Mail runs on a 1 GB server. On small servers `install.sh` does this for you:

- **Antivirus off below 4 GB RAM.** ClamAV is only enabled on servers with 4 GB of RAM or more (it needs about
  1.5 GB on its own). The risky-attachment blocker (programs, macros, disguised files, archives) keeps working.
- **2 GB swap file** (after asking), so a short memory spike doesn't get Postfix, Dovecot or the web app killed.
- **`POSTFIX_PROCESS_LIMIT=20`** (default 100), so a burst of spam connections can't use up the RAM.
- Container logs are capped at 30 MB per container, and the Docker build cache is removed after the first build.

Disk budget on 20 GB: about 3–5 GB for the OS, about 1.5 GB for images, up to 7.2 GB for 10 × 720 MB mailboxes,
and 2 GB of swap. That leaves room for one compressed backup at most, so copy backups off the server.
`scripts/backup.sh` refuses to start if the backup wouldn't fit.

### What runs

| Container | Purpose | Public ports |
|---|---|---|
| `web` | Webmail, admin console, attachment blocker | via Caddy |
| `caddy` | HTTPS with automatic Let's Encrypt certificates | 80, 443 |
| `postfix` | Receives and sends mail, DKIM signing, spam blocklists | 25, 465, 587 |
| `dovecot` | Mailboxes, IMAP for mail apps, 720 MB quotas | 993 |
| `clamav` | Virus scanning (optional, `ANTIVIRUS=true`) | none |

Mail, accounts, DKIM keys and certificates live in Docker volumes and survive updates.

## Day to day

```bash
docker compose logs -f                              # all logs
docker compose exec web zoltis accounts list        # accounts and storage used
docker compose exec web zoltis accounts add jane@yourcompany.com --name "Jane Doe"
docker compose exec web zoltis doctor yourcompany.com   # deliverability / spam check
./scripts/update.sh                                 # update to the latest version (git pull + rebuild)
./scripts/backup.sh                                 # encrypted backup (asks for a passphrase) to ./backups
```

## Moving from your current server (Postfix + Dovecot + Roundcube)

1. Install Zoltis Mail on a **new** server (or stop the old services first, because ports 25/587/993 must be free).
2. Create the same accounts in the admin console.
3. In **Admin console → Import mail**, enter the old server's IMAP address and each user's old password.
   All folders are copied. Running it again only copies new messages.
4. Switch the domain's **MX record** to the new server, then run the import once more to catch the last messages.

## Connecting phones and desktop mail apps

| | Server | Port | Security |
|---|---|---|---|
| Incoming (IMAP) | `mail.yourcompany.com` | 993 | SSL/TLS |
| Outgoing (SMTP) | `mail.yourcompany.com` | 587 | STARTTLS (or 465 SSL/TLS) |
| Username | full email address | | |

## Keeping mail out of spam

Inbox placement depends on DNS and server reputation. Zoltis Mail generates a DKIM key for every domain and shows the exact
records to publish. Run **Check DNS** in the admin console (or `zoltis doctor`) until everything is green, set the PTR record,
and see [docs/DELIVERABILITY.md](docs/DELIVERABILITY.md).

## Risky attachment blocker

On by default for both sent and received mail (`[attachments]` in the config):

| Check | Example | Default |
|---|---|---|
| Dangerous file types | `.exe .bat .cmd .scr .js .vbs .ps1 .msi .jar .lnk .iso .hta .dll` and about 70 more | block |
| Disguised names | `invoice.pdf.exe`, hidden right-to-left characters (`photo‮gpj.exe`), trailing dots/spaces | block |
| Renamed programs (checked by content) | an `.exe` renamed to `holiday.jpg`, Linux/macOS binaries, shortcuts, ISO images | block |
| Inside archives / zipped folders | `.zip`, `.tar`, `.tar.gz`, `.gz` checked file-by-file, nested up to 3 levels | block if anything inside is risky |
| Password-protected archives | contents can't be scanned | block |
| Zip bombs, path-traversal archives | `../../etc/...`, files that expand to huge sizes | block |
| Office files with macros | `.docm .xlsm`, or a `.docx` that hides `vbaProject.bin` | warn (user confirms) |
| RAR / 7z | can't be opened, so contents are unknown | warn |
| Shell scripts | `#!/bin/sh` files | warn (`strict_scripts = true` blocks `.sh .py .deb .rpm` too) |

- **Sending:** risky files are rejected the moment they're attached, with a list of what was blocked and why.
  Archives are inspected on the server straight away, and everything is checked again when the message is sent. Drafts are checked too.
- **Folders:** dragging a folder (or *Attach → Attach a folder*) checks every file inside, leaves out the blocked ones,
  and attaches the rest as `FolderName.zip`.
- **Receiving:** blocked attachments show a red *Blocked* card and can't be downloaded. With `incoming_action = warn`,
  users see a warning and can download anyway. Caution files ask for confirmation before downloading.
- Admins can add or exempt types: `extra_blocked_extensions = apk, py` or `allowed_extensions = iso`.

## Antivirus (ClamAV)

Every outgoing attachment is scanned before sending, and every received attachment before it can be opened.
Infected files are refused and labelled with the virus name. ClamAV downloads its virus database on first start, which takes about 5 minutes.
It is enabled automatically on servers with 4 GB of RAM or more and stays off on smaller ones
(re-running `install.sh` on a smaller server turns it off). Manual switch: `ANTIVIRUS=true|false` and
`COMPOSE_PROFILES=antivirus` (or empty) in `.env`.

## Security design

- Email HTML is sanitized on the server and shown in a sandboxed frame with a strict CSP, so scripts never run.
- Remote images and tracking pixels are blocked until the user allows them.
- Users can only send as their own address or an alias that delivers to them (Postfix `reject_sender_login_mismatch`).
- Passwords are stored as SHA512-CRYPT. Failed logins are rate-limited per IP and per account.
- 2-step verification (TOTP, *Settings → Security*): webmail asks for a code after the password. While it is on, the
  account password only works from the web container's private IP (Dovecot `allow_nets`), so IMAP/SMTP clients must
  use the account's app password. Admins can turn it off for a user who lost their phone (*Accounts → ⋮*).
- The admin console uses an internal Dovecot master login (random 256-bit secret) that only the web container's private IP may use.
- Encryption in transit everywhere: HTTPS with HSTS (2 years); TLS 1.2+ with forward-secrecy ciphers on IMAP and SMTP;
  STARTTLS even between containers on the private network.
- Outgoing mail is verified with DANE (DNSSEC, via a local validating resolver) and MTA-STS where the receiving domain
  publishes them, opportunistic TLS otherwise. Each domain publishes its own MTA-STS policy and TLS reporting record
  (*Domains & DNS*: start in `testing`, switch to `enforce` once the reports are clean).
- Backups made with `scripts/backup.sh` are encrypted with your passphrase (AES-256). Stored mailboxes are not
  encrypted per user; protect the server disk with your provider's disk encryption.
- Code integrity: every release is signed (`zoltis/RELEASE.manifest`). Changed program files, including the logo,
  lock the service and are reported at the daily license check-in (see `docs/LICENSING.md`).
- Community Edition policies (`web/legal/community-policies-v1.0.md`): the first administrator must accept them on
  the setup screen; who accepted which version, and when, is stored and shown in *Admin console → License*. When a new
  version ships, account and domain creation pauses until an admin accepts it.
- Community Edition always shows the Zoltis Mail name and logo. `APP_NAME`, `[branding] company` and
  `primary_color` only take effect on Enterprise (custom branding).
- Only ports 25, 80, 443, 465, 587 and 993 are published. Everything else stays on a private Docker network.

## Development

```bash
python3 devtools/demo.py        # full demo without Docker (emulated mail server), setup code DEMO1234
python3 -m pytest -q tests      # 142 tests
```

Project layout:

```
zoltis/          Python backend (standard library only): webmail API, admin API, mail-server config renderer
web/             Front-end (vanilla JS): webmail + admin console
docker/          Dockerfiles and configs for web, postfix, dovecot, caddy
scripts/         update, backup, restore
devtools/        Emulated IMAP/SMTP/ClamAV and a mock licensing portal for development and tests
docs/            Architecture, deliverability, editions
```

## License

Zoltis Mail Community License: free to run the official release for your own organisation with a free license key
from [zoltismail.com](https://zoltismail.com). See [LICENSE](LICENSE).
