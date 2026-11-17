# Moving to Mail Pro / Enterprise (export & import)

A self-hosted Community server can be moved to a server managed by Zoltis (Mail Pro or Enterprise), or to another
self-hosted server, in one step. **Admin console → Export & move** creates one encrypted file containing:

| Included | Details |
|---|---|
| Every email | All folders: Inbox, Sent, Drafts, Archive, Trash, Junk and custom folders. Attachments included (each message is a complete `.eml`). |
| Message status | Read/unread, starred, answered and draft flags, and the original received date |
| Accounts | Address, name, storage limit, admin and enabled flags, and the **password hash**, so people keep their passwords |
| Aliases | Address and destinations |
| Domains | Including the **DKIM signing key**, so the DKIM DNS record doesn't change |
| Personal settings | Display name, signature, theme and other preferences, plus the contacts used for autocomplete |

Not included: active sign-in sessions (people sign in once on the new server), the activity log, and the license key
(the new server has its own).

## Customer: export

1. **Admin console → Export & move**, choose a passphrase (10+ characters), click **Export everything**.
2. When it finishes, click **Download**, and send the file to Zoltis together with the passphrase, **over a separate
   channel** (e.g. the file through the upload link, the passphrase by phone).
3. Delete the file from the server to free the disk space.

The export file is about 60–80% of the mail size. If the server's disk is too small for it, the console says so.
Stream it straight to your own computer instead, so nothing is written on the server:

```bash
ssh you@your-server "cd zoltis-mail && docker compose exec -T -e ZOLTIS_EXPORT_PASSPHRASE='your passphrase' web zoltis export create -" > mail.zmexport
```

## Zoltis (or the customer's new server): import

Admin console: copy the file into the server, then click **Import** next to it in *Export & move*:

```bash
docker compose cp mail.zmexport web:/var/lib/zoltis/exports/
```

Command line, with progress:

```bash
docker compose exec -T -e ZOLTIS_EXPORT_PASSPHRASE='…' web zoltis export import - < mail.zmexport
```

- Import follows the **new server's license and limits**: domains must be covered by its license, and accounts or
  aliases above its limits are skipped and listed as warnings. A storage limit above the new plan's maximum is
  lowered to the maximum.
- Existing domains, accounts and settings on the new server are kept. Messages already in a folder (same Message-ID)
  are skipped, so **running the import again never creates duplicates**. That makes a two-pass move possible:
  import a first export early, then a final export right before switching DNS.
- A file that was cut off (e.g. an interrupted download) is imported up to where it ends, with a warning.

## Switching over

1. Import the final export on the new server.
2. In Cloudflare, point the `mail` and `webmail` **A records** at the new server's IP (DNS only). MX, SPF, DMARC
   and DKIM stay the same if the mail hostname stays the same. If the new server uses another hostname, update MX
   and SPF as its *Setup guide* shows.
3. Ask the new host to set reverse DNS (PTR). People keep using the same addresses and passwords. Phones and mail
   apps reconnect on their own when the hostname is unchanged.
4. Mail that arrived at the old server after the final export: run one more export and import. Duplicates are skipped.

## File format (for Zoltis tooling)

```
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -in mail.zmexport | tar tzf - --warning=no-unknown-keyword
```

A gzip-compressed PAX tar, encrypted with OpenSSL (AES-256-CBC, PBKDF2-SHA256, 600,000 iterations, random salt).
Entries, in this order:

| Entry | Content |
|---|---|
| `manifest.json` | `{"format": "zoltis-export", "version": 1, "created", "app_version", "edition", "license_id", "mail_hostname", "counts": {...}}` |
| `domains.json` | `[{"name", "created", "dkim_selector", "dkim_public", "dkim_private" (PEM)}]` |
| `accounts.json` | `[{"email", "domain", "name", "pw_hash" ({SHA512-CRYPT}$6$…, Dovecot format), "quota_mb", "is_admin", "enabled", "created", "last_login"}]` |
| `aliases.json` | `[{"source", "destinations": [...], "created"}]` |
| `users/<email>.json` | `{"settings": {...}, "contacts": {...}}` |
| `mail/<email>/<n>/folder.json` | `{"name", "role" (inbox/sent/drafts/trash/junk/archive or null), "delim"}` |
| `mail/<email>/<n>/<uid>.eml` | the raw message; PAX headers `ZOLTIS.flags` (IMAP flags) and `ZOLTIS.internaldate` (IMAP INTERNALDATE) |
| `end.json` | `{"complete": true, ...}`. Missing means the file was cut off. |

Readers must ignore entries they don't know. `version` only increases for incompatible changes.

The password hashes are SHA512-CRYPT, which every Dovecot accepts. Copy them as-is into the target's passdb.

**Security:** the file contains every email, every password hash and the DKIM private keys. Treat it like a full backup:
don't email it, delete it once imported, and keep the passphrase separate from the file. The encryption is
confidentiality-only (no authentication tag). Accidental damage is detected by gzip's checksum, but only accept
files from the customer directly.
