# Zoltis Mail editions

| | **Community Edition** |
|---|---|
| Who runs the server | **You**, on your own Ubuntu/Linux server (Docker) |
| Price | Free (download from GitHub) |
| Email accounts | Up to **10** |
| Domains | Up to **2** |
| Aliases | Up to **5** (`postmaster@` is free) |
| Mailbox size | Up to **720 MB** per account, attachments included |
| Support | Community (GitHub issues) |

Zoltis Mail Pro and Enterprise are separate products, built and packaged separately and managed by Zoltis.
Their plans and prices are on the Zoltis website (**Admin console → Upgrade to Mail Pro** links there).

Moving from Community to Mail Pro or Enterprise: **Admin console → Export & move** creates one encrypted file with every account, password, setting and email, which Zoltis imports into the managed server. See [MIGRATION.md](MIGRATION.md).

## Feature comparison

✅ included · 🔜 planned · — not included

### Email
| Feature | Community | Enterprise |
|---|---|---|
| Gmail-style webmail (search, labels, star, archive, undo, drafts, signatures, dark mode, mobile web) | ✅ | ✅ |
| Built-in mail server (Postfix + Dovecot) with DKIM signing | ✅ | ✅ managed by Zoltis |
| IMAP/SMTP for iPhone, Android, Outlook, Thunderbird | ✅ | ✅ |
| Aliases (info@, sales@) | ✅ | ✅ |
| Import mail from an old server | ✅ | ✅ done for you by Zoltis |
| Conversation threading, instant new-mail updates | — | 🔜 |
| Shared mailboxes with delegation | — | 🔜 |

### Admin console
| Feature | Community | Enterprise |
|---|---|---|
| Create, edit, disable and delete accounts; reset passwords | ✅ | ✅ |
| Per-account storage limits and usage | ✅ (max 720 MB) | ✅ (larger plans) |
| Domains with generated DNS records and a DNS / spam check | ✅ | ✅ |
| Active sessions and remote sign-out | ✅ | ✅ |
| Activity log | ✅ | ✅ with export and retention |
| Single sign-on (Microsoft Entra ID, Google, Keycloak) | — | 🔜 |
| Per-group policies | — | 🔜 |

### Security
| Feature | Community | Enterprise |
|---|---|---|
| ClamAV antivirus (incoming and outgoing) | ✅ | ✅ |
| Risky-attachment blocker (programs, disguised files, archives, macros, folders) | ✅ | ✅ |
| Tracking-image blocking, safe email display, anti-spoofing | ✅ | ✅ |
| Spam filtering | Blocklists (Spamhaus, SpamCop) | 🔜 Advanced filtering (Rspamd) managed by Zoltis |
| Managed backups, monitoring, security updates | You (scripts included) | ✅ Zoltis |

### Collaboration (Enterprise)
| Feature | Community | Enterprise |
|---|---|---|
| Calendar with invitations and shared calendars (CalDAV) | — | 🔜 |
| Contacts and company directory with phone sync (CardDAV) | Autocomplete only | 🔜 |
| Drive: file storage, share links, large-file sending | — | 🔜 |
| iOS and Android apps with push notifications | — | 🔜 |
