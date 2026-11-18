# Zoltis Mail Enterprise: plan

**Business model:** Enterprise is a **managed service**. Zoltis runs the mail servers for each customer and sells
**bundles of mail accounts per month** (see [EDITIONS.md](EDITIONS.md)). Customers don't install anything. They get
webmail, mobile apps, calendar, contacts and drive, and Zoltis handles servers, deliverability, backups and updates.

The Community Edition (free, self-hosted on GitHub/Docker) is the foundation: mail server, webmail, admin console,
security, and the module system that Enterprise modules plug into (`zoltis.enterprise`).

## What Zoltis needs to operate Enterprise
- **Multi-tenant control plane:** a customer portal (sign-up, choose bundle, billing), and a provisioning service that creates
  a tenant (own domains, account limit = bundle size) on Zoltis-run mail clusters.
- **Billing:** a monthly subscription per bundle (Stripe, Razorpay or similar). Upgrading the bundle raises the account limit right away.
- **Operations:** monitoring and alerting, central logging, daily off-site backups, IP warm-up and reputation monitoring,
  abuse handling, and a status page.
- **Shared, clean sending IPs** with Postmaster Tools and SNDS monitoring, plus Rspamd for inbound spam filtering.

## Modules

| Module | What users get | How it works | Sync with phones and desktop apps |
|---|---|---|---|
| **Calendar** | Day/week/month views, invites (iMIP: accept/decline from email), shared and team calendars, free/busy, reminders | Built-in **CalDAV server** backed by PostgreSQL or SQLite; iTIP/iMIP processing on incoming `text/calendar` mail | iOS and macOS natively; Android via DAVx⁵; Thunderbird; Outlook via CalDAV Synchronizer |
| **Contacts** | Address book, groups, shared company directory (LDAP/AD import), photos | Built-in **CardDAV server**; autocomplete in compose uses it | iOS and macOS natively; Android via DAVx⁵ |
| **Drive** | File storage, folders, share links with expiry and password, quotas, "save attachment to Drive", "send large file as link" | **WebDAV** plus the REST API; storage on local disk or S3-compatible object storage (MinIO, Wasabi, AWS); ClamAV scan on upload | Desktop via WebDAV mount; mobile apps |
| **Mobile apps** | iOS and Android apps for mail, calendar, contacts and drive, with push notifications for new mail | **Flutter** (one codebase for both platforms) on the existing REST API with Bearer tokens; a push service watches mailboxes with IMAP IDLE and sends through APNs/FCM | App Store and Google Play, or white-labelled builds per customer |
| **Admin console (Enterprise additions)** | Multi-domain tenants, bundles and billing, group policies, log export | Builds on the Community admin console | |
| **SSO** | Sign in with Microsoft Entra ID / Google / Keycloak (OIDC) or SAML | Requires the IMAP/SMTP server to accept OAuth tokens (`XOAUTH2`/`OAUTHBEARER`); Dovecot and Postfix (via Dovecot SASL) support this | |
| **Shared mailboxes and delegation** | info@, support@ shared by a team; "send as" | IMAP ACL (RFC 4314) on the mail server | |

> Note on "email contact sync": phones and Outlook can already sync **mail** directly over IMAP.
> Enterprise adds **calendar and contact** sync through CalDAV and CardDAV. Exchange ActiveSync isn't planned
> because of Microsoft's licensing; CalDAV and CardDAV cover iOS, macOS, Android (DAVx⁵) and Thunderbird.

## Platform work that Enterprise needs
- **Database:** PostgreSQL (SQLite for small installs) for calendar, contacts, drive metadata and audit logs.
- **Sessions in Redis**, so several app servers can run behind a load balancer.
- **Real-time updates:** server-sent events driven by IMAP IDLE, so new mail appears without polling.
- **Conversation threading** (Gmail-style grouping) using IMAP `THREAD=REFERENCES` when the server supports it, with client-side grouping otherwise.
- **Licensing:** Ed25519-signed license files (customer, seats, expiry, enabled modules), verified offline,
  with no phone-home required. Enterprise packages come from a private apt/yum repository or a signed tarball.

## Suggested delivery phases

| Phase | Scope | Rough effort* |
|---|---|---|
| 1 | Harden Community: security review/pen test, IMAP IDLE push, threading, i18n, accessibility pass | 4–6 weeks |
| 2 | Enterprise core: PostgreSQL, licensing, admin console, Contacts + CardDAV | 6–8 weeks |
| 3 | Calendar + CalDAV + email invitations | 8–10 weeks |
| 4 | Drive (WebDAV, S3, sharing, large-file links) | 6–8 weeks |
| 5 | Flutter mobile apps + push service + store publishing | 10–14 weeks |
| 6 | SSO (OIDC/SAML) + shared mailboxes | 4–6 weeks |

\*For a small team of 2–3 developers. Phases 3–5 can run in parallel.

## Licensing model
- **Community:** source-available under the **Zoltis Mail Community License** (`LICENSE`): free to run unchanged
  for your own organisation with a license key; changed copies only for private testing; no hosting for others,
  resale or removing the license check, limits or credit. Have a lawyer review it before the public release.
- **Enterprise:** not distributed. It runs only on Zoltis infrastructure, so no license keys are needed for customers.
- Note: in open-source code, the 10-account / 720 MB limits can technically be removed by anyone who edits the code.
  The limits shape the product; the value of Enterprise is that Zoltis manages it.
