# Community Edition licensing

Every install needs a **license key**. Licensing is a module of **zoltismail.com** (no separate host):

- **Community / self-hosted Edition:** the customer signs in at zoltismail.com → My account → License keys →
  Community Edition, enters the server's IP address and copies the free key. The server activates it and checks in
  daily at `https://zoltismail.com/api/license/v1/…`.
- **Managed plans:** Zealantis issues the key from the **ZOcc dashboard** while configuring the customer's server and
  sets it as `LICENSE_KEY`, so the server is licensed from its first start (no 7-day reminders). Billing and
  suspension come from ZOcc through the same check-in.

| | |
|---|---|
| Key bound to | the **mail domain(s)** registered on the portal. The app only adds those domains and creates accounts on them. |
| Key checked | **offline** with Ed25519: the key is signed by Zoltis, so it can't be forged or edited (e.g. to add a domain) |
| Activation | **online**, once when the key is entered, then renewed **daily**. The portal can refuse a second server or revoke a key. |
| Registration | Required from **2.3.0**. A server has **7 days** after it first starts on 2.3.0 (new or upgraded) to add a key ([license] `grace_days`). Admins get a banner and Inbox reminders at the start, with 3 days left, on the last day and after it. |
| Server IP | Each key names the server IP address(es) entered on zoltismail.com (`ips`). Activation is refused if the request doesn't come from one of them (`403 ip_mismatch`), and the activation certificate names the IP (`ip`). |
| Validity | **One year** from the first activation (`paid_until` in the certificate). Renewal opens 30 days before the end in the same zoltismail.com account; the key stays the same. |
| Without a license | Existing mailboxes keep sending and receiving. Only creating accounts, adding domains and (external mode) new webmail sign-ins are blocked. |
| Portal down | The current activation keeps working until it expires (`valid_until`, e.g. 30 days). A new key can't be activated. |

## Where customers enter the key

Customers get the key at **zoltismail.com → My account → License keys → Community Edition**, entering the server's
public IP address (shown in Admin console → License), then paste it into the server:

- **Setup screen** (first run): optional license key field next to the setup code (there are 7 days to add it).
  The admin address must be on a covered domain.
- **Admin console → License**: step-by-step instructions with the server IP, status, covered domains and IP,
  *Check now*, replace key.
- **CLI**: `docker compose exec web zoltis license activate <KEY>` (also `status`, `refresh`).
- **Environment**: `LICENSE_KEY=` in `.env` (→ `ZOLTIS_LICENSE_KEY`), activated when the server starts.

Stored in the data volume: `license.key`, `license.activation`, `install.id` (random per install, mode 0600).

## Before release (Zoltis)

1. Generate the signing key pair **once**, on a trusted machine:
   `python3 devtools/license_dev.py keygen`
2. Put the **public** key in `zoltis/licensing.py` → `TRUSTED_KEYS = {"k1": "<hex>"}`.
   Keep the **private** key only in the portal's secret store. Never commit it.
   To rotate, add `"k2"` next to `"k1"`, sign new keys with k2, and drop k1 in a later release.
3. The URLs in `zoltis/licensing.py`: `SITE = https://zoltismail.com` (customer pages `/account/licenses` and
   `/upgrade`) and `DEFAULT_SERVER = https://zoltismail.com/api/license` (the licensing module's API: `POST /v1/activate`
   and `/v1/deactivate` under it). Both must be live before the release, or override them with `[license] server`,
   `register_url` and `upgrade_url`. The upgrade page receives
   `?from=community&license=<lid>&domains=<comma list>`, so the Mail Pro sign-up can be linked to the existing customer.

4. **Sign every release** after the last change to `zoltis/` or `web/`:
   `python3 devtools/release_sign.py --seed <release key> --kid k1`, then commit `zoltis/RELEASE.manifest`.
   The public half goes in `TRUSTED_KEYS` like the license key (one key pair can serve both; the signing
   contexts differ). `python3 devtools/release_sign.py --check` shows what a server would report.

## One key, one server

- **Portal rule:** a key is active on one `install_id` at a time. Another install gets `409 {"code": "in_use"}`
  ("already in use on another server") until the customer clicks **Release** on the portal, for example when moving
  to a new VPS. The released server stops working at its next check-in.
- **The activation certificate is signed for that one `install_id`.** Copying `license.key` and `license.activation`
  to another server doesn't work.
- **Cloned servers:** copying the entire data volume also copies `install.id`, so both copies claim the same install.
  Each running copy has its own `instance_id`, though. ZOcc should flag a clone when **two different `instance_id`s
  alternate for one `install_id`** (A, B, A within 48 hours). A restart only changes the ID once: the old one is never
  seen again. Also flag when check-ins for one install come from two source IPs on the same day. On a clone, refuse
  further activations for that key (`409 in_use`) and ask the customer to release the extra server.

## Code integrity (changed program files)

Each release carries `zoltis/RELEASE.manifest`: the SHA-256 of every core file (the `zoltis/` Python package and
all of `web/`, including the logos), signed by Zoltis. The server checks its files at startup and every 10 minutes.

| Status | Meaning | When enforced |
|---|---|---|
| `ok` | Exactly the official release | Works normally |
| `modified` | A core file was changed, added or deleted (for example a replaced logo) | **Locked**: webmail, IMAP and SMTP refuse every sign-in with "program files were changed"; incoming mail is still stored |
| `unsigned` | No manifest, a forged one, or one for another version | **Locked** the same way |

Enforcement (`[integrity] enforce`, env `ZOLTIS_INTEGRITY_ENFORCE`): `auto` (default) is on when licensing is
required or when the copy carries a genuine signed manifest, so every official build enforces it and development
checkouts don't. Putting the official files back (reinstall or `git checkout`) unlocks the server at the next check.
The status is reported at every check-in (see `integrity` above), so ZOcc sees modified installs per license ID and
can refuse to renew them (answer `4xx` with `code: "modified"`), or suspend a managed plan.

## Token format (keys and activation certificates)

```
ZM1.<base64url(JSON payload, no padding)>.<base64url(Ed25519 signature, no padding)>
```

The signature covers a context prefix plus the exact payload bytes:

- license key: `b"zoltis-license-v1\n" + payload`
- activation certificate: `b"zoltis-activation-v1\n" + payload`

The prefixes stop an activation certificate from being passed off as a key, or the other way round.
`zoltis.licensing.encode_token()` is the reference implementation.

**License key payload** (issued on registration):

```json
{"v": 1, "kid": "k1", "lid": "lic_8f3a…", "edition": "community",
 "domains": ["acme.com"], "ips": ["203.0.113.9"], "customer": "Acme Ltd", "email": "it@acme.com",
 "issued": 1795000000, "expires": null}
```

`lid` is the portal's stable license ID. `expires` is a Unix time, or `null` for no expiry. To add a domain, the portal
issues a new key with the same `lid` and the extra domain. The customer pastes it in, and the app releases the old one.

**Activation certificate payload:**

```json
{"v": 1, "kid": "k1", "lid": "lic_8f3a…", "install_id": "ins_…", "status": "active",
 "issued": 1795000000, "valid_until": 1797592000}
```

## Licensing API (zoltismail.com module)

JSON over HTTPS at `https://zoltismail.com/api/license` (the paths below are relative to it). The app sends
`User-Agent: ZoltisMail/<version>`. Keys issued from the ZOcc dashboard for managed plans use the same API.

### `POST /v1/activate`

Called when a key is entered, and again every 24 h while the server runs. The renewal uses the same request,
so it doubles as the **"this server is live" check-in**: the portal records `last_seen` per `install_id` and shows
each install with its license ID and edition.

```json
{"license_key": "ZM1.…", "license_id": "lic_…", "install_id": "ins_…", "instance_id": "9f3a…", "server_ip": "203.0.113.9", "edition": "community",
 "app_version": "2.3.0", "hostname": "mail-1",
 "integrity": {"status": "ok", "fingerprint": "9f2c…", "files": [], "enforced": true}}
```

| Field | Meaning |
|---|---|
| `license_id` | The `lid` inside the key (also readable from the key itself) |
| `install_id` | Random ID of this server, created on first start (`install.id` in the data directory) |
| `server_ip` | The public IP set on this server (`PUBLIC_IP`). The portal checks the request's real source IP against the key's `ips` |
| `instance_id` | Random ID of the running process, new on every start and never saved. Detects cloned servers (below) |
| `edition` | `community` or `enterprise` |
| `app_version`, `hostname` | Version installed, and the server's host name |
| `integrity` | Are the program files the official release, unchanged? `status`: `ok`, `modified` (core files changed, added or deleted) or `unsigned` (no genuine release manifest). `fingerprint`: SHA-256 over all core files. `files`: names of the changed files (max 50, never their contents). `enforced`: whether this server locks itself. |

When the integrity status changes, the server checks in immediately instead of waiting for the next day.

Nothing else is sent: no email addresses, account counts, usage or mail. A server is "live" if it checked in
within the last ~25 hours. Network trouble makes it retry every 15 minutes, so a gap of several days means the server
is down, offline or uninstalled.

The check-in runs whenever a key is installed, also when licensing isn't required (`[license] required = false`).
In that case a refused key never blocks anything; the portal just stops seeing the server as active.

| Response | Meaning to the app |
|---|---|
| `200 {"activation": "ZM1.…"}` | Activated or renewed. Certificate stored. |
| `4xx {"error": "message shown to the admin", "code": "revoked\|expired\|in_use\|invalid"}` | Refused. The app drops its activation and stops creating accounts. |
| `5xx` / timeout | Temporary. The app keeps the current activation and retries in 15 min. |

Recommended policy (what `devtools/license_dev.py serve` does): verify the key signature, reject revoked or expired
keys, and allow **one active `install_id` per `lid`**. The same install re-activating is always fine. A different
install gets `409 in_use` until the customer releases the old server on the portal.

### Renewals and payments (inside the activation certificate)

The portal (ZOcc) puts the subscription terms in the signed activation certificate it returns, so they can't be
edited on the server. The key itself never changes, and Community keys are issued **without** `expires`.

```json
{"v": 1, "kid": "k1", "lid": "lic_…", "install_id": "ins_…", "issued": 1763400000, "valid_until": 1766000000,
 "plan": "managed", "paid_until": 1764547200, "status": "active", "grace_days": 10}
```

| Field | Community | Managed plans |
|---|---|---|
| `plan` | `community` | `managed` |
| `paid_until` | The yearly renewal date. The customer renews (free) on the portal and the portal moves it one year on. | The current invoice's due date. Moves one month on when it's paid. |
| `status` | `active` | `active`, `overdue` (past due, in the grace period) or `suspended` |
| `grace_days` | not used | Days after `paid_until` before the service is suspended. Default **10**. |
| `valid_until` | 30 days | Keep it short (e.g. 3 days), so a server that can't reach ZOcc still locks on time |

What the server does:

| Situation | Effect |
|---|---|
| Community, less than 30 days to `paid_until` | Admin console warns: renew on the portal, the key stays the same |
| Community, past `paid_until` | Mail keeps working. No new accounts or domains until renewed. Admins see a warning. |
| Managed, `status: overdue` | Everything works. Admins see "Pay before <date>, or the service is suspended". |
| Managed, `status: suspended`, or `paid_until + grace_days` passed while the certificate has lapsed | **Locked.** Every session ends, webmail sign-in is refused (HTTP 423 with a message pointing to the customer portal), and IMAP/POP/SMTP logins are refused. Incoming mail is still accepted and stored, so nothing is lost. Nobody on the server can unlock it. |
| ZOcc returns `status: active` | Unlocked automatically. While locked the server checks in every 15 minutes, so this takes at most 15 minutes. |

### `POST /v1/deactivate`

```json
{"license_key": "ZM1.…", "install_id": "ins_…"}
```

Best effort. The app calls it when a key is replaced, to free the old one. Answer `200 {"ok": true}`.

## Development

- `python3 devtools/demo.py` runs an in-process mock portal and prints a demo key for `example.com`.
- The tests (`tests/conftest.py`) trust a throwaway key and run the mock portal.
- `python3 devtools/license_dev.py serve --seed <hex>` runs the mock portal on its own. The app has to trust the matching public key.

## Limits of this protection

Community Edition is distributed as readable Python source. Someone determined can edit the code to remove the check,
and no client-side licensing can prevent that. What this design does give you:

- **Keys can't be forged or widened.** Only Zoltis' private key can sign a key or an activation.
- **One key, one server.** A copied key is refused by the portal on a second install.
- **Keys work only for their registered domains.** A shared key is useless to anyone with a different domain.
- **Revocation.** It takes effect at the next daily renewal.
- **Changed code is detected and reported.** Edited, added or deleted core files (including the logo) lock the
  service and show up in ZOcc under the license ID. Someone who also removes the integrity check stops sending
  `integrity: ok`; ZOcc should treat a missing or non-`ok` integrity status as out of license.

Copying an entire data volume (including `install.id`) clones the install. Each copy reports its own `instance_id`,
so ZOcc can spot and refuse it (see "One key, one server"), and the domain binding limits the copy to the same domains. A patched build that removes the check is a license violation, so pair this with the Community
license terms (see `LICENSE`) for legal protection.
