# Community Edition licensing

Community Edition is free, but every install needs a **license key** before it can create email
accounts or add domains. Customers get a key by registering on the Zoltis licensing portal (SaaS).

| | |
|---|---|
| Key bound to | the **mail domain(s)** registered on the portal. The app only adds those domains and creates accounts on them. |
| Key checked | **offline** with Ed25519: the key is signed by Zoltis, so it can't be forged or edited (e.g. to add a domain) |
| Activation | **online**, once when the key is entered, then renewed **daily**. The portal can refuse a second server or revoke a key. |
| Without a license | Existing mailboxes keep sending and receiving. Only creating accounts, adding domains and (external mode) new webmail sign-ins are blocked. |
| Portal down | The current activation keeps working until it expires (`valid_until`, e.g. 30 days). A new key can't be activated. |

## Where customers enter the key

- **Setup screen** (first run): license key field next to the setup code. The admin address must be on a covered domain.
- **Admin console → License**: status, covered domains, *Check now*, replace key.
- **CLI**: `docker compose exec web zoltis license activate <KEY>` (also `status`, `refresh`).
- **Environment**: `LICENSE_KEY=` in `.env` (→ `ZOLTIS_LICENSE_KEY`), activated when the server starts.

Stored in the data volume: `license.key`, `license.activation`, `install.id` (random per install, mode 0600).

## Before release (Zoltis)

1. Generate the signing key pair **once**, on a trusted machine:
   `python3 devtools/license_dev.py keygen`
2. Put the **public** key in `zoltis/licensing.py` → `TRUSTED_KEYS = {"k1": "<hex>"}`.
   Keep the **private** key only in the portal's secret store. Never commit it.
   To rotate, add `"k2"` next to `"k1"`, sign new keys with k2, and drop k1 in a later release.
3. Set `DEFAULT_SERVER`, `DEFAULT_REGISTER_URL` and `DEFAULT_UPGRADE_URL` in `zoltis/licensing.py` to the real
   portal URLs. All three are placeholders (`licensing.zoltis.example`) right now. The upgrade page receives
   `?from=community&license=<lid>&domains=<comma list>`, so the Mail Pro sign-up can be linked to the existing customer.

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
 "domains": ["acme.com"], "customer": "Acme Ltd", "email": "it@acme.com",
 "issued": 1795000000, "expires": null}
```

`lid` is the portal's stable license ID. `expires` is a Unix time, or `null` for no expiry. To add a domain, the portal
issues a new key with the same `lid` and the extra domain. The customer pastes it in, and the app releases the old one.

**Activation certificate payload:**

```json
{"v": 1, "kid": "k1", "lid": "lic_8f3a…", "install_id": "ins_…", "status": "active",
 "issued": 1795000000, "valid_until": 1797592000}
```

## Portal API

JSON over HTTPS. The app sends `User-Agent: ZoltisMail/<version>`.

### `POST /v1/activate`

Called when a key is entered, and again every 24 h while the server runs. The renewal uses the same request.

```json
{"license_key": "ZM1.…", "install_id": "ins_…", "app_version": "2.0.0", "hostname": "mail-1"}
```

| Response | Meaning to the app |
|---|---|
| `200 {"activation": "ZM1.…"}` | Activated or renewed. Certificate stored. |
| `4xx {"error": "message shown to the admin", "code": "revoked\|expired\|in_use\|invalid"}` | Refused. The app drops its activation and stops creating accounts. |
| `5xx` / timeout | Temporary. The app keeps the current activation and retries in 15 min. |

Recommended policy (what `devtools/license_dev.py serve` does): verify the key signature, reject revoked or expired
keys, and allow **one active `install_id` per `lid`**. The same install re-activating is always fine. A different
install gets `409 in_use` until the customer releases the old server on the portal.

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

Copying an entire data volume (including `install.id`) clones the install. The domain binding still limits that copy
to the same domains. A patched build that removes the check is a license violation, so pair this with the Community
license terms (see `LICENSE`) for legal protection.
