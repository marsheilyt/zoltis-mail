# Connecting the Zoltis Mail app

The Zoltis Mail phone/desktop app isn't built yet. The server is ready for it: the app uses the same
JSON API as the webmail, with a bearer token instead of a cookie.

## 1. Find the server

```
GET https://webmail.example.com/.well-known/zoltis-mail.json      (same as GET /api/client)
```

Returns the API version, the sign-in endpoints, whether 2-step verification and app passwords are
available, and (bundled mail server) the IMAP/SMTP host and ports:

```json
{"service": "zoltis-mail", "api_version": 1, "version": "2.3.0", "app_name": "Zoltis Mail",
 "auth": {"login": "/api/login", "two_factor": "/api/login/2fa", "logout": "/api/logout",
          "scheme": "Bearer", "login_body": {"client": "app"}, "csrf_header": {"X-Zoltis": "1"},
          "token_lifetime_seconds": 43200},
 "features": {"two_factor": true, "app_passwords": true},
 "imap": {"host": "mail.example.com", "port": 993, "security": "ssl"},
 "smtp": {"host": "mail.example.com", "port": 587, "security": "starttls", "alt_port": 465, "alt_security": "ssl"}}
```

## 2. Sign in

Every request that isn't a GET must send `X-Zoltis: 1`.

```
POST /api/login        {"email": "ann@example.com", "password": "…", "client": "app"}
→ 200 {"ok": true, "email": "…", "token": "…", "token_type": "Bearer", "expires_in": 43200}
```

When 2-step verification is on, the first answer is `{"twofa_required": true, "ticket": "…"}`. Ask for the
6-digit code (or a recovery code) within 5 minutes:

```
POST /api/login/2fa    {"ticket": "…", "code": "123456"}
→ 200 {"ok": true, "token": "…", …}
```

Then send `Authorization: Bearer <token>` on every request (`/api/me`, `/api/folders`, `/api/messages`,
`/api/message`, `/api/send`, …, the same endpoints the webmail uses). `POST /api/logout` ends the token.
A `401` means the token expired or the server restarted: sign in again.

## Notes for building the app

- Tokens live in the web server's memory for `session_hours` (default 12). Long-lived device tokens
  (stay signed in for weeks, survive a restart) and push notifications are not built yet. Add them
  together with the app.
- Never store the user's password on the device. Keep only the token, in the iOS Keychain / Android Keystore.
- If the app talks IMAP/SMTP directly instead of using the API, an account with 2-step verification
  must use an **app password** (Settings → Security). The normal password only works through the webmail.
