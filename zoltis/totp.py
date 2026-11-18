"""Two-step verification helpers: TOTP (RFC 6238), recovery codes and app passwords.

Standard library only. Works with any authenticator app (Google Authenticator,
Microsoft Authenticator, Authy, 1Password, Bitwarden, ...).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DIGITS = 6
PERIOD = 30


def new_secret() -> str:
    """160-bit secret, base32 without padding (what authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _code(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    n = struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF
    return str(n % 10 ** DIGITS).zfill(DIGITS)


def now_code(secret: str, at: float | None = None) -> str:
    return _code(secret, int((time.time() if at is None else at) // PERIOD))


def verify(secret: str, code: str, last_counter: int = -1, window: int = 1, at: float | None = None) -> int | None:
    """Check a 6-digit code, allowing `window` steps of clock drift either way.

    Returns the matching time step (store it and pass it back as `last_counter` so the
    same code can't be used twice), or None when the code is wrong or already used.
    """
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if not secret or len(code) != DIGITS:
        return None
    now = int((time.time() if at is None else at) // PERIOD)
    for step in range(now - window, now + window + 1):
        if step > last_counter and hmac.compare_digest(_code(secret, step), code):
            return step
    return None


def otpauth_uri(secret: str, account: str, issuer: str) -> str:
    label = quote(f"{issuer}:{account}", safe="@:")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={PERIOD}"


# ---------------------------------------------------------------- recovery codes
_RC_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"   # no 0/o, 1/l/i


def new_recovery_codes(n: int = 10) -> list[str]:
    return ["-".join("".join(secrets.choice(_RC_ALPHABET) for _ in range(5)) for _ in range(2)) for _ in range(n)]


def normalize_recovery(code: str) -> str:
    c = "".join(ch for ch in str(code or "").lower() if ch.isalnum())
    return f"{c[:5]}-{c[5:]}" if len(c) == 10 else ""


def hash_recovery(code: str) -> str:
    return hashlib.sha256(normalize_recovery(code).encode()).hexdigest()


# ---------------------------------------------------------------- app passwords
def new_app_password() -> str:
    """16 lowercase letters in groups of four (about 75 bits), easy to type on a phone."""
    letters = "abcdefghijkmnopqrstuvwxyz"
    return "-".join("".join(secrets.choice(letters) for _ in range(4)) for _ in range(4))
