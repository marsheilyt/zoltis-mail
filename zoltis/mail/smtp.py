"""Message composition and SMTP submission.

Builds standards-correct, deliverability-friendly MIME:
  * Message-ID on the sender's own domain
  * Date, MIME-Version, multipart/alternative (text + HTML)
  * Proper threading headers (In-Reply-To / References) on replies
  * UTF-8 headers encoded per RFC 2047, attachments base64
"""

from __future__ import annotations

import mimetypes
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid, getaddresses

from .imap import MailError, AuthError
from .sanitize import html_to_text, sanitize_html

EMAIL_RE = re.compile(r"^[^@\s<>\"]+@[^@\s<>\"]+\.[^@\s<>\"]+$")


def parse_recipients(value) -> list[str]:
    if isinstance(value, list):
        value = ",".join(value)
    out = []
    for name, addr in getaddresses([value or ""]):
        addr = addr.strip()
        if not addr:
            continue
        if not EMAIL_RE.match(addr):
            raise MailError(f"Invalid email address: {addr}")
        out.append(formataddr((name, addr)) if name else addr)
    return out


def build_message(*, from_name: str, from_email: str, to, cc=None, bcc=None, subject="",
                  html: str = "", text: str | None = None, attachments=None,
                  in_reply_to: str = "", references: str = "", reply_to: str = "", require_recipients: bool = True) -> tuple[EmailMessage, list[str]]:
    to_l, cc_l, bcc_l = parse_recipients(to), parse_recipients(cc), parse_recipients(bcc)
    if require_recipients and not (to_l or cc_l or bcc_l):
        raise MailError("Add at least one recipient")
    msg = EmailMessage()
    msg["From"] = formataddr((from_name, from_email)) if from_name else from_email
    if to_l:
        msg["To"] = ", ".join(to_l)
    if cc_l:
        msg["Cc"] = ", ".join(cc_l)
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = subject or ""
    msg["Date"] = formatdate(localtime=True)
    domain = from_email.rsplit("@", 1)[-1] if "@" in from_email else None
    msg["Message-ID"] = make_msgid(domain=domain)
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = (references + " " + in_reply_to).strip() if in_reply_to not in references else references
    msg["MIME-Version"] = "1.0"
    msg["X-Mailer"] = "Zoltis Mail"

    clean_html, _ = sanitize_html(html or "", allow_remote=True) if html else ("", 0)
    plain = text if text is not None else html_to_text(clean_html)
    plain = re.sub(r"\n{3,}", "\n\n", plain).strip() + "\n"
    msg.set_content(plain, subtype="plain", charset="utf-8")
    if clean_html:
        msg.add_alternative(
            '<!DOCTYPE html><html><head><meta charset="utf-8"></head>'
            f'<body style="font-family:Arial,Helvetica,sans-serif;font-size:14px">{clean_html}</body></html>',
            subtype="html", charset="utf-8")
    for att in attachments or []:
        ctype = att.get("content_type") or mimetypes.guess_type(att["filename"])[0] or "application/octet-stream"
        maintype, _, subtype = ctype.partition("/")
        msg.add_attachment(att["data"], maintype=maintype, subtype=subtype or "octet-stream",
                           filename=att["filename"])
    rcpts = [a for _, a in getaddresses(to_l + cc_l + bcc_l)]
    return msg, rcpts


class SMTPSender:
    def __init__(self, host, port, security, verify_cert, auth, timeout=30):
        self.host, self.port, self.security = host, int(port), security
        self.verify_cert, self.auth, self.timeout = verify_cert, auth, timeout

    def _ctx(self):
        ctx = ssl.create_default_context()
        if not self.verify_cert:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def send(self, user, password, msg: EmailMessage, rcpts: list[str]):
        try:
            if self.security == "ssl":
                s = smtplib.SMTP_SSL(self.host, self.port, context=self._ctx(), timeout=self.timeout)
            else:
                s = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
                s.ehlo()
                if self.security == "starttls":
                    s.starttls(context=self._ctx())
                    s.ehlo()
            with s:
                if self.auth:
                    try:
                        s.login(user, password)
                    except smtplib.SMTPAuthenticationError as e:
                        raise AuthError("SMTP server rejected your login") from e
                refused = s.send_message(msg, from_addr=_bare(msg["From"]), to_addrs=rcpts)
                return {a: (m.decode(errors="replace") if isinstance(m, bytes) else str(m)) for a, (c, m) in (refused or {}).items()}
        except smtplib.SMTPRecipientsRefused as e:
            parts = []
            for addr, (code, msg) in e.recipients.items():
                why = msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)
                why = why.split(" ", 1)[1] if re.match(r"^\d\.\d\.\d+ ", why) else why
                parts.append(f"{addr} ({why})")
            raise MailError("Couldn't deliver to " + "; ".join(parts)) from e
        except smtplib.SMTPSenderRefused as e:
            raise MailError(f"Sender refused by server: {e.smtp_error.decode(errors='replace')}") from e
        except smtplib.SMTPException as e:
            raise MailError(f"Sending failed: {e}") from e
        except OSError as e:
            raise MailError(f"Cannot reach SMTP server {self.host}:{self.port} ({e})") from e


def _bare(addr: str) -> str:
    return getaddresses([addr])[0][1]
