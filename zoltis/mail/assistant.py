"""Mail assistant: inbox categories and message summaries. Pure Python, no AI service, no models.

Categories (Gmail-style tabs) come from signals every mail carries anyway: mailing-list headers
(List-Id, List-Unsubscribe, List-Post), bulk/auto-reply markers (Precedence, Auto-Submitted), the
sending service, the sender's address ("noreply@", "news@"), well-known social networks, and words
in the subject. People you have written to always land in Primary, and a message you move to another
tab teaches the inbox where that sender belongs.

Summaries are extractive: the most informative sentences of the message (word-frequency scoring,
like classic "auto-summarize"), plus facts pulled out with patterns: dates and times, amounts,
deadlines, codes, questions asked of you, links and attachments. Nothing leaves the server.
"""

from __future__ import annotations

import re
from collections import Counter

CATEGORIES = ("primary", "updates", "promotions", "social", "forums")
KEYWORD_PREFIX = "$zc-"          # stored on each message as an IMAP keyword, e.g. $zc-promotions
CATEGORY_HEADERS = ("FROM", "SUBJECT", "LIST-ID", "LIST-UNSUBSCRIBE", "LIST-POST", "PRECEDENCE",
                    "AUTO-SUBMITTED", "X-AUTO-RESPONSE-SUPPRESS", "FEEDBACK-ID", "X-MAILER", "X-CAMPAIGN",
                    "X-MAILGUN-TAG", "X-SES-OUTGOING", "X-SFMC-STACK", "X-CSA-COMPLAINTS", "X-DISCOURSE-POST-ID",
                    "X-GITHUB-REASON", "X-FACEBOOK-NOTIFY", "X-LINKEDIN-CLASS")


def keyword(cat: str) -> str:
    return KEYWORD_PREFIX + cat


SOCIAL_DOMAINS = {
    "facebookmail.com", "facebook.com", "linkedin.com", "twitter.com", "x.com", "instagram.com", "tiktok.com",
    "pinterest.com", "snapchat.com", "youtube.com", "whatsapp.com", "telegram.org", "threads.net", "discord.com",
    "tumblr.com", "vk.com", "meetup.com", "nextdoor.com", "strava.com", "bsky.app", "mastodon.social", "quora.com",
}
FORUM_DOMAINS = {"googlegroups.com", "groups.io", "freelists.org", "lists.sourceforge.net", "discoursemail.com",
                 "redditmail.com", "stackexchange.com"}
BULK_SENDERS = ("mailchimp", "mcsv.net", "mcdlv.net", "sendgrid", "klaviyo", "hubspot", "hs-email", "constantcontact",
                "campaign-archive", "sendinblue", "brevo", "mailerlite", "mailjet", "exacttarget", "salesforce",
                "marketo", "mktomail", "braze", "iterable", "customer.io", "omnisend", "activecampaign", "convertkit",
                "substack", "beehiiv", "emarsys", "responsys", "cmail", "createsend")
PROMO_LOCALS = re.compile(r"^(news|newsletter|newsletters|offers?|deals?|promo|promotions?|marketing|sales|shop|store|"
                          r"hello|hi|team|info|members?|rewards?|vip|specials?|subscribers?)([._+-]|$)")
UPDATE_LOCALS = re.compile(r"^(no-?reply|do-?not-?reply|donotreply|notifications?|notify|alerts?|updates?|"
                           r"billing|invoices?|receipts?|orders?|accounts?|security|support|service|system|"
                           r"mailer-daemon|postmaster|calendar|bounce)([._+-]|$)")
# Sender names that on their own say what kind of mail it is (count double)
STRONG_PROMO = re.compile(r"^(news|newsletters?|offers?|deals?|promo|promotions?|marketing)([._+-]|$)")
STRONG_UPDATE = re.compile(r"^(no-?reply|do-?not-?reply|donotreply|notifications?|notify|alerts?|mailer-daemon)([._+-]|$)")
PROMO_WORDS = re.compile(r"(\d+\s?% off|\bsale\b|\bdeals?\b|discount|coupon|promo ?code|\boffer\b|free shipping|"
                         r"limited time|last chance|ends (today|tonight|soon)|black friday|cyber monday|"
                         r"new arrivals|shop now|save (up to|\$|€|£)|exclusive|flash sale|clearance|"
                         r"% de r[ée]duction|angebot|oferta)", re.I)
UPDATE_WORDS = re.compile(r"(receipt|invoice|your order|order (confirmation|#|number)|has shipped|shipped|"
                          r"out for delivery|delivered|tracking|statement|payment (received|due|failed|confirmation)|"
                          r"verification code|one-time (code|password)|security (alert|code)|sign-?in (attempt|alert)|"
                          r"password (reset|changed)|confirm your|booking|reservation|itinerary|e-?ticket|"
                          r"appointment|subscription|renewal|your account|bill is ready|reminder)", re.I)


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def _in(domain: str, names) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in names)


def classify(h: dict, known_contact: bool = False, override: str | None = None) -> str:
    """h: lower-case header name -> value (FROM must hold the plain address). Returns a category."""
    if override in CATEGORIES:
        return override
    if known_contact:
        return "primary"
    frm = (h.get("from") or "").lower()
    dom, local = _domain(frm), frm.split("@", 1)[0]
    subj = h.get("subject") or ""
    blob = " ".join(str(h.get(k, "")) for k in ("x-mailer", "feedback-id", "list-unsubscribe", "list-id")).lower()

    if _in(dom, SOCIAL_DOMAINS) or h.get("x-facebook-notify") or h.get("x-linkedin-class"):
        return "social"
    if _in(dom, FORUM_DOMAINS) or h.get("x-discourse-post-id") or (h.get("list-post") and h.get("list-id")):
        return "forums"
    if h.get("x-github-reason"):
        return "updates"

    bulk = bool(h.get("list-unsubscribe")) or (h.get("precedence") or "").lower() in ("bulk", "list") \
        or any(s in blob or s in dom for s in BULK_SENDERS) or bool(h.get("x-campaign") or h.get("x-sfmc-stack")
                                                                    or h.get("x-csa-complaints") or h.get("x-mailgun-tag"))
    auto = (h.get("auto-submitted") or "no").lower() != "no" or bool(h.get("x-auto-response-suppress"))
    promo = 2 * bool(PROMO_WORDS.search(subj)) + bool(PROMO_LOCALS.match(local)) + bool(STRONG_PROMO.match(local)) + bulk
    update = 2 * bool(UPDATE_WORDS.search(subj)) + bool(UPDATE_LOCALS.match(local)) + bool(STRONG_UPDATE.match(local)) + auto
    if promo >= 2 and promo > update:
        return "promotions"
    if update >= 2 or (update and not bulk):
        return "updates"
    if bulk:
        return "promotions"
    return "primary"


# --------------------------------------------------------------------------- summaries
STOP = set("""a about above after again against all am an and any are as at be because been before being below
between both but by can could did do does doing down during each few for from further had has have having he her
here hers herself him himself his how i if in into is it its itself just let me more most my myself no nor not of
off on once only or other our ours ourselves out over own same she should so some such than that the their theirs
them themselves then there these they this those through to too under until up very was we were what when where
which while who whom why will with would you your yours yourself yourselves also get got please thanks thank hi
hello dear regards best kind sent re fw fwd am pm via us one two may might must shall can't don't i'm it's we're
you're i've we've let's""".split())
SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(])|\n{2,}")
WORD = re.compile(r"[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ'-]+")
QUOTE_START = re.compile(r"^(On .{5,200} wrote:|-{2,}\s*Original Message\s*-{2,}|From: .+|Le .+ a écrit\s?:|Am .+ schrieb .+:)$",
                         re.I)
SIG_START = re.compile(r"^(--\s*|Sent from my .+|Get Outlook for .+|Best regards,?|Kind regards,?|Regards,?|Thanks,?|"
                       r"Thank you,?|Cheers,?|Sincerely,?)$", re.I)
MONTHS = r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
NUM = r"(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d{1,2})?"
DAYS = r"(?:mon|tues?|wed(?:nes)?|thu(?:rs)?|fri|sat(?:ur)?|sun)(?:day)?"
FACT_PATTERNS = [
    ("date", re.compile(rf"\b(?:{DAYS},?\s+)?(?:\d{{1,2}}(?:st|nd|rd|th)?\s+{MONTHS}(?:,?\s+\d{{4}})?|{MONTHS}\s+\d{{1,2}}(?:st|nd|rd|th)?(?:,?\s+\d{{4}})?)\b"
                        rf"|\b\d{{4}}-\d{{2}}-\d{{2}}\b|\b\d{{1,2}}/\d{{1,2}}/\d{{2,4}}\b|\b(?:today|tomorrow|tonight|next {DAYS}|this {DAYS}|{DAYS})\b", re.I)),
    ("time", re.compile(r"\b\d{1,2}(?::\d{2})?\s?(?:am|pm)\b|\b(?:[01]?\d|2[0-3]):[0-5]\d\b(?:\s?(?:gst|utc|gmt|[ecmp][sd]t|cet|ist))?", re.I)),
    ("amount", re.compile(rf"(?:[$€£₹¥]\s?{NUM}|\b{NUM}\s?(?:usd|aed|eur|gbp|inr|sar|dhs?|dirhams?|dollars|euros)\b|"
                          rf"\b(?:usd|aed|eur|gbp|inr|sar)\s?{NUM})", re.I)),
    ("deadline", re.compile(r"\b(?:by|before|no later than|due(?: on| by)?|deadline(?: is)?|expires?(?: on)?|until)\s+"
                            rf"(?:the\s+)?(?:end of (?:the )?(?:day|week|month)|eod|eow|{DAYS}|tomorrow|today|tonight|"
                            rf"\d{{1,2}}(?:st|nd|rd|th)?(?:\s+{MONTHS})?|{MONTHS}\s+\d{{1,2}}|\d{{1,2}}[:/]\d{{2}}(?:\s?[ap]m)?)", re.I)),
    ("code", re.compile(r"\b(?:code|otp|pin|password)\b[^0-9\n]{0,20}\b(\d{4,8})\b", re.I)),
    ("reference", re.compile(r"\b(?:order|booking|reservation|invoice|ticket|tracking|case|ref(?:erence)?)\s*(?:no\.?|number|#|id)?\s*[:#]?\s*([A-Z0-9-]*\d[A-Z0-9-]*)\b", re.I)),
]
ACTION_WORDS = re.compile(r"\b(please|could you|can you|would you|kindly|let me know|need you to|action required|"
                          r"respond|reply|confirm|approve|review|sign|complete|submit|pay|rsvp|asap|urgent)\b", re.I)


def clean_body(text: str) -> str:
    """The new part of a message: no quoted replies, forwarded headers or signature."""
    out = []
    for line in (text or "").replace("\r", "").split("\n"):
        s = line.strip()
        if s.startswith(">"):
            continue
        if QUOTE_START.match(s):
            break
        if SIG_START.match(s) and len(out) > 2:
            break
        out.append(line.rstrip())
    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()


def _sentences(text: str) -> list[str]:
    flat = re.sub(r"[ \t]+", " ", text)
    flat = re.sub(r"(?<![.!?:\n])\n(?!\n)", " ", flat)        # re-join hard-wrapped lines
    parts = [p.strip(" -•*\t") for p in SENT_SPLIT.split(flat)]
    return [p for p in parts if 20 <= len(p) <= 400 and len(WORD.findall(p)) >= 4 and "http" not in p[:12]]


def _uniq(items, limit):
    seen, out = set(), []
    for x in items:
        k = x.lower()
        if k not in seen:
            seen.add(k)
            out.append(x)
        if len(out) >= limit:
            break
    return out


def summarize(text: str, subject: str = "", attachments: list | None = None, max_sentences: int = 3) -> dict:
    body = clean_body(text)
    words = WORD.findall(body)
    sents = _sentences(body)
    freq = Counter(w.lower() for w in words if w.lower() not in STOP and len(w) > 2)
    subj_words = {w.lower() for w in WORD.findall(subject or "")} - STOP
    top = max(freq.values()) if freq else 1
    scored = []
    for i, s in enumerate(sents):
        ws = [w.lower() for w in WORD.findall(s)]
        if not ws:
            continue
        score = sum(freq.get(w, 0) / top for w in ws if w not in STOP) / (len(ws) ** 0.6)
        score += 0.4 * len(subj_words.intersection(ws)) / max(1, len(subj_words))
        score += 0.35 if i == 0 else 0.15 if i < 3 else 0
        score += 0.25 if ACTION_WORDS.search(s) else 0
        score += 0.2 if any(p.search(s) for k, p in FACT_PATTERNS if k in ("date", "deadline", "amount")) else 0
        scored.append((score, i, s))
    n = 1 if len(words) < 60 else 2 if len(words) < 180 else max_sentences
    best = sorted(sorted(scored, reverse=True)[:n], key=lambda x: x[1])
    summary = [s if len(s) <= 240 else s[:237].rsplit(" ", 1)[0] + "…" for _, _, s in best]

    facts = []
    for kind, pat in FACT_PATTERNS:
        hits = []
        for m in pat.finditer(body):
            v = (m.group(1) if kind in ("code", "reference") and m.groups() else m.group(0)).strip()
            hits.append(v)
        for v in _uniq(hits, 3):
            facts.append({"type": kind, "text": v})
    questions = _uniq([s for s in sents if s.endswith("?") and len(s) < 220], 3)
    links = len(set(re.findall(r"https?://[^\s<>\"')]+", text or "")))
    return {
        "summary": summary,
        "facts": facts,
        "questions": questions,
        "action_needed": bool(questions) or bool(ACTION_WORDS.search(body[:2000])),
        "links": links,
        "attachments": [a.get("filename") for a in (attachments or []) if not a.get("inline")][:5],
        "words": len(words),
        "reading_minutes": max(1, round(len(words) / 230)) if words else 0,
    }


# --------------------------------------------------------------------------- spam safety check
RESTRICTED_EXT = {
    "exe", "com", "scr", "pif", "bat", "cmd", "msi", "msp", "dll", "cpl", "jar", "js", "jse", "vbs", "vbe", "wsf", "wsh",
    "ps1", "psm1", "hta", "lnk", "url", "reg", "inf", "iso", "img", "vhd", "vhdx", "apk", "app", "dmg", "pkg", "sh",
    "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "one", "html", "htm", "svg", "shtml",
    "zip", "rar", "7z", "gz", "tar", "cab", "ace", "arj",
}
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)


def spam_check(html: str, text: str, attachments: list, from_addrs: list) -> dict:
    """What makes this Spam message risky to open: links, restricted or flagged files, a spoofed sender name."""
    urls = set(URL_RE.findall(html or "")) | set(URL_RE.findall(text or ""))
    domains = []
    for u in urls:
        d = u.split("/")[2].split("@")[-1].split(":")[0].lower()
        if d and d not in domains:
            domains.append(d)
    risky = []
    for a in attachments or []:
        name = a.get("filename") or ""
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        pol = a.get("policy") or {}
        if pol.get("verdict") in ("warn", "block"):
            risky.append({"filename": name, "reason": pol.get("summary") or "flagged by the attachment check"})
        elif ext in RESTRICTED_EXT:
            risky.append({"filename": name, "reason": f".{ext} files can run code or hide other files"})
    spoof = None
    f = (from_addrs or [{}])[0]
    shown = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", f.get("name") or "")
    if shown and shown[0].lower() != (f.get("email") or "").lower():
        spoof = f"The sender's name shows {shown[0]} but the message really comes from {f.get('email')}"
    return {"links": len(urls), "link_domains": domains[:6], "risky_attachments": risky,
            "attachments": len([a for a in attachments or [] if not a.get("inline")]), "spoofed_name": spoof}
