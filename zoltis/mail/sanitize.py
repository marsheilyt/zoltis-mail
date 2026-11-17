"""Allow-list HTML sanitizer for displaying untrusted email HTML.

Defence in depth: the client also renders the result inside an
<iframe sandbox> with a restrictive CSP, so scripts can never run even if
something slips past this filter.
"""

from __future__ import annotations

import html
import re
from html.parser import HTMLParser

ALLOWED_TAGS = {
    "a", "abbr", "address", "b", "big", "blockquote", "br", "caption", "center",
    "cite", "code", "col", "colgroup", "dd", "del", "div", "dl", "dt", "em", "font",
    "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "ins", "kbd", "li", "ol",
    "p", "pre", "q", "s", "small", "span", "strike", "strong", "sub", "sup",
    "table", "tbody", "td", "tfoot", "th", "thead", "tr", "tt", "u", "ul",
    "style", "html", "head", "body", "meta", "title", "section", "article",
    "header", "footer", "main", "figure", "figcaption", "picture", "label",
}
# Tags whose *content* must be dropped entirely.
DROP_CONTENT = {"script", "iframe", "object", "embed", "applet", "noscript",
                "frame", "frameset", "form", "button", "input", "select",
                "textarea", "svg", "math", "template", "base", "link"}
VOID = {"br", "hr", "img", "col", "meta"}
ALLOWED_ATTRS = {
    "align", "alt", "bgcolor", "border", "cellpadding", "cellspacing", "class",
    "color", "colspan", "dir", "face", "height", "href", "hspace", "lang", "name",
    "rowspan", "size", "src", "style", "summary", "title", "valign", "vspace",
    "width", "start", "type", "id", "role", "charset", "content",
}
SAFE_URL = re.compile(r"^(https?:|mailto:|tel:|cid:|#|/api/)", re.I)
CSS_BAD = re.compile(r"expression\s*\(|javascript:|behavior\s*:|-moz-binding|@import", re.I)
CSS_URL = re.compile(r"url\s*\(\s*['\"]?\s*(https?:[^)'\"]*)['\"]?\s*\)", re.I)


class _Sanitizer(HTMLParser):
    def __init__(self, cid_map: dict, allow_remote: bool):
        super().__init__(convert_charrefs=False)
        self.out: list[str] = []
        self.drop_depth = 0
        self.cid_map = cid_map
        self.allow_remote = allow_remote
        self.blocked = 0
        self.in_style = False

    # -- helpers -----------------------------------------------------------
    def _css(self, css: str) -> str:
        if CSS_BAD.search(css):
            return ""
        if not self.allow_remote:
            def repl(m):
                self.blocked += 1
                return "none"
            css = CSS_URL.sub(repl, css)
        return css

    def _attrs(self, tag, attrs):
        res = []
        for k, v in attrs:
            k = k.lower()
            if k.startswith("on") or k not in ALLOWED_ATTRS:
                continue
            v = v or ""
            if k == "style":
                v = self._css(v)
            if k in ("href", "src"):
                vs = v.strip()
                if not SAFE_URL.match(vs):
                    continue
                if vs.lower().startswith("cid:"):
                    url = self.cid_map.get(vs[4:].strip("<>"))
                    if not url:
                        continue
                    v = url
                elif k == "src" and tag == "img" and vs.lower().startswith("http") and not self.allow_remote:
                    self.blocked += 1
                    res.append(("data-zoltis-src", vs))
                    continue
            if tag == "meta" and k not in ("charset",):
                continue
            res.append((k, v))
        if tag == "a":
            res = [(k, v) for k, v in res if k not in ("target", "rel")]
            res += [("target", "_blank"), ("rel", "noopener noreferrer nofollow")]
        return "".join(f' {k}="{html.escape(v, quote=True)}"' for k, v in res)

    # -- parser callbacks --------------------------------------------------
    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in DROP_CONTENT:
            if tag not in VOID:
                self.drop_depth += 1
            return
        if self.drop_depth or tag not in ALLOWED_TAGS:
            return
        if tag == "style":
            self.in_style = True
        self.out.append(f"<{tag}{self._attrs(tag, attrs)}>")

    def handle_startendtag(self, tag, attrs):
        tag = tag.lower()
        if self.drop_depth or tag not in ALLOWED_TAGS:
            return
        self.out.append(f"<{tag}{self._attrs(tag, attrs)}>")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in DROP_CONTENT:
            self.drop_depth = max(0, self.drop_depth - 1)
            return
        if self.drop_depth or tag not in ALLOWED_TAGS or tag in VOID:
            return
        if tag == "style":
            self.in_style = False
        self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if self.drop_depth:
            return
        if self.in_style:
            self.out.append(self._css(data).replace("</", "<\\/"))
        else:
            self.out.append(html.escape(data, quote=False))

    def handle_entityref(self, name):
        if not self.drop_depth:
            self.out.append(f"&{name};")

    def handle_charref(self, name):
        if not self.drop_depth:
            self.out.append(f"&#{name};")

    def handle_comment(self, data):
        pass


def sanitize_html(src: str, cid_map: dict | None = None, allow_remote: bool = False):
    """Return (clean_html, blocked_remote_count)."""
    p = _Sanitizer(cid_map or {}, allow_remote)
    try:
        p.feed(src)
        p.close()
    except Exception:
        return html.escape(src), 0
    return "".join(p.out), p.blocked


URL_RE = re.compile(r"(https?://[^\s<>\"']+)")


def text_to_html(text: str) -> str:
    esc = html.escape(text)
    esc = URL_RE.sub(r'<a href="\1" target="_blank" rel="noopener noreferrer nofollow">\1</a>', esc)
    return f'<div style="white-space:pre-wrap;font-family:inherit">{esc}</div>'


TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")


BLOCK_END = re.compile(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</h\d>|</li>|</blockquote>|</table>")
LINK_RE = re.compile(r'(?is)<a\s[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>')


def html_to_text(src: str) -> str:
    """Readable plain-text alternative (used for the text/plain MIME part and previews)."""
    src = re.sub(r"(?is)<(style|script|head|title)[^>]*>.*?</\1>", "", src)
    src = re.sub(r"(?is)<!--.*?-->", "", src)

    def link(m):
        text = TAG_RE.sub("", m.group(2)).strip()
        url = html.unescape(m.group(1))
        return url if not text or text == url else f"{text} ({url})"

    src = LINK_RE.sub(link, src)
    src = re.sub(r"(?i)<li[^>]*>", "\n* ", src)
    src = BLOCK_END.sub("\n", src)
    src = re.sub(r"(?i)<(p|div|tr|h\d|table|blockquote)[^>]*>", "\n", src)
    src = re.sub(r"(?i)</t[dh]>", "\t", src)
    text = html.unescape(TAG_RE.sub("", src)).replace("\xa0", " ")
    lines = [re.sub(r"[ \t]+", " ", l).strip() for l in text.splitlines()]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def snippet(text: str, n: int = 160) -> str:
    # Drop quoted replies for a cleaner preview.
    lines = [l for l in text.splitlines() if not l.lstrip().startswith(">")]
    s = WS_RE.sub(" ", " ".join(lines)).strip()
    return s[:n]
