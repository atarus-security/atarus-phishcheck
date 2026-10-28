"""Rebuild email HTML for a preview that cannot load anything or run anything.

This is an allowlist tokenizer, not a blocklist of regular expressions: the
input is walked once with ``str.find``; only known tags and attributes are
kept, every attribute value is re-escaped, every link and image source is
replaced, and a Content-Security-Policy of ``default-src 'none'`` is placed
in the document so that anything the allowlist misses still cannot fetch.
The report embeds the result in an ``<iframe sandbox="">`` with no
permissions.

Standard library only.
"""
import html as html_lib
from atarus_phishcheck.analyzers.htmlscan import parse_attrs, strip_tags

ALLOWED_TAGS = {
    "a", "abbr", "address", "article", "aside", "b", "big", "blockquote", "body", "br", "caption",
    "center", "cite", "code", "col", "colgroup", "dd", "del", "dfn", "div", "dl", "dt", "em",
    "font", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "html", "i", "img", "ins",
    "kbd", "li", "main", "mark", "nav", "ol", "p", "pre", "q", "s", "samp", "section", "small",
    "span", "strike", "strong", "sub", "sup", "table", "tbody", "td", "tfoot", "th", "thead",
    "tr", "tt", "u", "ul", "var", "wbr",
}
VOID_TAGS = {"br", "hr", "img", "wbr", "col"}
# Dropped together with everything up to their closing tag.
DROP_WITH_CONTENT = {"script", "style", "iframe", "object", "noscript", "template", "svg", "math", "textarea", "title", "xmp", "head", "noembed", "noframes", "embed", "applet", "frameset"}
ALLOWED_ATTRS = {
    "href", "src", "alt", "title", "width", "height", "align", "valign", "bgcolor", "color",
    "border", "cellpadding", "cellspacing", "colspan", "rowspan", "style", "class", "id", "dir",
    "lang", "face", "size", "nowrap", "type", "start", "reversed", "cite", "datetime",
}
SAFE_URL_SCHEMES = ("http:", "https:", "mailto:", "tel:")
STYLE_BLOCKLIST = ("url", "expression", "@", "\\", "<", "&", "/*", "behavior", "binding", "image", "src", "content:", "javascript")
MAX_STYLE_CHARS = 1000

CSP = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
BANNER = '<div style="background:#fef3c7;border:2px solid #d97706;padding:12px 16px;margin-bottom:16px;font-family:system-ui,sans-serif;font-size:12px;color:#78350f;border-radius:6px;"><strong>atarus-phishcheck preview:</strong> only allowlisted tags and attributes are kept, scripts and style sheets are removed, images and remote resources are blocked, every link is disabled. Each link keeps its original destination in data-original-href.</div>'


def sanitize_html_for_preview(html: str) -> str:
    """Return a self-contained HTML document safe to place in an iframe srcdoc."""
    if not html:
        return ""
    return '<!DOCTYPE html><html><head><meta charset="utf-8">' + CSP + '</head><body>' + BANNER + _rebuild(html) + '</body></html>'


def _rebuild(html: str) -> str:
    out = []
    pos = 0
    n = len(html)
    lower = html.lower()
    while pos < n:
        lt = html.find("<", pos)
        if lt == -1:
            out.append(html[pos:])
            break
        out.append(html[pos:lt])
        if html.startswith("<!--", lt):
            end = html.find("-->", lt + 4)
            pos = n if end == -1 else end + 3
            continue
        if lt + 1 < n and html[lt + 1] in "!?":
            end = html.find(">", lt)
            pos = n if end == -1 else end + 1
            continue
        gt = _tag_end(html, lt)
        if gt == -1:
            out.append("&lt;")
            pos = lt + 1
            continue
        inner = html[lt + 1:gt]
        closing = inner.startswith("/")
        i = 1 if closing else 0
        start = i
        while i < len(inner) and (inner[i].isalnum() or inner[i] in ":-"):
            i += 1
        if i == start or not inner[start].isalpha():
            out.append("&lt;")
            pos = lt + 1
            continue
        name = inner[start:i].lower()
        pos = gt + 1

        if name in DROP_WITH_CONTENT and not closing:
            close = lower.find("</" + name, pos)
            if close == -1:
                break
            close_gt = html.find(">", close)
            pos = n if close_gt == -1 else close_gt + 1
            continue
        if name not in ALLOWED_TAGS:
            continue
        if closing:
            if name not in VOID_TAGS:
                out.append(f"</{name}>")
            continue
        out.append(_rebuild_tag(name, inner[i:]))
    return "".join(out)


def _tag_end(html: str, lt: int) -> int:
    """Index of the ``>`` that ends the tag starting at lt, honouring quotes."""
    i = lt + 1
    n = len(html)
    quote = None
    while i < n:
        ch = html[i]
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == ">":
            return i
        elif ch == "<":
            return -1
        i += 1
    return -1


def _rebuild_tag(name: str, attrs_text: str) -> str:
    parts = [f"<{name}"]
    for key, value in parse_attrs(attrs_text):
        if key.startswith("on") or key not in ALLOWED_ATTRS:
            continue
        if value is None:
            value = ""
        value = value.strip()
        if key == "href":
            parts.append(' href="#link-blocked" data-original-href="%s"' % html_lib.escape(_describe_url(value), quote=True))
            continue
        if key == "src":
            parts.append(' src="#blocked-image" data-original-image="%s"' % html_lib.escape(_describe_url(value), quote=True))
            continue
        if key == "style":
            if not _style_is_plain(value):
                continue
        if key == "type" and name not in ("ol", "ul", "li"):
            continue
        parts.append(' %s="%s"' % (key, html_lib.escape(value[:2048], quote=True)))
    parts.append(">")
    return "".join(parts)


def _describe_url(value: str) -> str:
    """The original URL if its scheme is one a browser would open as a page, else a note."""
    compact = "".join(ch for ch in value if ch.isprintable() and not ch.isspace()).lower()
    if not compact:
        return "(empty)"
    if compact.startswith(SAFE_URL_SCHEMES) or compact.startswith(("/", "#", "?")) or ":" not in compact.split("/")[0]:
        return value[:2048]
    scheme = compact.split(":", 1)[0]
    return f"(blocked: {scheme[:20]} scheme)"


def _style_is_plain(value: str) -> bool:
    if len(value) > MAX_STYLE_CHARS:
        return False
    compact = "".join(value.lower().split())
    return not any(marker in compact for marker in STYLE_BLOCKLIST)


def has_renderable_html(html: str) -> bool:
    if not html:
        return False
    stripped = strip_tags(html).strip()
    lower = html.lower()
    return len(stripped) > 20 or ("<img" in lower or "<table" in lower)
