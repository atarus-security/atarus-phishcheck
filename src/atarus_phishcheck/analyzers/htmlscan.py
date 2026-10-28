"""Linear-time helpers for looking at hostile HTML.

These replace regular expressions of the shape ``<[^>]+>`` and
``<a[^>]+href=...[^>]*>([^<]+)</a>`` whose backtracking grew quadratically
or worse on crafted input. Every function here walks the text with
``str.find`` so each character is visited a bounded number of times.

Standard library only.
"""
import bisect

_WS = " \t\r\n\f"


def strip_tags(html: str) -> str:
    """Return the text content with tags removed and whitespace collapsed."""
    if not html:
        return ""
    parts = []
    pos = 0
    n = len(html)
    while pos < n:
        lt = html.find("<", pos)
        if lt == -1:
            parts.append(html[pos:])
            break
        parts.append(html[pos:lt])
        gt = html.find(">", lt + 1)
        if gt == -1:
            # unclosed tag: keep the rest as text, minus the bracket
            parts.append(html[lt + 1:])
            break
        pos = gt + 1
    return " ".join("".join(parts).split())


def parse_attrs(attrs: str) -> list:
    """Parse the attribute part of a tag into [(name_lower, value_or_None), ...]."""
    out = []
    i = 0
    n = len(attrs)
    while i < n:
        while i < n and attrs[i] in _WS or (i < n and attrs[i] == "/"):
            i += 1
        if i >= n:
            break
        start = i
        while i < n and attrs[i] not in _WS and attrs[i] not in "=/>":
            i += 1
        name = attrs[start:i].lower()
        if not name:
            i += 1
            continue
        while i < n and attrs[i] in _WS:
            i += 1
        value = None
        if i < n and attrs[i] == "=":
            i += 1
            while i < n and attrs[i] in _WS:
                i += 1
            if i < n and attrs[i] in "\"'":
                quote = attrs[i]
                end = attrs.find(quote, i + 1)
                if end == -1:
                    value = attrs[i + 1:]
                    i = n
                else:
                    value = attrs[i + 1:end]
                    i = end + 1
            else:
                start = i
                while i < n and attrs[i] not in _WS:
                    i += 1
                value = attrs[start:i]
        out.append((name, value))
    return out


def attr_value(attrs, name: str):
    """First value of attribute ``name`` from a parsed list or raw string, else None."""
    if isinstance(attrs, str):
        attrs = parse_attrs(attrs)
    for k, v in attrs:
        if k == name:
            return v
    return None


def iter_tags(html: str):
    """Yield (name_lower, attrs_string, start_index, end_index) for each tag.

    end_index is the index of the closing ``>``. Comments and declarations
    are skipped. Closing tags are yielded with a leading ``/`` in the name.
    """
    pos = 0
    n = len(html)
    while pos < n:
        lt = html.find("<", pos)
        if lt == -1:
            return
        if html.startswith("<!--", lt):
            end = html.find("-->", lt + 4)
            pos = n if end == -1 else end + 3
            continue
        gt = html.find(">", lt + 1)
        if gt == -1:
            return
        inner = html[lt + 1:gt]
        pos = gt + 1
        i = 0
        closing = inner.startswith("/")
        if closing:
            i = 1
        start = i
        while i < len(inner) and (inner[i].isalnum() or inner[i] in ":-"):
            i += 1
        if i == start or not inner[start].isalpha():
            continue
        name = inner[start:i].lower()
        yield ("/" + name if closing else name), inner[i:], lt, gt


def iter_anchors(html: str):
    """Yield (href_or_None, inner_html) for each ``<a ...>...</a>``.

    Positions of every ``</a`` are collected once so that anchors without a
    matching close tag cannot make the scan quadratic.
    """
    lower = html.lower()
    closes = []
    pos = 0
    while True:
        c = lower.find("</a", pos)
        if c == -1:
            break
        closes.append(c)
        pos = c + 3
    if not closes:
        return
    for name, attrs, start, end in iter_tags(html):
        if name != "a":
            continue
        idx = bisect.bisect_right(closes, end)
        if idx >= len(closes):
            return
        close = closes[idx]
        yield attr_value(attrs, "href"), html[end + 1:close]
