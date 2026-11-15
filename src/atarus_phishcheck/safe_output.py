"""Make attacker-controlled text safe to print on a terminal.

Standard library only.
"""
import copy
import dataclasses
import unicodedata

_KEEP = {"\n", "\t"}
_ESC = "\x1b"


def safe_text(value, limit: int = 300) -> str:
    """Strip terminal escape sequences, control characters and format
    characters (bidi overrides, zero-width joiners) from text taken from the
    email before it is printed. Truncates to ``limit`` characters."""
    text = "" if value is None else str(value)
    full_length = len(text)
    # Look at no more of a long value than can be shown: a 20 MB Subject
    # must not take seconds to print 300 characters of.
    text = text[:limit * 8 + 4096]
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == _ESC:
            i = _skip_escape(text, i)
            continue
        if ch in _KEEP:
            out.append(ch)
        else:
            cat = unicodedata.category(ch)
            if cat not in ("Cc", "Cf", "Cs", "Co", "Cn") and ch not in ("\u2028", "\u2029"):
                out.append(ch)
        i += 1
    cleaned = "".join(out)
    if len(cleaned) > limit or n < full_length:
        cleaned = cleaned[:limit] + "..."
    return cleaned


_HIDDEN_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Cn")


def _hidden(ch: str) -> bool:
    return ch not in _KEEP and (unicodedata.category(ch) in _HIDDEN_CATEGORIES or ch in ("\u2028", "\u2029"))


def visible_text(value) -> str:
    """Text for an HTML page with every control, format, surrogate, private
    use and unassigned character (escape sequences, bidi overrides,
    zero-width marks, NUL) written as a visible ``[U+XXXX]`` instead, so
    that 'photo<U+202E>gpj.exe' cannot display as 'photoexe.jpg'. Nothing is
    removed or cut; HTML escaping is still the template's job. Linear."""
    text = "" if value is None else str(value)
    if text.isascii() and text.isprintable():
        return text
    return "".join(f"[U+{ord(ch):04X}]" if _hidden(ch) else ch for ch in text)


def visible_copy(result):
    """A display copy (``display_copy``) with every string in it, at any
    depth, passed through ``visible_text``: the one sanitizer for HTML.
    The parsed body is left out: reports show findings and headers, and the
    preview is sanitized separately."""
    out = display_copy(result)
    out.body = None
    return _visible(out)


def _visible(obj):
    if isinstance(obj, str):
        return visible_text(obj)
    if isinstance(obj, (list, tuple)):
        return type(obj)(_visible(v) for v in obj)
    if isinstance(obj, dict):
        return {_visible(k): _visible(v) for k, v in obj.items()}
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.replace(obj, **{f.name: _visible(getattr(obj, f.name)) for f in dataclasses.fields(obj) if f.init})
    return obj


DISPLAY_CHARS = 4096  # longest value a report shows; detection always reads the whole value


def shown(value, limit: int = DISPLAY_CHARS):
    """A value cut for display, with the cut marked, or the value itself."""
    if not isinstance(value, str) or len(value) <= limit:
        return value
    return value[:limit] + f" [shown cut at {limit:,} of {len(value):,} characters; all of it was analysed]"


def display_copy(result):
    """A copy of an AnalysisResult for the report writers, every text field
    taken from the email cut to DISPLAY_CHARS with the cut marked. The
    analysis itself always runs on the full values."""
    out = copy.copy(result)
    if result.headers is not None:
        out.headers = _shown_fields(result.headers)
        out.headers.received_chain = [shown(r) for r in result.headers.received_chain]
        out.headers.from_addresses = [shown(a) for a in result.headers.from_addresses]
    out.findings = [_shown_fields(f) for f in result.findings]
    out.indicators = [_shown_fields(i) for i in result.indicators]
    out.checks_not_run = [_shown_fields(c) for c in result.checks_not_run]
    return out


def _shown_fields(obj):
    changes = {f.name: shown(getattr(obj, f.name)) for f in dataclasses.fields(obj) if isinstance(getattr(obj, f.name), str)}
    return dataclasses.replace(obj, **changes)


def _skip_escape(text: str, i: int) -> int:
    """Index just past the escape sequence starting at text[i] (an ESC byte)."""
    n = len(text)
    j = i + 1
    if j >= n:
        return n
    lead = text[j]
    if lead == "[":  # CSI: parameters and intermediates, then a final byte 0x40 to 0x7E
        j += 1
        while j < n and not ("@" <= text[j] <= "~"):
            j += 1
        return min(j + 1, n)
    if lead in "]PX^_":  # OSC and string sequences end with BEL or ESC backslash
        j += 1
        while j < n:
            if text[j] == "\x07":
                return j + 1
            if text[j] == _ESC and j + 1 < n and text[j + 1] == "\\":
                return j + 2
            j += 1
        return n
    return j + 1  # two-character escape
