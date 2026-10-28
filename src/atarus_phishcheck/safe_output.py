"""Make attacker-controlled text safe to print on a terminal.

Standard library only.
"""
import unicodedata

_KEEP = {"\n", "\t"}
_ESC = "\x1b"


def safe_text(value, limit: int = 300) -> str:
    """Strip terminal escape sequences, control characters and format
    characters (bidi overrides, zero-width joiners) from text taken from the
    email before it is printed. Truncates to ``limit`` characters."""
    text = "" if value is None else str(value)
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
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + "..."
    return cleaned


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
