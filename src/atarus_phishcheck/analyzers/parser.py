"""Parse raw email bytes into structured headers and body.

How the cost is bounded, and why it is done this way:

- The message is parsed by the standard library feed parser with the
  ``compat32`` policy. That policy stores each header as the raw text and
  parses nothing until asked. The ``default`` policy parses every header it
  hands out with the structured header parser, whose time and memory grow
  faster than linearly with the length of one header: 32,000 RFC 2047
  encoded words in a 450 KB Subject used 7.5 GB. This module never asks the
  library to decode a header or a MIME parameter. It reads the raw values
  and decodes them itself with linear routines (``decode_words``,
  ``_address_list``, ``_params``), so a header is read in full however long
  it is, and nothing is cut before detection runs.
- One rule for every value the checks depend on: a parse that fails or is
  uncertain never produces "nothing". When the strict reading of From,
  Reply-To, Return-Path or a MIME parameter list finds no value, or a value
  other readers may see differently, a lenient reading runs as well, the
  checks run on what it found, and the problem is recorded
  (``EmailHeaders.malformed``, ``attachment["malformed"]``) so that a
  finding adds it to the score. A test compares these readings with the
  standard library's default policy on thousands of variants.
- The parser is fed the bytes exactly as given. Attachment payloads are
  decoded from those bytes, so their hashes match the file.
- The feed parser does work for every MIME part and, for every line, once
  per enclosing multipart. ``_BoundedParse`` counts both from inside the
  parser while it runs and stops it when there are more than MAX_PARTS
  parts, more than MAX_DEPTH levels of nesting, or when lines times nesting
  depth passes MAX_NESTING_WORK. What was read up to that point (the top
  headers and the parts already started) is still analysed, the report says
  what was not and why (``EmailBody.limited``), and the structure itself
  is a high-severity finding.
- Counts kept per part are capped (file names, mailboxes, links); passing
  a cap is recorded so that a finding says so.
- Display is separate from detection: report writers cut long values for
  display (``safe_output.display_copy``) and say so.

The file read is capped at MAX_INPUT_BYTES. Body text is cut at
MAX_PART_CHARS for the content checks, recorded in EmailBody.truncated;
links are taken from all of every text and HTML part, attachments
included.
"""
import binascii
import codecs
import email.policy
import hashlib
import os
import re
from email.feedparser import BytesFeedParser
from email.message import Message
from urllib.parse import unquote_to_bytes, urlsplit
from atarus_phishcheck.models import EmailHeaders, EmailBody

MAX_INPUT_BYTES = 25 * 1024 * 1024  # one email file, attachments included
MAX_HEADER_CHARS = 4096  # display only: longer values are shown cut, and detection reads all of them
MAX_PARTS = 10_000  # MIME parts read; past this the rest of the message is not analysed, and that is a finding
MAX_DEPTH = 100  # MIME nesting levels read; ordinary mail nests a few
MAX_NESTING_WORK = 40_000_000  # lines times enclosing multiparts the library parser may check
MAX_PART_CHARS = 1_000_000  # per text or HTML body part, for the content checks
MAX_EXTRA_CHARS = 1_000_000  # further text and HTML parts together, for the content checks
MAX_URL_CHARS = 2048
MAX_URLS = 500
MAX_RECEIVED = 100
MAX_MAILBOXES = 20  # mailboxes kept from one address header
MAX_NAMES = 20  # distinct file names kept for one part
MAX_PARAM_VALUES = 20  # values kept for one parameter name
MAX_HEADER_TOKENS = 20_000  # words and specials read strictly from one address or MIME header; past it the reading is lenient
_FEED_CHUNK = 64 * 1024

# Only ever applied to one URL token at a time; no nested quantifiers.
_URL_PATTERN = re.compile(r'https?://[^\s<>"\'\)]+|www\.[^\s<>"\'\)]+', re.IGNORECASE)

# One RFC 2047 encoded word. Linear: the charset run is bounded and the
# payload run stops at the first "?" or white space, so no character is
# scanned by more than one attempt beyond the bounded charset part.
_ENCODED_WORD = re.compile(r"=\?([^?\s]{1,64})\?([bBqQ])\?([^?\s]*)\?=")
_LINE_BREAK = re.compile(r"\r\n|\r|\n")
_CONTINUATION = re.compile(r"^([^*]+)\*(\d{1,4})(\*?)$")


class InputRejected(ValueError):
    """The input cannot be analysed at all; the message says why in plain words."""


class InputTooLarge(InputRejected):
    pass


class NotAnEmail(InputRejected):
    pass


_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # Outlook .msg and other compound files


def read_email_file(path: str) -> bytes:
    """Read an email file with the size cap applied before anything is parsed.
    Returns the bytes as stored, apart from a byte order mark."""
    size = os.path.getsize(path)
    if size > MAX_INPUT_BYTES:
        raise InputTooLarge(f"{path} is {size} bytes; the limit is {MAX_INPUT_BYTES} bytes")
    with open(path, "rb") as f:
        data = f.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise InputTooLarge(f"{path} exceeds the {MAX_INPUT_BYTES} byte limit")
    if not data.strip():
        raise NotAnEmail(f"{path} is empty")
    if data.startswith(_OLE_MAGIC):
        raise NotAnEmail(f"{path} is an Outlook .msg or other compound file, not a MIME message; save the email as .eml from the mail client and analyze that")
    return _without_bom(data)


def _without_bom(data: bytes) -> bytes:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace").encode("utf-8")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:]
    return data


def as_bytes(raw) -> bytes:
    """The message as bytes. Text (pasted input, tests) is encoded as UTF-8."""
    if isinstance(raw, (bytes, bytearray)):
        return _without_bom(bytes(raw))
    return raw.lstrip("﻿").encode("utf-8", errors="surrogateescape")


def parse_email(raw) -> tuple:
    """Parse a raw email (bytes, or text for pasted input) into (EmailHeaders, EmailBody).

    A message past the part or nesting limits is not refused: what was read
    is returned and ``EmailBody.limited`` says what was not analysed."""
    data = as_bytes(raw)
    if len(data) > MAX_INPUT_BYTES:
        raise InputTooLarge(f"input exceeds the {MAX_INPUT_BYTES} byte limit")
    data, obsolete = _join_obsolete_field_names(data)
    msg, limited = _BoundedParse(data).run()
    try:
        headers = _extract_headers(msg)
    except RecursionError:
        headers = EmailHeaders()
        limited = limited or _NESTING_TEXT
    headers.malformed[:0] = obsolete
    try:
        body = _extract_body(msg)
    except RecursionError:  # MAX_DEPTH keeps the tree shallow; this is a second guard
        body = EmailBody()
        limited = limited or _NESTING_TEXT
    if limited:
        # The limits bound cost, never what is reported: the bytes the
        # parser did not reach are read by a linear scan that does not
        # depend on the MIME structure, and what it finds is checked too.
        from atarus_phishcheck.analyzers import rawscan
        found = rawscan.scan(data, body.read_digests, _attachment_keys(body))
        rawscan.merge(body, found)
        limited += (". The whole message was then read by a linear scan of its raw bytes (part headers, file names, links, "
                    "base64 and quoted-printable blocks, executable content), and every check ran on what it found as well")
    body.limited = limited
    return headers, body


def _attachment_keys(body) -> set:
    keys = set()
    for att in body.attachments:
        for name in [att.get("filename", "")] + list(att.get("other_names", [])):
            keys.add((name, att.get("sha256", "")))
    return keys


_NESTING_TEXT = ("the MIME structure is nested more deeply than the standard library can walk; the MIME parser read "
                 "only the top-level headers")


# ----- the parser, bounded from inside -----

class _Refused(Exception):
    pass


class _BoundedParse:
    """The standard library feed parser, watched from inside while it runs.

    The parser calls the message factory once per MIME part. The factory
    counts parts and reads the current nesting depth, so the limits are
    applied to the structure the parser itself sees, never to a guess made
    by a separate scan of the text. When a limit is reached the parser is
    stopped and the message read so far (its headers and the parts already
    started) is returned with the reason."""

    def __init__(self, data: bytes):
        self.data = data
        self.lines = data.count(b"\n") + data.count(b"\r") - data.count(b"\r\n") + 1  # CRLF is one line
        self.parts = 0
        self.parser = None
        self.parser = BytesFeedParser(_factory=self._new_part, policy=email.policy.compat32)

    def _new_part(self, policy=None):
        if self.parser is not None:  # the constructor makes one probe call
            self.parts += 1
            if self.parts > MAX_PARTS:
                raise _Refused(f"the message has more than {MAX_PARTS:,} MIME parts. Ordinary mail has a few dozen at most. "
                               f"The MIME parser read the top-level headers and the first {MAX_PARTS:,} parts, and stopped there")
            depth = len(getattr(self.parser, "_msgstack", ())) + 1
            if depth > MAX_DEPTH:
                raise _Refused(f"the message nests MIME parts more than {MAX_DEPTH} levels deep. Ordinary mail nests a few. "
                               f"The MIME parser read the top-level headers and the parts above level {MAX_DEPTH}, and stopped there")
            if depth * self.lines > MAX_NESTING_WORK:
                raise _Refused(f"the message nests MIME parts {depth} deep over {self.lines:,} lines, which would take the standard "
                               f"library parser minutes. Ordinary mail nests a few levels. The MIME parser read the top-level headers and "
                               f"the parts started before level {depth}, and stopped there")
        return _CountedMessage(policy=policy or email.policy.compat32)

    def _partial(self):
        stack = getattr(self.parser, "_msgstack", None)
        if stack:
            return stack[0]
        return getattr(self.parser, "_last", None) or _CountedMessage(policy=email.policy.compat32)

    def run(self) -> tuple:
        """(message, reason the analysis is limited or '')"""
        try:
            for start in range(0, len(self.data), _FEED_CHUNK):
                self.parser.feed(self.data[start:start + _FEED_CHUNK])
            return self.parser.close(), ""
        except _Refused as e:
            return self._partial(), str(e)
        except RecursionError:
            return self._partial(), _NESTING_TEXT


# Headers some check reads. Every other header is only counted: keeping
# 2.5 million unread "X-n: v" headers as Python objects took over 800 MB.
_READ_HEADERS = frozenset((
    "from", "reply-to", "return-path", "sender", "to", "cc", "subject", "date", "message-id", "x-mailer",
    "x-originating-ip", "authentication-results", "dkim-signature", "received-spf", "received", "mime-version",
    "content-type", "content-transfer-encoding", "content-disposition",
))
MAX_SAME_HEADER = 1000  # headers kept per name that a check reads; checks use the first (Received: the first 100) and the count
MAX_OTHER_HEADERS = 200  # headers kept that no check reads; the rest are counted


class _CountedMessage(Message):
    """A compat32 Message that keeps the headers the checks read and counts
    the rest, so the cost of a header storm is a counter, not an object per
    header. Nothing a check reads is dropped: the checks read the first
    header of a name, the first 100 Received headers, and the counts."""

    def __init__(self, policy=None):
        super().__init__(policy=policy or email.policy.compat32)
        self.header_counts = {}  # names in _READ_HEADERS only, so the dict stays small
        self.header_total = 0
        self._other_kept = 0

    def set_raw(self, name, value):
        self.header_total += 1
        key = str(name).lower()
        if key in _READ_HEADERS:
            count = self.header_counts.get(key, 0) + 1
            self.header_counts[key] = count
            if count > MAX_SAME_HEADER:
                return
        elif self._other_kept >= MAX_OTHER_HEADERS:
            return
        else:
            self._other_kept += 1
        super().set_raw(name, value)


def _header_count(msg, name: str = None) -> int:
    """How many headers the message has (of one name, when given), dropped ones included."""
    if isinstance(msg, _CountedMessage):
        return msg.header_counts.get(name, 0) if name else msg.header_total
    items = _raw_items(msg)
    return sum(1 for n, _ in items if n == name) if name else len(items)


# Header field names followed by white space before the colon ("From : x")
# are obsolete RFC 5322 syntax that the library parser does not read as a
# header: "From :" is skipped as a misplaced mbox line, and "Subject :"
# ends the header block. Mail clients differ. The top header block is
# rewritten without that white space, which changes no body or attachment
# byte, and the rewrite is recorded as a malformed header.
_OBSOLETE_NAME = re.compile(rb"(?m)^([!-9;-~]+)[ \t]+:")
_HEADER_END = re.compile(rb"\r?\n\r?\n|\r\r")
_REWRITE_SLICE = 1 << 17


def _join_obsolete_field_names(data: bytes) -> tuple:
    end = _HEADER_END.search(data)
    block_end = end.start() if end else len(data)
    block = data[:block_end]
    if not _OBSOLETE_NAME.search(block):
        return data, []
    names = []
    pieces = []
    # In slices of about 128 KB cut at line ends: one substitution over
    # 20 MB of such lines held millions of match pieces at once.
    start = 0
    while start < len(block):
        cut = block.find(b"\n", start + _REWRITE_SLICE)
        cut = len(block) if cut < 0 else cut + 1
        piece = block[start:cut]
        if len(names) < MAX_MAILBOXES:
            for m in _OBSOLETE_NAME.finditer(piece):
                names.append(m.group(1).decode("ascii", "replace"))
                if len(names) >= MAX_MAILBOXES:
                    break
        pieces.append(_OBSOLETE_NAME.sub(rb"\1:", piece))
        start = cut
    fixed = b"".join(pieces)
    del pieces
    problems = [{
        "header": name,
        "reason": f"the header name is followed by white space before the colon ('{name} :'). That is obsolete syntax: some mail "
                  "software ignores such a header, or takes it as the start of the body, while others show it. It was read as a header",
        "evidence": "",
        "family": "names",
        "disagree": name.lower() in _READ_HEADERS,  # a header a check reads: readers that skip it see another message
        "severity": "medium" if name.lower() in _READ_HEADERS else "info",
    } for name in dict.fromkeys(names)]
    return fixed + data[block_end:], problems


# ----- header values -----

def _text(value) -> str:
    """A raw header value as text. Bytes that are not ASCII were kept by the
    parser as surrogate escapes; they are read as UTF-8 here."""
    if not isinstance(value, str):
        value = str(value)
    try:
        value = value.encode("ascii", "surrogateescape").decode("utf-8", "replace")
    except UnicodeEncodeError:
        pass
    return _LINE_BREAK.sub("", value).strip()


def _raw_items(msg) -> list:
    try:
        return [(str(name).lower(), value) for name, value in msg.raw_items()]
    except Exception:
        return []


def _all(items: list, name: str) -> list:
    return [_text(v) for n, v in items if n == name]


def _first(items: list, name: str) -> str:
    for n, v in items:
        if n == name:
            return _text(v)
    return ""


def _codec(charset: str) -> str:
    """A text codec for a declared charset, or utf-8 when it is unknown or not
    a text encoding (``idna``, ``rot13`` and the like are not charsets)."""
    name = (charset or "").strip().strip('"').split("*", 1)[0].lower()
    if not name or name in ("unknown-8bit", "x-unknown", "default"):
        return "utf-8"
    try:
        info = codecs.lookup(name)
    except (LookupError, ValueError):
        return "utf-8"
    if not getattr(info, "_is_text_encoding", True) or info.name in ("idna", "punycode"):
        return "utf-8"
    return info.name


def decode_bytes(data: bytes, charset: str) -> str:
    try:
        return data.decode(_codec(charset), errors="replace")
    except Exception:
        return data.decode("utf-8", errors="replace")


def _word_bytes(encoding: str, payload: str):
    raw = payload.encode("utf-8", "replace")
    try:
        if encoding in "bB":
            raw = raw.rstrip(b"=")
            return binascii.a2b_base64(raw + b"=" * (-len(raw) % 4))
        return binascii.a2b_qp(raw, header=True)
    except (binascii.Error, ValueError):
        return None


def decode_words(value: str) -> str:
    """Decode RFC 2047 encoded words in one linear pass. White space between
    two encoded words is dropped, as the RFC says; a word that does not
    decode is kept as written."""
    if not value or "=?" not in value:
        return value or ""
    out = []
    pending = bytearray()
    pending_charset = None
    pos = 0
    after_word = False

    def flush():
        nonlocal pending, pending_charset
        if pending_charset is not None:
            out.append(decode_bytes(bytes(pending), pending_charset))
        pending = bytearray()
        pending_charset = None

    for m in _ENCODED_WORD.finditer(value):
        gap = value[pos:m.start()]
        if gap and not (after_word and not gap.strip()):
            flush()
            out.append(gap)
        decoded = _word_bytes(m.group(2), m.group(3))
        if decoded is None:
            flush()
            out.append(m.group(0))
            after_word = False
        else:
            charset = m.group(1).split("*", 1)[0].lower()
            if charset != pending_charset:
                flush()
                pending_charset = charset
            pending.extend(decoded)
            after_word = True
        pos = m.end()
    flush()
    out.append(value[pos:])
    return "".join(out)


# ----- lexing shared by addresses and MIME parameters -----

_COMMENT_STOP = re.compile(r"\(+|\)+|\\", re.DOTALL)
_QUOTED_PAIR = re.compile(r"\\(.)", re.DOTALL)


def _unescape(text: str) -> str:
    return _QUOTED_PAIR.sub(r"\1", text) if "\\" in text else text


def _comment_end(value: str, start: int) -> int:
    """Index just past the comment that opens at value[start], or -1 when it
    never closes. Nesting and quoted-pairs follow RFC 5322. One pass, no
    recursion, runs of parentheses taken at once, so a comment 2,000 levels
    deep costs what its length costs."""
    depth = 0
    pos = start
    search = _COMMENT_STOP.search
    while True:
        m = search(value, pos)
        if m is None:
            return -1
        run = m.group()
        if run == "\\":
            pos = m.end() + 1
            continue
        if run[0] == "(":
            depth += len(run)
        elif len(run) >= depth:
            return m.start() + depth
        else:
            depth -= len(run)
        pos = m.end()


# ----- addresses -----

# Tokens of an address header after comments are taken out. A quoted
# string and a domain literal are matched as a whole with an unrolled loop
# (linear); every other character is an atom run or a single special.
_ADDR_TOKEN = re.compile(r'''
    (?P<ws>[ \t]+)
  | (?P<q>"[^"\\]*(?:\\.[^"\\]*)*")
  | (?P<dl>\[[^\[\]\\]*(?:\\.[^\[\]\\]*)*\])
  | (?P<ew>=\?[^?\s]{1,64}\?[bBqQ]\?[^?\s]*\?=)
  | (?P<atom>[^ \t()<>\[\]:;@\\,."]+)
  | (?P<sp>[<>:;@,.\[\]\\")])
''', re.VERBOSE | re.DOTALL)
_DOT_ATOM_ENDS = frozenset(' \t"(),:;<>@[\\]')
_LENIENT_ANGLE = re.compile(r"<\s*([^<>\s@]+@[^<>\s@]+)\s*>")
_ADDR_CHARS = r'[^\s<>()\[\],;:"@]'
_LENIENT_ADDR = re.compile(r"(?<!" + _ADDR_CHARS + r")" + _ADDR_CHARS + r"+@" + _ADDR_CHARS + r"+")


def _addr_tokens(value: str):
    """Yield (kind, text, start) for an address header. Kinds: atom, q
    (quoted-string content), dl (domain literal), c (comment content),
    one-character specials, and bad (an unclosed quote or comment, a stray
    backslash, ")" or bracket). Linear in the length of the value."""
    pos = 0
    n = len(value)
    match = _ADDR_TOKEN.match
    while pos < n:
        if value[pos] == "(":
            end = _comment_end(value, pos)
            if end < 0:
                yield ("bad", "a comment that is never closed", pos)
                return
            yield ("c", value[pos + 1:end - 1], pos)
            pos = end
            continue
        m = match(value, pos)
        kind = m.lastgroup
        text = m.group()
        start = pos
        pos = m.end()
        if kind == "ws":
            continue
        if kind == "q":
            yield ("q", _unescape(text[1:-1]), start)
        elif kind == "sp":
            if text == '"':
                yield ("bad", "a quoted string that is never closed", start)
                return
            if text in "\\)[]":
                yield ("bad", f"a stray '{text}'", start)
            else:
                yield (text, text, start)
        elif kind == "ew":
            yield ("atom", text, start)  # an RFC 2047 encoded word is one word, whatever it spells
        else:
            yield (kind, text, start)


def _quote_local(local: str) -> str:
    if _DOT_ATOM_ENDS.isdisjoint(local):
        return local
    return '"' + local.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _addr_spec(tokens: list) -> tuple:
    """(address or '', problem or '') from the tokens of one addr-spec."""
    at = [i for i, t in enumerate(tokens) if t[0] == "@"]
    if not at:
        return "", "a mailbox with no '@'"
    if len(at) > 1:
        return "", "a mailbox with more than one '@'"
    local_toks, domain_toks = tokens[:at[0]], tokens[at[0] + 1:]
    problem = ""
    words = []
    expect_word = True
    for kind, text, _ in local_toks:
        if kind in ("atom", "q") and expect_word:
            words.append(text)
            expect_word = False
        elif kind == "." and not expect_word:
            expect_word = True
        elif kind == ".":
            problem = "a local part with a misplaced '.'"
            words.append("")
        else:
            return "", "a local part that is not a word or quoted string"
    if expect_word and words:
        problem = problem or "a local part that ends with '.'"
    local = ".".join(words) if not problem else ".".join(words) + ("." if expect_word and words else "")
    if not local:
        problem = "an empty local part"
    if len(domain_toks) == 1 and domain_toks[0][0] == "dl":
        inner = _unescape(domain_toks[0][1][1:-1]).strip(" \t")
        if " " in inner or "\t" in inner:
            problem = problem or "an address literal with white space inside"
        domain = "[" + inner.replace(" ", "").replace("\t", "") + "]"
    else:
        labels = []
        expect_label = True
        for kind, text, _ in domain_toks:
            if kind == "atom" and expect_label:
                labels.append(text)
                expect_label = False
            elif kind == "." and not expect_label:
                expect_label = True
            else:
                return "", "a domain that is not a dotted name or an address literal"
        if not labels:
            return "", "an empty domain"
        if expect_label:
            problem = problem or "a domain that ends with '.'"
        domain = ".".join(labels)
    if not local:
        return '""@' + domain, problem  # kept, so that the domain is still checked
    return _quote_local(local) + "@" + domain, problem


def _phrase(tokens: list) -> tuple:
    """(display name text, problem or '')"""
    if any(t[0] == "@" for t in tokens):  # an address written as the name: show it as one string
        return "".join(t[1] for t in tokens), "a display name holding characters a name may not contain unquoted"
    out = ""
    problem = ""
    glue = True
    for kind, text, _ in tokens:
        if kind in ("atom", "q"):
            out += text if glue else " " + text
            glue = False
        elif kind == ".":
            out += "."  # obsolete but common: "J. Smith", "PayPal, Inc."
        else:
            problem = "a display name holding characters a name may not contain unquoted"
            out += text
            glue = True
    return out, problem


def _is_route(tokens: list) -> bool:
    """True for an obsolete source route: "@" domain *("," ["@" domain])."""
    expect = "@"
    seen = False
    for kind, _text, _ in tokens:
        if expect == "@":
            if kind == ",":
                continue
            if kind != "@":
                return False
            expect = "label"
        elif expect == "label":
            if kind not in ("atom", "dl"):
                return False
            expect = "after"
            seen = True
        else:  # after a label: "." and another label, or ","
            if kind == ".":
                expect = "label"
            elif kind == ",":
                expect = "@"
            else:
                return False
    return seen and expect == "after"


def _mailbox(tokens: list, comment: str) -> tuple:
    """(display name, address, problems, other addresses) for one element of
    an address list, tokens with comments removed."""
    problems = [t[1] for t in tokens if t[0] == "bad"]
    others = []
    tokens = [t for t in tokens if t[0] != "bad"]
    opens = [i for i, t in enumerate(tokens) if t[0] == "<"]
    if not opens:
        name, addr = comment, ""
        if not any(t[0] == "@" for t in tokens):
            if tokens:
                problems.append("a name with no address")
            return name, "", problems, others
        addr, problem = _addr_spec(tokens)
        if problem:
            problems.append(problem)
        return name, addr, problems, others
    first = opens[0]
    close = next((i for i in range(first + 1, len(tokens)) if tokens[i][0] == ">"), None)
    if close is None:
        problems.append("an address whose '<' is never closed")
        inside = tokens[first + 1:]
        after = []
    else:
        inside = tokens[first + 1:close]
        after = tokens[close + 1:]
    if any(t[0] == "<" for t in inside):
        problems.append("a '<' inside an address")
        inside = [t for t in inside if t[0] != "<"]
    colons = [i for i, t in enumerate(inside) if t[0] == ":"]
    if colons:
        route = inside[:colons[-1]]
        inside = inside[colons[-1] + 1:]  # an obsolete source route: "<@relay.test:user@host.test>"
        if not _is_route(route):
            problems.append("an address with a ':' that is not a source route")
    name, problem = _phrase(tokens[:first])
    if problem:
        problems.append(problem)
        if any(t[0] == "@" for t in tokens[:first]):
            other, _ = _addr_spec([t for t in tokens[:first] if t[0] in ("atom", "q", ".", "@", "dl")])
            if other:
                others.append(other)
                problems.append(f"an address ({other}) written as the display name in front of another address")
    if not inside:
        problems.append("an empty address '<>'")
        addr = ""
    else:
        addr, problem = _addr_spec(inside)
        if problem:
            problems.append(problem)
    if after:
        problems.append("text after the closing '>'")
        for i, t in enumerate(after):
            if t[0] == "<":
                end = next((j for j in range(i + 1, len(after)) if after[j][0] == ">"), len(after))
                other, _ = _addr_spec(after[i + 1:end])
                if other:
                    others.append(other)
    return (name or comment), addr, problems, others


def _address_list(value: str) -> dict:
    """Read an address header (From, Reply-To, Sender, Return-Path) by the
    RFC 5322 grammar, obsolete forms included: comments, quoted strings and
    pairs, groups, display names, source routes, empty list elements. One
    linear pass with no recursion, stopping once MAX_MAILBOXES mailboxes
    are kept.

    When no mailbox can be read, a lenient reading takes the last address in
    angle brackets, or else the first thing shaped like an address. Returns
    {"mailboxes": [(display name, lower-case address)], "problems": [str],
    "lenient": bool, "more": bool, "others": [address]}."""
    out = {"mailboxes": [], "problems": [], "lenient": False, "more": False, "others": []}
    if not value:
        return out
    mailboxes = out["mailboxes"]
    problems = out["problems"]
    current = []
    comment = ""
    in_group = False
    angle = False

    def finish():
        nonlocal current, comment
        if current:
            name, addr, probs, others = _mailbox(current, comment)
            problems.extend(probs)
            out["others"].extend(o.lower() for o in others)
            if addr:
                mailboxes.append((decode_words(name).strip(), addr.lower()))
        current = []
        comment = ""

    for count, tok in enumerate(_addr_tokens(value)):
        if count >= MAX_HEADER_TOKENS:
            problems.append(f"more than {MAX_HEADER_TOKENS:,} words and separators, past which the header was read leniently")
            current = []
            out["more"] = bool(mailboxes)
            break
        kind = tok[0]
        if kind == "c":
            if not comment and tok[1].strip():
                comment = tok[1].strip()
            continue
        if angle:
            current.append(tok)
            if kind == ">":
                angle = False
            continue
        if kind == "<":
            angle = True
            current.append(tok)
        elif kind == ",":
            finish()
        elif kind == ":" and not in_group and all(t[0] in ("atom", "q", ".") for t in current):
            in_group = True  # a group: the name before ":" names the group, not a mailbox
            current = []
            comment = ""
        elif kind == ";":
            if not in_group:
                problems.append("a ';' outside a group")
            in_group = False
            finish()
        else:
            current.append(tok)
        if len(mailboxes) >= MAX_MAILBOXES:
            out["more"] = True
            break
    if not out["more"]:
        finish()
        if in_group:
            problems.append("a group that is never closed with ';'")
    if len(mailboxes) > MAX_MAILBOXES:
        del mailboxes[MAX_MAILBOXES:]
        out["more"] = True
    if not mailboxes and value.strip() and value.strip() != "<>":
        addr = ""
        for m in _LENIENT_ANGLE.finditer(value):
            addr = m.group(1)
        if not addr:
            m = _LENIENT_ADDR.search(value)
            if m:
                addr = m.group()
        if addr:
            mailboxes.append(("", addr.strip().lower()))
            out["lenient"] = True
        if not problems:
            problems.append("no address could be read")
    # one entry per kind of problem is enough for the report
    out["problems"] = list(dict.fromkeys(problems))[:10]
    out["others"] = list(dict.fromkeys(out["others"]))[:MAX_MAILBOXES]
    return out


def _unique_domains(domains) -> list:
    """Non-empty domains in order, one per canonical form (the first spelling kept)."""
    seen = {}
    for d in domains:
        if d:
            seen.setdefault(canonical_domain(d), d)
    return list(seen.values())


def _domain_of(address: str) -> str:
    if "@" not in address:
        return ""
    at = address.rfind("@[") if address.endswith("]") else -1
    if at < 0:
        at = address.rfind("@")
    return address[at + 1:].lower().rstrip(".")


_AFTER_AT = re.compile(r"@\s*([^\s<>()\[\],;:\"@\\]+|\[[^\[\]\s]{1,64}\])")


def lenient_domains(raw: str) -> list:
    """Every domain another reader could take from an address header: the
    text after the last "@" (read in the raw value and with encoded words
    decoded), the domain of each address in angle brackets, and of the first
    thing shaped like an address. Linear; at most MAX_MAILBOXES."""
    found = []
    for text in dict.fromkeys((raw, decode_words(raw))):
        at = text.rfind("@")
        if at >= 0:
            m = _AFTER_AT.match(text, at)
            if m:
                found.append(m.group(1))
    for i, m in enumerate(_LENIENT_ANGLE.finditer(raw)):
        if i >= MAX_MAILBOXES:
            break
        found.append(_domain_of(m.group(1)))
    m = _LENIENT_ADDR.search(raw)
    if m:
        found.append(_domain_of(m.group()))
    out = []
    for d in found:
        d = d.strip().strip(".").lower()
        if d and ("." in d or d.startswith("[")) and d not in out:
            out.append(d)
    return out[:MAX_MAILBOXES]


def _record(h: EmailHeaders, header: str, parsed: dict, raw: str) -> None:
    if not parsed["problems"] and not parsed["lenient"]:
        return
    reason = "; ".join(parsed["problems"])
    if parsed["lenient"]:
        reason += ". The address used, " + parsed["mailboxes"][0][1] + ", was found by a lenient reading"
    elif not parsed["mailboxes"]:
        reason += ". No address could be read from it"
    # Points only when the readings disagree on what a check uses, the
    # domain: a comma or bracket in a display name that every reading gets
    # past to the same address is noted, not scored.
    strict = set() if parsed["lenient"] else {_domain_of(a) for _, a in parsed["mailboxes"]}
    readings = [d for d in lenient_domains(raw) + [_domain_of(o) for o in parsed["others"]] if d]
    other = [d for d in dict.fromkeys(readings) if d not in strict]
    if other:
        reason += ". Other readings give the domain " + ", ".join(other[:5])
    h.malformed.append({"header": header, "reason": reason, "evidence": raw[:300], "family": "address", "disagree": bool(other),
                        "severity": "medium" if other else "info"})


# ----- MIME parameters -----

_PARAM_TOKEN = re.compile(r'''
    (?P<ws>[ \t]+)
  | (?P<q>"[^"\\]*(?:\\.[^"\\]*)*")
  | (?P<semi>;)
  | (?P<eq>=)
  | (?P<atom>[^ \t;="(]+)
  | (?P<qopen>")
''', re.VERBOSE | re.DOTALL)
_TSPECIALS = frozenset('()<>@,;:\\"/[]?=')
_LENIENT_PARAM = re.compile(r'(?i)(?<![^\s;()])((?:file)?name|charset)\*?(?:\d{1,4}\*?)?\s*=\s*("[^"]*"?|[^\s;()]+)')
_LENIENT_NAMES = ("filename", "name", "charset")
_RFC2231_SHAPE = re.compile(r"^[A-Za-z0-9_.:-]{0,40}'[A-Za-z0-9-]{0,20}'")
# An encoded word read tolerantly: any charset text, and a payload of any
# characters but "?" (stray spaces or junk in base64 are dropped, as some
# readers do). Linear for the same reason as _ENCODED_WORD.
_LOOSE_WORD = re.compile(r"=\?([^?]{0,64})\?([bBqQ])\?([^?]*)\?=")
_NOT_BASE64 = re.compile(r"[^A-Za-z0-9+/]")


def _lenient_words(value: str) -> str:
    """decode_words, then any encoded word it left alone decoded tolerantly."""
    value = decode_words(value)
    if "=?" not in value:
        return value

    def loose(m):
        payload = m.group(3)
        if m.group(2) in "bB":
            raw = _NOT_BASE64.sub("", payload)
            if len(raw) % 4 == 1:
                raw = raw[:-1]
            try:
                data = binascii.a2b_base64(raw + "=" * (-len(raw) % 4))
            except (binascii.Error, ValueError):
                return m.group(0)
        else:
            data = binascii.a2b_qp(payload.encode("utf-8", "replace"), header=True)
        return decode_bytes(data, m.group(1).replace(":", "").strip())
    return _LOOSE_WORD.sub(loose, value)


class MimeParams:
    """A MIME header such as Content-Type or Content-Disposition, read.

    ``head`` is the lower-case value before the first ";" (the type).
    ``params`` maps a lower-case name to its values in order, as the RFC
    2045, 2047 and 2231 grammar reads them. ``lenient`` holds values for
    ``filename``, ``name`` and ``charset`` that a tolerant scan found and
    the strict reading did not. ``problems`` says what did not fit the
    grammar. ``overflow`` counts values past MAX_PARAM_VALUES."""

    __slots__ = ("head", "params", "lenient", "problems", "overflow")

    def __init__(self):
        self.head = ""
        self.params = {}
        self.lenient = {}
        self.problems = []
        self.overflow = 0

    def __iter__(self):  # (head, params), as callers of the old tuple form unpack it
        return iter((self.head, self.params))

    def first(self, name: str) -> str:
        values = self.params.get(name) or self.lenient.get(name) or [""]
        return values[0]

    def all(self, name: str) -> list:
        return list(self.params.get(name, [])) + list(self.lenient.get(name, []))

    def add(self, store: dict, name: str, value: str) -> None:
        values = store.setdefault(name, [])
        if len(values) >= MAX_PARAM_VALUES:
            self.overflow += 1
        elif value not in values:  # at most MAX_PARAM_VALUES entries, so this stays bounded
            values.append(value)


def _param_tokens(value: str) -> list:
    """[(kind, text)] for a MIME header value. Kinds: ws, q (quoted-string
    content), semi, eq, atom, c (comment), qopen and copen (an unclosed
    quote or comment, with the rest of the value). Linear."""
    out = []
    pos = 0
    n = len(value)
    match = _PARAM_TOKEN.match
    while pos < n:
        if len(out) >= MAX_HEADER_TOKENS:
            out.append(("cut", value[pos:]))
            break
        if value[pos] == "(":
            end = _comment_end(value, pos)
            if end < 0:
                out.append(("copen", value[pos + 1:]))
                break
            out.append(("c", value[pos + 1:end - 1]))
            pos = end
            continue
        m = match(value, pos)
        kind = m.lastgroup
        text = m.group()
        pos = m.end()
        if kind == "q":
            out.append(("q", _unescape(text[1:-1])))
            if "\\" in text and "=?" in text:
                out.append(("note", "an encoded word written with quoted-pairs"))
        elif kind == "qopen":
            out.append(("qopen", _unescape(value[pos:])))
            break
        else:
            out.append((kind, text))
    return out


def _token_prefix(text: str) -> tuple:
    """(the leading run of RFC 2045 token characters, whether anything follows)"""
    for i, ch in enumerate(text):
        if ch in _TSPECIALS or ord(ch) < 33:
            return text[:i], True
    return text, False


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
        if "\\" in value:
            value = _unescape(value)
    elif value[:1] in "\"'":
        value = value[1:]
    return value.strip()


def _params(value: str) -> MimeParams:
    """Read a MIME header such as Content-Type or Content-Disposition.
    Comments are dropped, quoted strings kept whole, RFC 2231 continuations
    and charsets joined and decoded, then RFC 2047 encoded words, which
    many mailers put in quoted parameters. When any part of the value does
    not fit the grammar, a tolerant scan reads every ``filename``, ``name``
    and ``charset`` it can find as well. Linear in the length of the value."""
    out = MimeParams()
    header_value = value or ""
    tokens = _param_tokens(header_value)
    pieces = [[]]
    for tok in tokens:
        if tok[0] == "semi":
            pieces.append([])
        elif tok[0] == "note":
            out.problems.append(tok[1])
        elif tok[0] == "cut":
            out.problems.append(f"more than {MAX_HEADER_TOKENS:,} words and separators, past which the header was read leniently")
        else:
            if tok[0] == "c" and ("=" in tok[1] or ";" in tok[1]):
                # Readers disagree on where such a comment ends, and some do
                # not take it as a comment at all.
                out.problems.append("a comment holding parameter-like text")
            pieces[-1].append(tok)
    head = [t for t in pieces[0] if t[0] not in ("ws", "c")]
    if head and head[0][0] == "atom":
        out.head = head[0][1].lower()
        if any(ch in _TSPECIALS and ch != "/" for ch in out.head):
            out.problems.append("a type with characters a type may not contain")
    if len(head) != 1 or head[0][0] != "atom":
        if head or len(pieces) > 1:
            out.problems.append("the value before the first ';' is not a single word")
        if head and len(head) > 1 and all(t[0] == "atom" for t in head):
            out.head = "".join(t[1] for t in head).lower()  # "text /html"
    continued = {}
    seen_names = {}
    for piece in pieces[1:]:
        toks = [t for t in piece if t[0] not in ("ws", "c")]
        if not toks:
            continue  # an empty parameter, as after a trailing ";"
        if toks[0][0] in ("copen", "qopen"):
            out.problems.append("a quote or comment that is never closed")
            continue
        if len(toks) < 3 or toks[0][0] != "atom" or toks[1][0] != "eq":
            out.problems.append("a parameter that is not name=value")
            continue
        name = toks[0][1].strip().lower()
        if any(ch in _TSPECIALS for ch in name):
            out.problems.append("a parameter name with characters a name may not contain")
        if "*" in name:
            kinds = [t[0] for t in piece]
            if kinds.index("eq") > kinds.index("atom") + 1:
                out.problems.append("white space or a comment between an RFC 2231 name and '='")
        vtok = toks[2] if len(toks) > 2 else ("", "")
        if len(toks) > 3:
            out.problems.append("a parameter value that is not one word or one quoted string")
        if vtok[0] in ("q", "qopen"):
            raw = vtok[1]
            if vtok[0] == "qopen":
                out.problems.append("a quoted string that is never closed")
            quoted = True
        elif vtok[0] == "atom":
            raw, extra = _token_prefix(vtok[1])
            if extra:
                out.problems.append("a parameter value with characters that need quoting")
            quoted = False
        else:
            if vtok[0] == "copen":
                out.problems.append("a comment that is never closed")
            elif vtok[0] == "eq":
                out.problems.append("a parameter value that starts with '='")
            continue
        m = _CONTINUATION.match(name)
        if m:
            continued.setdefault(m.group(1), []).append((int(m.group(2)), bool(m.group(3)), raw, quoted))
            continue
        seen_names[name] = seen_names.get(name, 0) + 1
        if name.endswith("*"):
            out.add(out.params, name[:-1], _rfc2231(raw, quoted))
            continue
        value = decode_words(raw).strip() if quoted else raw.strip()
        if quoted and raw != raw.strip():
            # The library keeps white space inside the quotes; this reader
            # drops it, so "koi8-r " is a charset here and not there.
            out.problems.append("a quoted value with white space at its start or end")
        out.add(out.params, name, value)
        if quoted and "=?" in raw:
            for word in _ENCODED_WORD.finditer(raw):
                before = raw[word.start() - 1] if word.start() else " "
                after = raw[word.end()] if word.end() < len(raw) else " "
                if not before.isspace() or not after.isspace():
                    out.problems.append("an encoded word joined to other text, which RFC 2047 does not allow")
                    break
        if quoted and "=?" in value and _LOOSE_WORD.search(value):
            out.problems.append("an encoded word that does not decode cleanly")
            loose = _lenient_words(raw).strip()
            if loose != value:
                out.add(out.lenient, name, loose)
        elif not quoted and _RFC2231_SHAPE.match(value) and value.count("'") >= 2:
            out.problems.append("a value in RFC 2231 form without the '*' that marks it")
            out.add(out.lenient, name, _rfc2231(value))
    for name, segments in continued.items():
        strict, lenient, problem = _join_continuations(segments)
        if problem:
            out.problems.append(problem)
        if name in out.params:
            # Readers join RFC 2231 sections and a plain or extended value of
            # the same name in different ways (the standard library glues
            # them together), so this is ambiguous even when they agree.
            out.problems.append(f"'{name}' given both in RFC 2231 sections and in another form")
        out.add(out.params, name, strict)
        if lenient != strict:
            out.add(out.lenient, name, lenient)
    if any(count > 1 for count in seen_names.values()):
        out.problems.append("a parameter given more than once")  # readers keep the first, the last, or join them
    for name in _LENIENT_NAMES:
        values = out.params.get(name, [])
        if len(values) > 1 and name != "name":
            out.problems.append(f"more than one '{name}' parameter, with different values")
    if out.problems:
        _lenient_scan(tokens, out, header_value)
    out.problems = list(dict.fromkeys(out.problems))[:10]
    return out


def _join_continuations(segments: list) -> tuple:
    """(strict value, lenient value, problem) for RFC 2231 segments
    [(number, encoded, raw, quoted)]. The strict value stops at the first
    missing number and keeps the first of duplicates, as the standard
    library does; the lenient value joins every segment in number order,
    the last of duplicates winning."""
    segments.sort(key=lambda s: s[0])
    problem = ""
    first_of = {}
    last_of = {}
    for seg in segments:
        first_of.setdefault(seg[0], seg)
        last_of[seg[0]] = seg
    if len(first_of) != len(segments):
        problem = "an RFC 2231 continuation number used twice"
    if 0 in first_of:
        n0, encoded0, raw0, _q = first_of[0]
        if encoded0 and raw0.count("'") < 2:
            problem = problem or "an RFC 2231 first section without its charset and language"
        if not encoded0 and any(seg[1] for seg in segments):
            problem = problem or "RFC 2231 sections where only later ones are marked encoded"
        if not encoded0 and raw0.count("'") >= 2 and _RFC2231_SHAPE.match(raw0):
            problem = problem or "an RFC 2231 first section in encoded form without the '*' that marks it"
    numbers = sorted(first_of)
    strict_numbers = []
    for expected, number in enumerate(numbers):
        if number != expected:
            problem = problem or "an RFC 2231 continuation with a missing number"
            break
        strict_numbers.append(number)
    strict = _decode_segments([first_of[n] for n in strict_numbers])
    lenient = _decode_segments([last_of[n] for n in numbers])
    return strict, lenient, problem


def _decode_segments(segments: list) -> str:
    charset = ""
    data = bytearray()
    for index, (n, encoded, raw, quoted) in enumerate(segments):
        if encoded:
            if index == 0 and raw.count("'") >= 2:
                charset, _lang, raw = raw.split("'", 2)
            data.extend(unquote_to_bytes(raw))
        else:
            data.extend(raw.encode("utf-8", "replace"))
    return decode_words(decode_bytes(bytes(data), charset or "utf-8")).strip()


def _rfc2231(raw: str, quoted: bool = False) -> str:
    if raw.count("'") >= 2:
        charset, _lang, rest = raw.split("'", 2)
        return decode_bytes(unquote_to_bytes(rest), charset).strip()
    return decode_bytes(unquote_to_bytes(raw), "utf-8").strip()


def _lenient_scan(tokens: list, out: MimeParams, value: str = "") -> None:
    """Every filename, name and charset the tokens hold, read tolerantly:
    any word followed by "=", in any piece, with the value taken both as
    one word and as everything up to the next ";", or as a quoted string.
    Quoted strings and comments are skipped as wholes, so text inside them
    is never read as a parameter; the rest of an unclosed quote or comment
    is searched with a plain pattern. Linear."""
    found = []
    # Last, the raw value with no regard for quotes: a quote that opens in
    # the middle of a word ('Attac"hment') pairs up differently for
    # different readers, so the header is already malformed and every
    # reading of it is checked.
    for m in _LENIENT_PARAM.finditer(value.replace("\\", "") if "\\" in value else value):
        if len(found) >= MAX_HEADER_TOKENS:
            out.overflow += 1  # counted, not kept
            continue
        found.append((m.group(1).lower(), m.group(0).split("=", 1)[0].strip().lower(), _unquote(m.group(2))))
    for kind, text in tokens:
        if kind == "c" and "=" in text:
            # Some readers do not take "(" inside a word as a comment, so a
            # parameter written inside one is still read when the header is
            # already malformed.
            for m in _LENIENT_PARAM.finditer(text):
                found.append((m.group(1).lower(), m.group(0).split("=", 1)[0].strip().lower(), _unquote(m.group(2))))
    words = [t for t in tokens if t[0] not in ("c", "note", "cut")]
    n = len(words)
    for i, (kind, text) in enumerate(words):
        if kind in ("qopen", "copen"):
            for m in _LENIENT_PARAM.finditer(text):
                found.append((m.group(1).lower(), m.group(0).split("=", 1)[0].strip().lower(), _unquote(m.group(2))))
            continue
        if kind != "atom":
            continue
        j = i + 1
        while j < n and words[j][0] == "ws":
            j += 1
        if j >= n or words[j][0] != "eq":
            continue
        raw_name = text.strip().lower()
        if raw_name.startswith("*"):  # "filename *=...": the name split by white space
            k = i - 1
            while k >= 0 and words[k][0] == "ws":
                k -= 1
            if k >= 0 and words[k][0] == "atom":
                raw_name = words[k][1].strip().lower() + raw_name
        base = raw_name.split("*", 1)[0]
        if base not in _LENIENT_NAMES:
            continue
        j += 1
        while j < n and words[j][0] == "ws":
            j += 1
        if j < n and words[j][0] in ("q", "qopen"):
            found.append((base, raw_name, words[j][1]))
            continue
        run = []
        while j < n and words[j][0] not in ("semi", "qopen", "copen"):
            run.append(" " if words[j][0] == "ws" else words[j][1])
            j += 1
        whole = "".join(run).strip()
        one = whole.split(" ", 1)[0]
        for candidate in (one, whole):
            if candidate:
                found.append((base, raw_name, _unquote(candidate)))
    for base, raw_name, value in found:
        if raw_name.endswith("*") or _RFC2231_SHAPE.match(value):
            value = _rfc2231(value)
        value = _lenient_words(value).strip()
        strict = out.params.get(base, ())
        if value and value not in strict and len(strict) < MAX_PARAM_VALUES:  # past the cap it is a strict value, not a lenient one
            out.add(out.lenient, base, value)


# ----- headers -----

def _extract_headers(msg) -> EmailHeaders:
    items = _raw_items(msg)
    h = EmailHeaders()
    h.raw = ""
    h.header_count = _header_count(msg)

    from_values = _all(items, "from")
    h.from_header_count = _header_count(msg, "from")
    from_raw = from_values[0] if from_values else ""
    h.from_header = decode_words(from_raw)
    parsed = _address_list(from_raw)
    mailboxes = parsed["mailboxes"]
    if mailboxes:
        h.from_name = mailboxes[0][0]
        h.from_email = mailboxes[0][1]
    else:
        h.from_name, h.from_email = h.from_header, ""
    h.from_domain = _domain_of(h.from_email)
    h.from_addresses = [a for _, a in mailboxes]
    h.from_more_mailboxes = parsed["more"]
    # Every domain a reader could take as the sender's. The text after the
    # last "@" always counts (in "<a@paypal.com@evil.example>" a reader may
    # take either side); the other lenient readings count when the header is
    # malformed.
    lenient = lenient_domains(from_raw) if from_raw else []
    if not (parsed["problems"] or parsed["lenient"]):
        lenient = lenient[:1]
    h.sender_candidates = _unique_domains([h.from_domain] + [_domain_of(a) for a in h.from_addresses + parsed["others"]] + lenient)
    if from_raw:
        _record(h, "From", parsed, from_raw)

    reply_raw = _first(items, "reply-to")
    h.reply_to = decode_words(reply_raw)
    reply = _address_list(reply_raw)
    h.reply_to_email = reply["mailboxes"][0][1] if reply["mailboxes"] else ""
    if reply_raw:
        _record(h, "Reply-To", reply, reply_raw)

    rp_raw = _first(items, "return-path")
    rp = _address_list(rp_raw)
    h.return_path = rp["mailboxes"][0][1] if rp["mailboxes"] else ""
    if rp_raw and rp_raw.strip() not in ("<>", ""):
        _record(h, "Return-Path", rp, rp_raw)

    h.to = decode_words(_first(items, "to"))
    h.subject = decode_words(_first(items, "subject"))
    h.date = _first(items, "date")
    h.message_id = _first(items, "message-id")
    h.x_mailer = decode_words(_first(items, "x-mailer"))
    h.x_originating_ip = _first(items, "x-originating-ip").strip("[] ")
    h.authentication_results = _first(items, "authentication-results")
    h.dkim_signature = _first(items, "dkim-signature")
    h.received_spf = _first(items, "received-spf")
    received = [v for n, v in items if n == "received"]
    h.received_count = _header_count(msg, "received")
    h.received_chain = [_text(v) for v in received[:MAX_RECEIVED]]
    return h


# ----- body -----

def _cap_part(body: EmailBody, label: str, value: str) -> str:
    if len(value) > MAX_PART_CHARS:
        body.truncated.append(f"{label} part cut at {MAX_PART_CHARS} characters ({len(value)} present) for the content checks; links were read from all of it")
        return value[:MAX_PART_CHARS]
    return value


def _part_header(part, name: str) -> str:
    return _first(_raw_items(part), name)


_KNOWN_CTE = ("7bit", "8bit", "binary", "base64", "quoted-printable", "x-uuencode", "uuencode", "x-uue")


def _normalize_cte(part) -> str:
    """Read Content-Transfer-Encoding by its grammar (comments, quotes, white
    space and letter case dropped) and give the library the clean value, so
    that ``base64 ``, ``base64 (x)`` or ``"base64"`` is decoded instead of
    left as encoded text that no link check can read. Returns a problem
    description, or ''."""
    raw = _part_header(part, "content-transfer-encoding")
    if not raw:
        return ""
    cte = _params(raw)
    value = cte.head or _unquote(raw).lower()
    if not value and cte.problems:
        value = _unquote(raw.split("(", 1)[0]).lower()
    problem = ""
    if value not in _KNOWN_CTE:
        problem = f"an unknown Content-Transfer-Encoding '{raw[:60]}'"
    elif value != str(part.get("content-transfer-encoding", "")).lower():
        # The library compares the raw value, white space and comments included.
        if '"' in raw or "'" in raw or cte.problems:
            problem = f"a Content-Transfer-Encoding written as '{raw[:60]}'"
        try:
            part.replace_header("Content-Transfer-Encoding", value)
        except KeyError:
            pass
    return problem


def _payload(part) -> bytes:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        return b""
    return payload if isinstance(payload, bytes) else b""


def _content_type(part, ctype_params: MimeParams) -> str:
    """The lower-case type/subtype, read with comments dropped, or the part's
    default type when the header is missing or not of that form, as the
    standard library does."""
    head = ctype_params.head.replace(" ", "")
    if head.count("/") == 1 and not head.startswith("/") and not head.endswith("/"):
        return head
    return part.get_default_type()


_HTML_NAMES = (".htm", ".html", ".xhtml", ".shtml", ".mht", ".mhtml", ".svg")


def _attachment_of(part, dparams: MimeParams, cparams: MimeParams):
    """The attachment entry for a part, or None if the part is not a file.

    A part is a file when its Content-Disposition type is ``attachment`` in
    any letter case, or when it names a file (Content-Disposition filename
    or name, Content-Type name) whatever its disposition: ``inline`` and a
    missing disposition are how executables are slipped past checks that
    only look for the word ``attachment``. The names kept are every
    distinct name the strict reading and the tolerant scan found, up to
    MAX_NAMES; ``name_count`` says how many there were.
    """
    if part.is_multipart():
        return None
    disposition = dparams.head
    names = {}
    total = 0
    for value in dparams.all("filename") + dparams.all("name") + cparams.all("name"):
        value = value.strip()
        if value and value not in names:
            total += 1
            if len(names) < MAX_NAMES:
                names[value] = None
    overflow = dparams.overflow + cparams.overflow
    total += overflow
    if disposition != "attachment" and not names:
        return None
    problems = []
    for label, p in (("Content-Disposition", dparams), ("Content-Type", cparams)):
        if p.problems:
            problems.append(f"{label}: " + "; ".join(p.problems))
    lenient_names = [v for v in dparams.lenient.get("filename", []) + dparams.lenient.get("name", []) + cparams.lenient.get("name", []) if v.strip()]
    payload = _payload(part)
    names = list(names)
    return {
        "filename": names[0] if names else "",
        "other_names": names[1:],
        "name_count": total,
        "content_type": _content_type(part, cparams),
        "disposition": disposition,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
        "md5": hashlib.md5(payload).hexdigest() if payload else "",
        "magic": payload[:4],
        "malformed": problems,
        "lenient_names": lenient_names[:MAX_NAMES],
    }


def _part_charset(cparams: MimeParams) -> str:
    return cparams.first("charset").strip().lower()


def _part_text(part, cparams: MimeParams) -> str:
    return decode_bytes(_payload(part), _part_charset(cparams) or "utf-8")


def _walk(msg):
    """Every part, depth first, with no recursion."""
    stack = [msg]
    while stack:
        part = stack.pop()
        yield part
        if part.is_multipart():
            children = part.get_payload()
            if isinstance(children, list):
                stack.extend(reversed(children))


def _extract_body(msg) -> EmailBody:
    b = EmailBody()
    texts = []
    extra_budget = MAX_EXTRA_CHARS
    extra_text = []
    for part in _walk(msg):
        if part.is_multipart():
            continue
        cparams = _params(_part_header(part, "content-type"))
        dparams = _params(_part_header(part, "content-disposition"))
        cte_problem = _normalize_cte(part)
        attachment = _attachment_of(part, dparams, cparams)
        if cte_problem:
            b.part_problems.append(cte_problem)
        if attachment is None and cparams.problems:
            b.part_problems.append("Content-Type: " + "; ".join(cparams.problems))
        if attachment is not None:
            b.attachments.append(attachment)
        ctype = _content_type(part, cparams)
        is_top = part is msg
        names = [] if attachment is None else [attachment["filename"]] + attachment["other_names"]
        is_html = ctype == "text/html" or any(n.lower().rstrip(". ").endswith(_HTML_NAMES) for n in names)
        is_text = ctype == "text/plain" or (is_top and attachment is None and ctype != "text/html") or ctype.startswith("text/")
        as_file = attachment is not None and attachment["disposition"] == "attachment"
        if not (is_html or is_text):
            continue
        full = _part_text(part, cparams)
        b.read_digests.add(_text_digest(full))
        texts.append(full)  # links are read from every text and HTML part, attachments included
        full = squeeze(full)  # padding never uses up the content checks' share
        if not full.strip():
            continue  # a blank part is never the body the checks read first: padding cannot displace the real one
        if cparams.problems and _codec(_part_charset(cparams)) not in ("utf-8", "ascii"):
            # The charset came from a header that readers disagree on: read
            # the links of the other likely reading as well.
            texts.append(decode_bytes(_payload(part), "utf-8"))
        if is_html and not b.html and not as_file:
            b.html = _cap_part(b, "HTML", full)
        elif is_text and not is_html and not b.text and not as_file and (ctype == "text/plain" or is_top):
            b.text = _cap_part(b, "text", full)
        else:
            label = "HTML attachment" if is_html and as_file else "HTML" if is_html else "text attachment" if as_file else "text"
            keep = full[:extra_budget]
            if len(keep) < len(full):
                b.truncated.append(f"a further {label} part was read for the content checks only up to the shared {MAX_EXTRA_CHARS:,} character budget for further parts; links were read from all of it")
            extra_budget -= len(keep)
            if keep:
                if is_html:
                    b.extra_html.append(keep)
                else:
                    extra_text.append(keep)
    b.extra_text = "\n".join(extra_text)
    b.urls = _extract_urls(" ".join(texts), b)
    return b


_WHITE_RUN = re.compile(r"\s+")
_PADDING_RUN = re.compile(r"[\s\x00-\x08\x0e-\x1f\x7f]{64,}")


def squeeze(text: str) -> str:
    """Text for the content checks with every run of 64 or more white space
    or control characters made one space. A megabyte of spaces, line breaks
    or NULs then costs one character of the share each part gets, and
    cannot push the words after it out of the checks. Linear."""
    return _PADDING_RUN.sub(" ", text) if len(text) >= 64 else text


def _text_digest(text: str) -> bytes:
    """A digest of a part's text with white space runs made one space, so the
    raw scan can tell a part the structured parse already read."""
    digest = hashlib.sha1()
    started = pending = False
    step = 1 << 16  # in slices, so a million short words never become a million objects at once
    for i in range(0, len(text), step):
        chunk = text[i:i + step]
        core = _WHITE_RUN.sub(" ", chunk).strip()
        if not core:
            pending = True
            continue
        if started and (pending or chunk[0].isspace()):
            digest.update(b" ")
        digest.update(core.encode("utf-8", "surrogatepass"))
        started = True
        pending = chunk[-1].isspace()
    return digest.digest()


def url_hostname(url: str) -> str:
    """Lower-case host of a URL taken from the email, or '' if it has none.

    ``urllib.parse`` raises ValueError for malformed bracketed hosts such as
    ``http://[abc``; one such string in a body used to abort the whole
    analysis. Here it only means the URL has no usable host."""
    try:
        parsed = urlsplit(url if url.lower().startswith(("http://", "https://")) else f"http://{url}")
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def canonical_domain(domain: str) -> str:
    """The one form in which two domains are compared or deduplicated: lower
    case, no trailing dot, and non-ASCII labels in their IDNA (xn--) form, so
    'bücher.example' and 'xn--bcher-kva.example' are the same domain. A name
    that has no IDNA form, or is longer than a host name can be, is only
    lower-cased."""
    d = (domain or "").strip().rstrip(".").lower()
    if d.isascii() or len(d) > 253:
        return d
    try:
        return d.encode("idna").decode("ascii")
    except UnicodeError:
        return d


def _extract_urls(text: str, body: EmailBody = None) -> list:
    if not text:
        return []
    cleaned = []
    seen = set()
    for m in _URL_PATTERN.finditer(text):
        u = m.group(0)[:MAX_URL_CHARS].rstrip('.,;:!?)')
        if u not in seen:
            if len(cleaned) >= MAX_URLS:
                if body is not None:
                    body.truncated.append(f"the body has more than {MAX_URLS} distinct links; only the first {MAX_URLS} were analysed")
                    body.urls_capped = True
                break
            seen.add(u)
            cleaned.append(u)
    return cleaned
