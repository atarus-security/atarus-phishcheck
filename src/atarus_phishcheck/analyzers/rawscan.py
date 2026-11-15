"""A linear scan of the raw bytes, for messages past the structure limits.

When the MIME structure passes a limit (``parser.MAX_PARTS``,
``parser.MAX_DEPTH``, ``parser.MAX_NESTING_WORK``) the library parser is
stopped, so the parts after that point are never seen by it. The limits
are there to bound cost, never what is reported, so this module reads the
whole message again with passes that do not depend on the MIME structure
and take time in proportion to the input:

- every Content-Type, Content-Disposition and Content-Transfer-Encoding
  header block anywhere in the bytes, with the file names it gives (read by
  the same parameter reader as the structured parse) and the body up to
  the next line that starts with "--", decoded when it is base64 or
  quoted-printable;
- every link in the raw text, in the quoted-printable reading of the whole
  message, and in every decoded block;
- base64 lines that start with an executable file header (MZ, ELF).

What it finds is merged with what the structured parse found, without
repeating it: attachments become attachment entries, text and HTML blocks
feed the content and brand checks, links feed the link checks.
"""
import binascii
import hashlib
import re

from atarus_phishcheck.analyzers import parser

_PART_HEADER = re.compile(rb"(?i)(?:(?<=[\r\n])|\A)content-(?:type|disposition|transfer-encoding)[ \t]*:")
_BLOCK_END = re.compile(rb"\r\n\r\n|\n\n|\r\r|\n\r\n|\r\n\n")
_NEXT_PART = re.compile(rb"(?:\r\n|\r|\n)--")
_LINE_REST = re.compile(rb"[^\r\n]{0,204}")
_BOUNDARY_PARAM = re.compile(r'(?i)(?<![a-z0-9_-])boundary\s*=\s*(?:"([^"]{1,200})"|([^\s;"]{1,200}))')
MAX_BOUNDARIES = 100_000
_FOLD = re.compile(r"(?:\r\n|\r|\n)(?=[ \t])")
_FIELD = re.compile(r"(?i)^(content-type|content-disposition|content-transfer-encoding)[ \t]*:(.*)$")
_URL = re.compile(rb'https?://[^\s<>"\'\)]+|www\.[^\s<>"\'\)]+', re.IGNORECASE)
_EXECUTABLE_BASE64 = re.compile(rb"(?:(?<=[\r\n])|\A)[ \t]*(?:TVqQ|TVpQ|TVoA|TVpB|TVqA|TVro|f0VMR)")
_NOT_BASE64 = re.compile(rb"[^A-Za-z0-9+/]")

MAX_BLOCKS_READ = 20_000  # header blocks read with the full parameter reader; past it a block's names are read by a plain pattern
MAX_RAW_ATTACHMENTS = 1000  # attachment entries the scan adds; entries with a dangerous name or content are kept first
_PLAIN_NAME = re.compile(r'(?i)(?:file)?name\*?(?:\d{1,4}\*?)?[ \t]*=[ \t]*("[^"]*"?|[^\s;]+)')


class RawScan:
    __slots__ = ("attachments", "html", "text", "urls", "executable_lines", "blocks", "attachments_over")

    def __init__(self):
        self.attachments = []  # entries in the parser's attachment form
        self.html = []  # decoded HTML blocks
        self.text = []  # decoded plain text blocks
        self.urls = []  # distinct links, in order of appearance
        self.executable_lines = 0  # base64 lines that start with an executable header
        self.blocks = 0  # header blocks seen
        self.attachments_over = 0  # entries past MAX_RAW_ATTACHMENTS, counted


_digest = parser._text_digest


def _decode(body: bytes, cte: str) -> bytes:
    """The body decoded by its transfer encoding, tolerantly: characters
    outside the base64 alphabet are dropped, as most readers do."""
    try:
        if cte == "base64":
            cleaned = _NOT_BASE64.sub(b"", body)
            return binascii.a2b_base64(cleaned[: len(cleaned) // 4 * 4])
        if cte == "quoted-printable":
            return binascii.a2b_qp(body)
    except (binascii.Error, ValueError):
        return b""
    return body


def _fields(block: bytes) -> dict:
    """{field name: [values]} for the Content-* fields of one header block."""
    text = _FOLD.sub("", block.decode("utf-8", "replace"))
    out = {}
    for line in parser._LINE_BREAK.split(text):
        m = _FIELD.match(line)
        if m:
            out.setdefault(m.group(1).lower(), []).append(m.group(2).strip())
    return out


def _names_plain(fields: dict) -> list:
    names = []
    for key in ("content-disposition", "content-type"):
        for value in fields.get(key, []):
            for m in _PLAIN_NAME.finditer(value):
                names.append(parser._unquote(m.group(1)))
    return names


def scan(data: bytes, skip_digests=(), skip_attachments=()) -> RawScan:
    """Scan ``data`` (the message bytes). Text whose normalized digest is in
    ``skip_digests`` and attachments whose (name, sha256) is in
    ``skip_attachments`` were already read by the structured parse and are
    not returned again. Linear in len(data)."""
    out = RawScan()
    seen_text = set(skip_digests)
    seen_att = set(skip_attachments)
    seen_blocks = set()
    boundaries = set()
    seen_urls = set()
    urgent, ordinary = [], []
    decoded_for_links = []

    def add_urls(blob: bytes):
        for m in _URL.finditer(blob):
            url = m.group().decode("utf-8", "replace")[: parser.MAX_URL_CHARS].rstrip(".,;:!?)")
            if url not in seen_urls:
                seen_urls.add(url)
                out.urls.append(url)

    pending = None  # (header start, header end, body start) of the block whose body ends at the next block
    starts = _PART_HEADER.finditer(data)
    cursor = 0
    while True:
        m = next(starts, None)
        if m is not None and m.start() < cursor:
            continue  # inside the header block just read
        next_start = m.start() if m is not None else len(data)
        if pending is not None:
            _read_block(data, pending, next_start, out, seen_text, seen_att, seen_blocks, urgent, ordinary, decoded_for_links, boundaries)
            pending = None
        if m is None:
            break
        end = _BLOCK_END.search(data, m.start())
        header_end = end.start() if end else len(data)
        body_start = end.end() if end else len(data)
        pending = (m.start(), header_end, body_start)
        cursor = body_start
        out.blocks += 1

    add_urls(data)
    try:
        add_urls(binascii.a2b_qp(data))
    except (binascii.Error, ValueError):
        pass
    for blob in decoded_for_links:
        add_urls(blob)
    out.executable_lines = sum(1 for _ in _EXECUTABLE_BASE64.finditer(data))
    keep = urgent + ordinary[: max(0, MAX_RAW_ATTACHMENTS - len(urgent))]
    out.attachments_over += len(urgent) + len(ordinary) - len(keep)
    out.attachments = keep
    return out


def _body_end(data: bytes, start: int, limit: int, boundaries: set) -> int:
    """Where a block's body ends: at the next line that is "--" and a
    boundary some Content-Type declared (a "-- " signature line is not), or
    at the next "--" line when no boundary is known, or at ``limit``."""
    pos = start
    while True:
        m = _NEXT_PART.search(data, pos, limit)
        if m is None:
            return limit
        token = _LINE_REST.match(data, m.end(), limit).group().rstrip(b" \t")
        if not boundaries or token in boundaries or (token.endswith(b"--") and token[:-2] in boundaries):
            return m.start()
        pos = m.end()


def _read_block(data, block, limit, out, seen_text, seen_att, seen_blocks, urgent, ordinary, decoded_for_links, boundaries):
    from atarus_phishcheck.analyzers.indicators import attachment_is_dangerous
    start, header_end, body_start = block
    header = data[start:header_end]
    fields = _fields(header)
    ctype_raw = (fields.get("content-type") or [""])[0]
    for value in fields.get("content-type", []):
        m = _BOUNDARY_PARAM.search(value)
        if m and len(boundaries) < MAX_BOUNDARIES:
            boundaries.add((m.group(1) or m.group(2)).strip().encode("utf-8", "surrogateescape"))
    body = data[body_start:_body_end(data, body_start, max(body_start, limit), boundaries)]
    key = hashlib.sha1(header + b"\0" + body).digest()
    if key in seen_blocks:
        return
    seen_blocks.add(key)
    disp_raw = (fields.get("content-disposition") or [""])[0]
    cte_raw = (fields.get("content-transfer-encoding") or [""])[0]
    cte = parser._unquote(cte_raw.split(";", 1)[0].split("(", 1)[0]).lower()
    if len(seen_blocks) <= MAX_BLOCKS_READ:
        cparams, dparams = parser._params(ctype_raw), parser._params(disp_raw)
        ctype = cparams.head.replace(" ", "")
        disposition = dparams.head
        names = []
        for value in dparams.all("filename") + dparams.all("name") + cparams.all("name"):
            value = value.strip()
            if value and value not in names:
                names.append(value)
        charset = cparams.first("charset")
        problems = [f"{label}: " + "; ".join(p.problems) for label, p in (("Content-Disposition", dparams), ("Content-Type", cparams)) if p.problems]
        lenient_names = [v for v in dparams.lenient.get("filename", []) + dparams.lenient.get("name", []) + cparams.lenient.get("name", []) if v.strip()]
    else:
        problems, lenient_names = [], []
        ctype = parser._unquote(ctype_raw.split(";", 1)[0]).lower().replace(" ", "")
        disposition = parser._unquote(disp_raw.split(";", 1)[0]).lower()
        names = list(dict.fromkeys(n for n in _names_plain(fields) if n))
        charset = ""
    payload = _decode(body, cte)
    if cte in ("base64", "quoted-printable"):
        decoded_for_links.append(payload)
    if names or disposition == "attachment":
        sha = hashlib.sha256(payload).hexdigest() if payload else ""
        if any((n, sha) in seen_att for n in names) or (not names and ("", sha) in seen_att):
            return  # the structured parse read this one
        entry = {
            "filename": names[0] if names else "",
            "other_names": names[1:parser.MAX_NAMES],
            "name_count": len(names),
            "content_type": ctype if ctype.count("/") == 1 else "application/octet-stream",
            "disposition": disposition,
            "size": len(payload),
            "sha256": sha,
            "md5": hashlib.md5(payload).hexdigest() if payload else "",
            "magic": payload[:4],
            "malformed": problems,
            "lenient_names": lenient_names[:parser.MAX_NAMES],
            "found_by": "raw scan",
        }
        keep = urgent if attachment_is_dangerous(entry) else ordinary
        if len(keep) < MAX_RAW_ATTACHMENTS:
            keep.append(entry)
        else:
            out.attachments_over += 1  # counted, not kept: entries cost memory, and the kept ones already show the pattern
        if not ctype.startswith("text/"):
            return
    if ctype in ("text/html", "text/plain") or (not ctype and not names):
        text = parser.decode_bytes(payload, charset or "utf-8")
        if not text.strip():
            return
        digest = _digest(text)
        if digest in seen_text:
            return
        seen_text.add(digest)
        (out.html if ctype == "text/html" else out.text).append(text)


def merge(body, found: RawScan) -> None:
    """Add what the scan found to an EmailBody, without repeating what the
    structured parse already put there."""
    body.attachments.extend(found.attachments)
    exec_seen = sum(1 for a in body.attachments if (a.get("magic") or b"")[:2] == b"MZ" or (a.get("magic") or b"")[:4] == b"\x7fELF")
    if found.executable_lines > exec_seen:
        body.attachments.append({
            "filename": "", "other_names": [], "name_count": 0, "content_type": "application/octet-stream",
            "disposition": "", "size": 0, "sha256": "", "md5": "", "magic": b"MZ", "malformed": [], "lenient_names": [],
            "found_by": "raw scan",
        })
    budget = parser.MAX_EXTRA_CHARS
    extra_text = [body.extra_text]  # joined once at the end: adding to a string per block copies it each time
    for kind in ("html", "text"):
        for value in getattr(found, kind):
            value = parser.squeeze(value)
            body.raw_scan_text.append(value[:parser.MAX_PART_CHARS])
            if not getattr(body, kind):
                setattr(body, kind, parser._cap_part(body, "HTML" if kind == "html" else "text", value))
                continue
            keep = value[:budget]
            budget -= len(keep)
            if keep:
                (body.extra_html if kind == "html" else extra_text).append(keep)
    if len(extra_text) > 1:
        body.extra_text = "\n".join(extra_text).lstrip("\n")
    known = set(body.urls)
    added = 0
    for url in found.urls:
        if url in known:
            continue
        if added >= parser.MAX_URLS:
            body.urls_capped = True
            body.truncated.append(f"the raw scan found more than {parser.MAX_URLS} further distinct links; only the first {parser.MAX_URLS} were analysed")
            break
        known.add(url)
        body.urls.append(url)
        added += 1
    if found.attachments_over:
        body.truncated.append(f"the raw scan found {found.attachments_over:,} further attachment entries past the {MAX_RAW_ATTACHMENTS:,} it keeps; entries with a dangerous name or content were kept first")
