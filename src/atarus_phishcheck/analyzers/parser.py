"""Parse raw email content into structured headers and body.

Input limits: the file read is capped (MAX_INPUT_BYTES), each header value
is cut at MAX_HEADER_CHARS and each body part at MAX_PART_CHARS before any
pattern matching runs. Truncation is recorded in EmailBody.truncated so the
report can say what was not analysed.
"""
import email
import email.policy
import email.utils
import os
import re
from email import message_from_string
from atarus_phishcheck.models import EmailHeaders, EmailBody

MAX_INPUT_BYTES = 25 * 1024 * 1024  # one email file, attachments included
MAX_HEADER_CHARS = 4096  # per header value
MAX_PART_CHARS = 1_000_000  # per text or HTML body part
MAX_URL_CHARS = 2048
MAX_URLS = 500

# Only ever applied to one URL token at a time; no nested quantifiers.
_URL_PATTERN = re.compile(r'https?://[^\s<>"\'\)]+|www\.[^\s<>"\'\)]+')


class InputTooLarge(ValueError):
    pass


def read_email_file(path: str) -> str:
    """Read an email file with the size cap applied before anything is parsed."""
    size = os.path.getsize(path)
    if size > MAX_INPUT_BYTES:
        raise InputTooLarge(f"{path} is {size} bytes; the limit is {MAX_INPUT_BYTES} bytes")
    with open(path, "rb") as f:
        data = f.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise InputTooLarge(f"{path} exceeds the {MAX_INPUT_BYTES} byte limit")
    return data.decode("utf-8", errors="replace")


def parse_email(raw_content: str) -> tuple:
    """Parse raw email (.eml content or pasted headers+body) into structured data"""
    if len(raw_content.encode("utf-8", errors="replace")) > MAX_INPUT_BYTES:
        raise InputTooLarge(f"input exceeds the {MAX_INPUT_BYTES} byte limit")
    msg = message_from_string(raw_content, policy=email.policy.default)
    headers = _extract_headers(msg, raw_content)
    body = _extract_body(msg)
    return headers, body


def _hdr(msg, name: str) -> str:
    try:
        value = msg.get(name, "")
    except Exception:
        return ""
    value = "" if value is None else str(value)
    return value[:MAX_HEADER_CHARS]


def _extract_headers(msg, raw_content: str) -> EmailHeaders:
    h = EmailHeaders()
    h.raw = raw_content

    h.from_header = _hdr(msg, "From")
    h.from_name, h.from_email = _parse_address(h.from_header)
    h.from_domain = h.from_email.split("@")[-1].lower() if "@" in h.from_email else ""

    h.reply_to = _hdr(msg, "Reply-To")
    h.return_path = _hdr(msg, "Return-Path").strip("<>")
    h.to = _hdr(msg, "To")
    h.subject = _hdr(msg, "Subject")
    h.date = _hdr(msg, "Date")
    h.message_id = _hdr(msg, "Message-ID")
    h.x_mailer = _hdr(msg, "X-Mailer")
    h.x_originating_ip = _hdr(msg, "X-Originating-IP").strip("[]")
    h.authentication_results = _hdr(msg, "Authentication-Results")
    h.dkim_signature = _hdr(msg, "DKIM-Signature")
    h.received_spf = _hdr(msg, "Received-SPF")

    try:
        received_headers = msg.get_all("Received") or []
    except Exception:
        received_headers = []
    h.received_chain = [str(r)[:MAX_HEADER_CHARS] for r in received_headers[:100]]

    return h


def _cap_part(body: EmailBody, label: str, value: str) -> str:
    if len(value) > MAX_PART_CHARS:
        body.truncated.append(f"{label} part cut at {MAX_PART_CHARS} characters ({len(value)} present); the rest was not analysed")
        return value[:MAX_PART_CHARS]
    return value


def _extract_body(msg) -> EmailBody:
    b = EmailBody()

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get("Content-Disposition", ""))

            if "attachment" in cdisp:
                filename = part.get_filename()
                if filename:
                    try:
                        size = len(part.get_payload(decode=True) or b"")
                    except Exception:
                        size = 0
                    b.attachments.append({
                        "filename": str(filename)[:MAX_HEADER_CHARS],
                        "content_type": ctype,
                        "size": size,
                    })
                continue

            try:
                payload = part.get_content()
                if ctype == "text/plain" and not b.text:
                    b.text = _cap_part(b, "text", str(payload))
                elif ctype == "text/html" and not b.html:
                    b.html = _cap_part(b, "HTML", str(payload))
            except Exception:
                pass
    else:
        try:
            payload = msg.get_content()
            ctype = msg.get_content_type()
            if ctype == "text/html":
                b.html = _cap_part(b, "HTML", str(payload))
            else:
                b.text = _cap_part(b, "text", str(payload))
        except Exception:
            b.text = _cap_part(b, "text", str(msg.get_payload() or ""))

    b.urls = _extract_urls(b.text + " " + b.html)
    return b


def _parse_address(addr: str) -> tuple:
    """(display name, address) using the standard library address parser."""
    if not addr:
        return "", ""
    name, address = email.utils.parseaddr(addr.strip())
    if "@" not in address:
        return addr.strip(), ""
    return name.strip(), address.strip().lower()


def _extract_urls(text: str) -> list:
    if not text:
        return []
    cleaned = []
    seen = set()
    for m in _URL_PATTERN.finditer(text):
        u = m.group(0)[:MAX_URL_CHARS].rstrip('.,;:!?)')
        if u not in seen:
            seen.add(u)
            cleaned.append(u)
            if len(cleaned) >= MAX_URLS:
                break
    return cleaned
