"""Parse raw email content into structured headers and body"""
import email
import email.policy
import re
from email import message_from_string
from atarus_phishcheck.models import EmailHeaders, EmailBody


def parse_email(raw_content: str) -> tuple:
    """Parse raw email (.eml content or pasted headers+body) into structured data"""
    msg = message_from_string(raw_content, policy=email.policy.default)
    headers = _extract_headers(msg, raw_content)
    body = _extract_body(msg)
    return headers, body


def _extract_headers(msg, raw_content: str) -> EmailHeaders:
    h = EmailHeaders()
    h.raw = raw_content

    h.from_header = str(msg.get("From", ""))
    h.from_name, h.from_email = _parse_address(h.from_header)
    h.from_domain = h.from_email.split("@")[-1].lower() if "@" in h.from_email else ""

    h.reply_to = str(msg.get("Reply-To", ""))
    h.return_path = str(msg.get("Return-Path", "")).strip("<>")
    h.to = str(msg.get("To", ""))
    h.subject = str(msg.get("Subject", ""))
    h.date = str(msg.get("Date", ""))
    h.message_id = str(msg.get("Message-ID", ""))
    h.x_mailer = str(msg.get("X-Mailer", ""))
    h.x_originating_ip = str(msg.get("X-Originating-IP", "")).strip("[]")
    h.authentication_results = str(msg.get("Authentication-Results", ""))
    h.dkim_signature = str(msg.get("DKIM-Signature", ""))
    h.received_spf = str(msg.get("Received-SPF", ""))

    received_headers = msg.get_all("Received") or []
    h.received_chain = [str(r) for r in received_headers]

    return h


def _extract_body(msg) -> EmailBody:
    b = EmailBody()

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get("Content-Disposition", ""))

            if "attachment" in cdisp:
                filename = part.get_filename()
                if filename:
                    b.attachments.append({
                        "filename": filename,
                        "content_type": ctype,
                        "size": len(part.get_payload(decode=True) or b""),
                    })
                continue

            try:
                payload = part.get_content()
                if ctype == "text/plain" and not b.text:
                    b.text = str(payload)
                elif ctype == "text/html" and not b.html:
                    b.html = str(payload)
            except Exception:
                pass
    else:
        try:
            payload = msg.get_content()
            ctype = msg.get_content_type()
            if ctype == "text/html":
                b.html = str(payload)
            else:
                b.text = str(payload)
        except Exception:
            b.text = str(msg.get_payload() or "")

    b.urls = _extract_urls(b.text + " " + b.html)
    return b


def _parse_address(addr: str) -> tuple:
    if not addr:
        return "", ""
    m = re.match(r'^"?([^"<]*)"?\s*<([^>]+)>', addr.strip())
    if m:
        return m.group(1).strip(), m.group(2).strip().lower()
    m = re.match(r'^([^\s@]+@[^\s@]+)', addr.strip())
    if m:
        return "", m.group(1).strip().lower()
    return addr.strip(), ""


def _extract_urls(text: str) -> list:
    if not text:
        return []
    pattern = r'https?://[^\s<>"\'\)]+|www\.[^\s<>"\'\)]+'
    urls = re.findall(pattern, text)
    cleaned = []
    seen = set()
    for u in urls:
        u = u.rstrip('.,;:!?)')
        if u not in seen:
            seen.add(u)
            cleaned.append(u)
    return cleaned
