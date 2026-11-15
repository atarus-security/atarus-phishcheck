"""Extract indicators of compromise from email content"""
import ipaddress
import re
import unicodedata
from atarus_phishcheck.analyzers.parser import url_hostname, canonical_domain, _address_list, MAX_MAILBOXES, MAX_NAMES, MAX_URLS
from atarus_phishcheck.network import host_as_ip
from atarus_phishcheck.analyzers.urlexpand import SHORTENER_DOMAINS
from atarus_phishcheck.models import Indicator, EmailHeaders, EmailBody, Finding


SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "loan",
    "zip", "mov", "country", "stream", "download", "racing", "online",
    "bid", "win", "men", "loan", "party", "trade", "date", "review",
}

# One list for the offline shortener finding and for --expand-links.
URL_SHORTENERS = SHORTENER_DOMAINS


def extract_indicators(headers: EmailHeaders, body: EmailBody) -> tuple:
    """Extract IOCs and check for suspicious patterns. Returns (list[Indicator], list[Finding])"""
    indicators = []
    findings = []

    if headers.from_email:
        indicators.append(Indicator(type="email", value=headers.from_email, context="From header"))

    findings.extend(_malformed_header_findings(headers.malformed))
    if headers.header_count and not headers.from_email:
        findings.append(Finding(
            category="technical",
            severity="medium",
            title="No sender address could be read" if headers.from_header_count else "Message has no From header",
            description="RFC 5322 requires a From header with an address. Without one the sender cannot be checked against the domain the message claims, and mail clients show whatever text is there.",
            recommendation="Treat the sender as unknown and verify the message through a channel you already trust.",
            evidence=("From: " + headers.from_header[:300]) if headers.from_header_count else "",
        ))

    if headers.from_header_count > 1:
        findings.append(Finding(
            category="indicators",
            severity="high",
            title="Message has more than one From header",
            description=f"RFC 5322 allows exactly one From header. With more than one, mail clients and filters can disagree about the sender: one may show the first and another check the last. This is a known technique for showing a trusted sender while authentication runs against another. The analysis here uses the first From header. This message has {headers.from_header_count:,}.",
            recommendation="Treat the displayed sender as unverified. Look at every From header in the raw source and at the Authentication-Results header before trusting the message.",
            evidence="From headers: " + str(headers.from_header_count),
        ))
    if len(headers.from_addresses) > 1:
        extra = headers.from_addresses[1:]
        for address in extra:
            indicators.append(Indicator(type="email", value=address, context="From header (additional mailbox)"))
        count = f"more than {MAX_MAILBOXES}" if headers.from_more_mailboxes else str(len(headers.from_addresses))
        findings.append(Finding(
            category="indicators",
            severity="medium",
            title=f"From header names {count} mailboxes",
            description=f"The From header lists more than one address. That is allowed only with a Sender header and is almost never seen in real mail; mail clients may display any of them. The analysis here uses the first, '{headers.from_email}'.",
            recommendation="Check each address listed and treat the sender as unverified.",
            evidence="From: " + ", ".join(headers.from_addresses),
        ))
    if headers.reply_to:
        reply_email = headers.reply_to_email
        if reply_email and not _same_address(reply_email, headers.from_email):
            indicators.append(Indicator(type="email", value=reply_email, context="Reply-To header"))
            findings.append(Finding(
                category="indicators",
                severity="high",
                title="Reply-To address differs from From address",
                description=f"The email From '{headers.from_email}' but replies would go to '{reply_email}'. This is a common phishing technique to redirect victim responses away from the spoofed sender.",
                recommendation="Verify sender identity through an independent channel. Do not reply to this email without confirming the true destination.",
                evidence=f"From: {headers.from_email}\nReply-To: {reply_email}",
            ))

    if headers.return_path and headers.from_domain:
        rp_email = headers.return_path.lower().strip()
        if rp_email and "@" in rp_email:
            rp_domain = rp_email.split("@")[-1].rstrip(".")
            if canonical_domain(rp_domain) != canonical_domain(headers.from_domain):
                findings.append(Finding(
                    category="indicators",
                    severity="medium",
                    title="Return-Path domain differs from From domain",
                    description=f"The Return-Path domain '{rp_domain}' does not match the From domain '{headers.from_domain}'. While not always malicious (common with mailing lists), this combined with other indicators suggests spoofing.",
                    recommendation="Combined with SPF/DKIM failures, this strongly indicates sender forgery.",
                    evidence=f"From domain: {headers.from_domain}\nReturn-Path domain: {rp_domain}",
                ))

    senders = [d for d in (headers.sender_candidates or [headers.from_domain]) if d and len(d) <= MAX_HOSTNAME][:5]
    for url in body.urls:
        domain = url_hostname(url)
        if len(domain) > MAX_HOSTNAME:
            continue
        if domain:
            indicators.append(Indicator(type="url", value=url, context="Email body"))
            indicators.append(Indicator(type="domain", value=domain, context="URL in body"))

            if _is_ip_address(domain):
                findings.append(Finding(
                    category="indicators",
                    severity="high",
                    title=f"URL uses raw IP address: {domain}",
                    description=f"The link '{url}' uses a raw IP address instead of a domain name. Established organizations almost never use raw IPs in customer-facing links.",
                    recommendation="Do not click. This is a strong phishing indicator, especially when combined with urgency or authority impersonation in the email body.",
                    evidence=url,
                ))
                continue

            tld = domain.split(".")[-1]
            if tld in SUSPICIOUS_TLDS:
                findings.append(Finding(
                    category="indicators",
                    severity="medium",
                    title=f"URL uses suspicious TLD: .{tld}",
                    description=f"The link '{url}' uses the '.{tld}' top-level domain. This TLD is frequently abused for phishing due to low registration cost and lax abuse enforcement.",
                    recommendation="Investigate the domain before clicking. Verify through independent channels that the sender really uses this TLD.",
                    evidence=url,
                ))

            base_domain = _get_base_domain(domain)
            if base_domain in URL_SHORTENERS:
                findings.append(Finding(
                    category="indicators",
                    severity="medium",
                    title=f"URL uses a shortener: {base_domain}",
                    description=f"The link '{url}' uses a URL shortener, which hides the actual destination. This is a common technique in phishing to bypass URL reputation checks.",
                    recommendation="Do not click shortener URLs in unsolicited emails. Expand the URL through a safe resolver (or this tool's --online --expand-links option) before evaluating.",
                    evidence=url,
                ))

            sender = next((s for s in senders if _is_lookalike(domain, s)), "")
            if sender:
                findings.append(Finding(
                    category="indicators",
                    severity="high",
                    title=f"Lookalike domain detected: {domain}",
                    description=f"The URL domain '{domain}' appears similar to the sender domain '{sender}' but is not identical. This pattern is common in phishing attacks that impersonate trusted brands.",
                    recommendation="Do not interact with this URL. Lookalike domains are a core tactic of credential phishing campaigns.",
                    evidence=f"Sender domain: {sender}\nURL domain: {domain}",
                ))
    if body.urls_capped:
        findings.append(Finding(
            category="indicators",
            severity="low",
            title=f"Message has more than {MAX_URLS} distinct links",
            description=f"Only the first {MAX_URLS} distinct links were analysed. Ordinary mail rarely carries this many; a large number of links can be used to push a malicious one past a check that stops early.",
            recommendation="Review the links in the raw source.",
        ))

    if headers.x_originating_ip:
        indicators.append(Indicator(type="ip", value=headers.x_originating_ip, context="X-Originating-IP header"))

    for recv in headers.received_chain:
        for ip in _received_ips(recv):
            indicators.append(Indicator(type="ip", value=ip, context="Received header"))

    for att in body.attachments:
        # Every name the part gives (Content-Disposition filename and
        # Content-Type name can differ, and either may be the one a mail
        # client shows), each read in full however much padding precedes it,
        # plus every name a tolerant reading of malformed headers found.
        names = [att.get("filename", "")] + list(att.get("other_names", []))
        flagged_exec = False
        for filename in names:
            if not filename:
                continue
            indicators.append(Indicator(type="file", value=filename, context=f"Attachment ({att.get('content_type', 'unknown')})"))
            check, hidden = _name_as_shown(filename)
            if hidden:
                findings.append(Finding(
                    category="indicators",
                    severity="high",
                    title=f"Attachment name holds hidden or direction-changing characters: {filename!a}",
                    description=f"The attachment name contains {hidden}. Right-to-left overrides and similar characters make a name display in a different order than it is stored, so 'photo\\u202egpj.exe' is shown as 'photoexe.jpg'. Trailing dots and spaces are dropped by Windows, so 'invoice.exe.' opens as 'invoice.exe'. The checks below ran on '{check}'.",
                    recommendation="Do not open this attachment. A name written to display differently from what it is has no ordinary use.",
                    evidence=f"Filename (escaped): {filename!a}\nContent-Type: {att.get('content_type', 'unknown')}",
                ))
            lower = check.lower()
            if lower.endswith(DANGEROUS_EXTENSIONS):
                flagged_exec = True
                findings.append(Finding(
                    category="indicators",
                    severity="high",
                    title=f"Dangerous attachment type: {filename}",
                    description=f"The attachment '{filename}' is an executable or script file type commonly used to deliver malware.",
                    recommendation="Do not open this attachment. Executable attachments in unsolicited email are almost always malicious.",
                    evidence=f"Filename: {filename}\nContent-Type: {att.get('content_type', 'unknown')}",
                ))

            if lower.endswith((".docm", ".xlsm", ".pptm")):
                findings.append(Finding(
                    category="indicators",
                    severity="medium",
                    title=f"Macro-enabled attachment: {filename}",
                    description=f"The attachment '{filename}' is a macro-enabled Office document. Macros are a primary infection vector for malware including banking trojans and ransomware.",
                    recommendation="Do not enable macros. Verify necessity with the sender through an independent channel.",
                    evidence=f"Filename: {filename}",
                ))

            double_ext = _DOUBLE_EXTENSION.search(lower)
            if double_ext:
                findings.append(Finding(
                    category="indicators",
                    severity="high",
                    title=f"Double extension attachment: {filename}",
                    description=f"The attachment '{filename}' uses a double extension. This is a deception technique to make executables appear as safe file types.",
                    recommendation="This attachment is almost certainly malicious. Do not open under any circumstances.",
                    evidence=f"Filename: {filename}",
                ))

        ctype = (att.get("content_type") or "").lower()
        magic = att.get("magic") or b""
        if not flagged_exec and (ctype in EXECUTABLE_TYPES or magic[:2] == b"MZ" or magic[:4] == b"\x7fELF"):
            what = f"its Content-Type is {ctype}" if ctype in EXECUTABLE_TYPES else "its content starts with an executable file header"
            findings.append(Finding(
                category="indicators",
                severity="high",
                title=f"Executable attachment content: {(att.get('filename') or '(unnamed attachment)')!a}",
                description=f"The attachment is a program: {what}, whatever its name says. A file with no name, or a harmless-looking name, can still be saved and run.",
                recommendation="Do not open this attachment.",
                evidence=f"Filename: {att.get('filename') or '(none)'}\nContent-Type: {ctype}\nFirst bytes: {magic[:4].hex()}",
            ))

        if att.get("name_count", 0) > MAX_NAMES:
            findings.append(Finding(
                category="indicators",
                severity="high",
                title=f"Attachment gives more than {MAX_NAMES} file names",
                description=f"One MIME part names about {att['name_count']:,} files; ordinary mail gives one, sometimes two that agree. The first {MAX_NAMES} distinct names were checked. A long list of names is a way to bury the one a mail client shows.",
                recommendation="Do not open this attachment; read its headers in the raw source.",
                evidence=f"First names: {', '.join(names[:5])[:300]}",
            ))

    malformed_parts = [att for att in body.attachments if att.get("malformed")]
    if malformed_parts:
        # One finding for the family, with a count. Points only when a
        # tolerant reading found a name the strict one did not and a name
        # check fires on it: then readers disagree on what the file is.
        disagree = [att for att in malformed_parts if any(_name_flagged(n) for n in att.get("lenient_names") or [])]
        shown = disagree or malformed_parts
        findings.append(Finding(
            category="technical",
            severity="medium" if disagree else "info",
            title="Attachment headers are malformed",
            description=(f"{len(malformed_parts):,} attachment part header(s) do not follow the MIME grammar, for example "
                         + ascii((shown[0].get("filename") or "(unnamed attachment)"))[:200] + ": " + "; ".join(shown[0]["malformed"])[:400]
                         + ". Mail clients can read such a header differently from this tool, so a tolerant reading was run as well "
                         "and every name it found was checked"
                         + (". The readings disagree on a file name a check uses: " + ", ".join(ascii(n) for a in disagree for n in (a.get("lenient_names") or [])[:3])[:300]
                            if disagree else "; the readings agree on what every check uses") + "."),
            recommendation="Read the part headers in the raw source before opening the attachments.",
            evidence="Names checked: " + ", ".join(ascii(a.get("filename") or "(unnamed)") for a in shown[:5])[:300],
        ))

    if body.part_problems:
        findings.append(Finding(
            category="technical",
            severity="info",
            title="MIME part header is malformed",
            description="A part header does not follow the MIME grammar: " + "; ".join(dict.fromkeys(body.part_problems))[:400] + ". It was read tolerantly, so the part's content was still analysed.",
            recommendation="Read the part headers in the raw source.",
        ))

    return indicators, findings


MAX_HOSTNAME = 253

DANGEROUS_EXTENSIONS = (".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js", ".jar", ".hta", ".lnk", ".iso", ".img")
_DOUBLE_EXTENSION = re.compile(r'\.(pdf|doc|xls|ppt|txt|jpg|png)\.(exe|scr|js|vbs|bat|cmd|com)$')
EXECUTABLE_TYPES = {
    "application/x-msdownload", "application/x-msdos-program", "application/x-dosexec", "application/x-ms-dos-executable",
    "application/vnd.microsoft.portable-executable", "application/x-executable", "application/x-ms-installer",
    "application/x-msi", "application/hta", "application/x-ms-shortcut", "application/x-bat", "application/x-sh",
    "application/java-archive", "application/x-java-archive",
}


_FAMILY = {
    "address": ("Address headers are malformed", "address header(s)", "RFC 5322",
                "Mail clients, filters and this tool can read such a header differently, which is how a sender is shown as one address "
                "while checks run against another. Every check here ran on every reading.",
                "Read the header in the raw source and treat the sender as unverified."),
    "names": ("Header names are malformed", "header name(s)", "RFC 5322",
              "Some mail software ignores such a header or takes it as the start of the body, while others show it. It was read as a header.",
              "Read the headers in the raw source."),
}


def _malformed_header_findings(problems: list) -> list:
    """One finding per family of malformed headers, with a count. A family
    scores (medium) only when the strict and lenient readings disagree on a
    value a check uses; otherwise it is recorded at info severity."""
    out = []
    for family, (title, noun, grammar, why, advice) in _FAMILY.items():
        entries = [p for p in problems if p.get("family", "address") == family]
        if not entries:
            continue
        disagree = [p for p in entries if p.get("disagree")]
        shown = disagree or entries
        names = ", ".join(dict.fromkeys(p["header"] for p in entries))
        out.append(Finding(
            category="technical",
            severity="medium" if disagree else "info",
            title=title,
            description=(f"{len(entries):,} {noun} ({names[:200]}) do not follow the {grammar} grammar. {shown[0]['header']}: "
                         f"{shown[0]['reason'][:600]}. {why}"
                         + ("" if disagree else " The readings agree on every value the checks use.")),
            recommendation=advice,
            evidence=shown[0].get("evidence", ""),
        ))
    return out


def _name_flagged(name: str) -> bool:
    """True when a name check (dangerous, macro or double extension, hidden characters) fires on this name."""
    shown, hidden = _name_as_shown(name or "")
    lower = shown.lower()
    return bool(hidden) or lower.endswith(DANGEROUS_EXTENSIONS) or lower.endswith((".docm", ".xlsm", ".pptm")) or bool(_DOUBLE_EXTENSION.search(lower))


def attachment_is_dangerous(att: dict) -> bool:
    """True when an attachment entry would raise a high or medium attachment
    finding: a dangerous, macro or double extension, a hidden character in
    a name, or executable content or type."""
    magic = att.get("magic") or b""
    if (att.get("content_type") or "").lower() in EXECUTABLE_TYPES or magic[:2] == b"MZ" or magic[:4] == b"\x7fELF":
        return True
    return any(_name_flagged(name) for name in [att.get("filename", "")] + list(att.get("other_names", [])))


def _name_as_shown(filename: str) -> tuple:
    """(the name as a file system or a reader sees it, what was hidden or '').
    Format characters (direction overrides, zero-width marks) are removed,
    as are surrounding quotes and the trailing dots and spaces Windows
    drops."""
    hidden = []
    if any(unicodedata.category(ch) == "Cf" for ch in filename):
        hidden.append("invisible or text-direction characters (" + ", ".join(sorted({f"U+{ord(c):04X}" for c in filename if unicodedata.category(c) == "Cf"}))[:200] + ")")
        filename = "".join(ch for ch in filename if unicodedata.category(ch) != "Cf")
    stripped = filename.strip().strip("\"'").rstrip(". ")
    if stripped != filename.strip().strip("\"'") and stripped:
        hidden.append("trailing dots or spaces")
    return (stripped or filename), " and ".join(hidden)


def _received_ips(recv: str) -> list:
    """Bracketed address literals in a Received header, IPv4 and IPv6
    (``[192.0.2.1]``, ``[2001:db8::1]``, ``[IPv6:2001:db8::1]``), validated."""
    found = {}
    for literal in _ADDRESS_LITERAL.findall(recv):
        candidate = literal[5:] if literal.lower().startswith("ipv6:") else literal
        try:
            ip = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
        found[ip] = None  # a dict keeps the order and finds repeats in constant time
        if len(found) >= MAX_RECEIVED_IPS:
            break
    return list(found)


MAX_RECEIVED_IPS = 50  # per Received header
_ADDRESS_LITERAL = re.compile(r'\[([0-9A-Za-z:.]{2,60})\]')


def _extract_email(s: str) -> str:
    """First address in a header value, read as the parser reads it."""
    mailboxes = _address_list(s)["mailboxes"]
    return mailboxes[0][1] if mailboxes else ""


def _is_ip_address(s: str) -> bool:
    """True for any host a browser would treat as an IP address: IPv4,
    IPv6 (with or without brackets), and the legacy forms browsers still
    accept, such as 3232235777, 0x7f000001 and 127.1."""
    return host_as_ip(s) is not None


# Common two-label public suffixes. Without them the "base domain" of
# shop.co.uk was co.uk and its name "co", which matched any URL containing
# "co" (tesco.com, cocacola.com) as a lookalike of the sender.
TWO_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "co.kr", "or.kr", "co.in", "net.in", "org.in",
    "co.za", "org.za", "com.br", "net.br", "org.br", "com.mx", "com.ar", "com.cn",
    "com.hk", "com.sg", "com.tr", "com.tw", "co.il", "co.id", "com.my", "com.ph",
}

MIN_LOOKALIKE_NAME = 4  # shorter names (x, ab, co) are substrings of too many real domains


def _get_base_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LABEL_SUFFIXES:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _same_address(a: str, b: str) -> bool:
    """True when two addresses have the same local part and the same domain
    in canonical IDNA form."""
    local_a, _, domain_a = a.rpartition("@")
    local_b, _, domain_b = b.rpartition("@")
    return local_a == local_b and canonical_domain(domain_a) == canonical_domain(domain_b)


def _is_lookalike(url_domain: str, sender_domain: str) -> bool:
    if len(sender_domain) > MAX_HOSTNAME or len(url_domain) > MAX_HOSTNAME:
        return False
    if canonical_domain(url_domain) == canonical_domain(sender_domain):
        return False

    sender_base = _get_base_domain(sender_domain)
    url_base = _get_base_domain(url_domain)

    if canonical_domain(sender_base) == canonical_domain(url_base):
        return False

    sender_name = sender_base.split(".")[0]
    url_name = url_base.split(".")[0]

    if sender_name == url_name:
        # The same name under another top-level domain (example.test and
        # example.net) was flagged before the two-label suffix list existed,
        # through the edit-distance rule below; it still is, for names of
        # at least MIN_LOOKALIKE_NAME characters outside that list.
        plain_sender, plain_url = sender_domain.split(".")[-2:], url_domain.split(".")[-2:]
        return (len(sender_name) >= MIN_LOOKALIKE_NAME and plain_sender[0] == sender_name and plain_url[0] == url_name)
    if len(sender_name) >= MIN_LOOKALIKE_NAME and sender_name in url_name:
        return True
    if len(url_name) >= MIN_LOOKALIKE_NAME and url_name in sender_name:
        return True

    if len(sender_name) >= MIN_LOOKALIKE_NAME and _levenshtein(sender_name, url_name) <= 2 and len(url_name) >= MIN_LOOKALIKE_NAME:
        return True

    return False


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    previous = range(len(b) + 1)
    for i, ca in enumerate(a):
        current = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous[j + 1] + 1
            deletions = current[j] + 1
            substitutions = previous[j] + (ca != cb)
            current.append(min(insertions, deletions, substitutions))
        previous = current
    return previous[-1]
