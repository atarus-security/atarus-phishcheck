"""Extract indicators of compromise from email content"""
import re
import dns.resolver
from urllib.parse import urlparse
from atarus_phishcheck.models import Indicator, EmailHeaders, EmailBody, Finding


SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "loan",
    "zip", "mov", "country", "stream", "download", "racing", "online",
    "bid", "win", "men", "loan", "party", "trade", "date", "review",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "t.co", "tiny.cc", "lnkd.in", "rb.gy", "cutt.ly", "shorturl.at",
    "bit.do", "rebrand.ly", "clck.ru", "soo.gd", "s2r.co",
}


def extract_indicators(headers: EmailHeaders, body: EmailBody) -> tuple:
    """Extract IOCs and check for suspicious patterns. Returns (list[Indicator], list[Finding])"""
    indicators = []
    findings = []

    if headers.from_email:
        indicators.append(Indicator(type="email", value=headers.from_email, context="From header"))
    if headers.reply_to:
        reply_email = _extract_email(headers.reply_to)
        if reply_email and reply_email != headers.from_email:
            indicators.append(Indicator(type="email", value=reply_email, context="Reply-To header"))
            findings.append(Finding(
                category="indicators",
                severity="high",
                title="Reply-To address differs from From address",
                description=f"The email From '{headers.from_email}' but replies would go to '{reply_email}'. This is a common phishing technique to redirect victim responses away from the spoofed sender.",
                recommendation="Verify sender identity through an independent channel. Do not reply to this email without confirming the true destination.",
                evidence=f"From: {headers.from_email}\nReply-To: {reply_email}",
            ))

    if headers.return_path and headers.from_email:
        rp_email = headers.return_path.lower().strip()
        if rp_email and "@" in rp_email:
            rp_domain = rp_email.split("@")[-1]
            if headers.from_domain and rp_domain != headers.from_domain:
                findings.append(Finding(
                    category="indicators",
                    severity="medium",
                    title="Return-Path domain differs from From domain",
                    description=f"The Return-Path domain '{rp_domain}' does not match the From domain '{headers.from_domain}'. While not always malicious (common with mailing lists), this combined with other indicators suggests spoofing.",
                    recommendation="Combined with SPF/DKIM failures, this strongly indicates sender forgery.",
                    evidence=f"From domain: {headers.from_domain}\nReturn-Path domain: {rp_domain}",
                ))

    for url in body.urls:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        domain = parsed.netloc.lower().split(":")[0]
        if domain:
            indicators.append(Indicator(type="url", value=url, context="Email body"))
            indicators.append(Indicator(type="domain", value=domain, context="URL in body"))

            if _is_ip_address(domain):
                findings.append(Finding(
                    category="indicators",
                    severity="high",
                    title=f"URL uses raw IP address: {domain}",
                    description=f"The link '{url}' uses a raw IP address instead of a domain name. Legitimate organizations almost never use raw IPs in customer-facing links.",
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
                    recommendation="Investigate the domain before clicking. Verify through independent channels that the sender legitimately uses this TLD.",
                    evidence=url,
                ))

            base_domain = _get_base_domain(domain)
            if base_domain in URL_SHORTENERS:
                findings.append(Finding(
                    category="indicators",
                    severity="medium",
                    title=f"URL uses a shortener: {base_domain}",
                    description=f"The link '{url}' uses a URL shortener, which hides the actual destination. This is a common technique in phishing to bypass URL reputation checks.",
                    recommendation="Do not click shortener URLs in unsolicited emails. Expand the URL through a safe resolver (e.g. unshorten.it) before evaluating.",
                    evidence=url,
                ))

            if headers.from_domain and _is_lookalike(domain, headers.from_domain):
                findings.append(Finding(
                    category="indicators",
                    severity="high",
                    title=f"Lookalike domain detected: {domain}",
                    description=f"The URL domain '{domain}' appears similar to the sender domain '{headers.from_domain}' but is not identical. This pattern is common in phishing attacks that impersonate trusted brands.",
                    recommendation="Do not interact with this URL. Lookalike domains are a core tactic of credential phishing campaigns.",
                    evidence=f"Sender domain: {headers.from_domain}\nURL domain: {domain}",
                ))

    if headers.x_originating_ip:
        indicators.append(Indicator(type="ip", value=headers.x_originating_ip, context="X-Originating-IP header"))

    for recv in headers.received_chain:
        ips = re.findall(r'\[(\d+\.\d+\.\d+\.\d+)\]', recv)
        for ip in ips:
            indicators.append(Indicator(type="ip", value=ip, context="Received header"))

    for att in body.attachments:
        filename = att.get("filename", "")
        if filename:
            indicators.append(Indicator(type="file", value=filename, context=f"Attachment ({att.get('content_type', 'unknown')})"))

            dangerous_ext = (".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js", ".jar", ".hta", ".lnk", ".iso", ".img")
            if filename.lower().endswith(dangerous_ext):
                findings.append(Finding(
                    category="indicators",
                    severity="high",
                    title=f"Dangerous attachment type: {filename}",
                    description=f"The attachment '{filename}' is an executable or script file type commonly used to deliver malware.",
                    recommendation="Do not open this attachment. Executable attachments in unsolicited email are almost always malicious.",
                    evidence=f"Filename: {filename}\nContent-Type: {att.get('content_type', 'unknown')}",
                ))

            if filename.lower().endswith((".docm", ".xlsm", ".pptm")):
                findings.append(Finding(
                    category="indicators",
                    severity="medium",
                    title=f"Macro-enabled attachment: {filename}",
                    description=f"The attachment '{filename}' is a macro-enabled Office document. Macros are a primary infection vector for malware including banking trojans and ransomware.",
                    recommendation="Do not enable macros. Verify necessity with the sender through an independent channel.",
                    evidence=f"Filename: {filename}",
                ))

            double_ext = re.search(r'\.(pdf|doc|xls|ppt|txt|jpg|png)\.(exe|scr|js|vbs|bat|cmd|com)$', filename.lower())
            if double_ext:
                findings.append(Finding(
                    category="indicators",
                    severity="high",
                    title=f"Double extension attachment: {filename}",
                    description=f"The attachment '{filename}' uses a double extension. This is a deception technique to make executables appear as safe file types.",
                    recommendation="This attachment is almost certainly malicious. Do not open under any circumstances.",
                    evidence=f"Filename: {filename}",
                ))

    return indicators, findings


def _extract_email(s: str) -> str:
    m = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', s)
    return m.group(0).lower() if m else ""


def _is_ip_address(s: str) -> bool:
    return bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', s))


def _get_base_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _is_lookalike(url_domain: str, sender_domain: str) -> bool:
    if url_domain == sender_domain:
        return False

    sender_base = _get_base_domain(sender_domain)
    url_base = _get_base_domain(url_domain)

    if sender_base == url_base:
        return False

    sender_name = sender_base.split(".")[0]
    url_name = url_base.split(".")[0]

    if sender_name in url_name and sender_name != url_name:
        return True
    if url_name in sender_name and sender_name != url_name:
        return True

    if len(sender_name) >= 4 and _levenshtein(sender_name, url_name) <= 2 and len(url_name) >= 4:
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
