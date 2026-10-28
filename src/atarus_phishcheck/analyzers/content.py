"""Analyze email content for phishing language patterns"""
import re
from atarus_phishcheck.models import EmailHeaders, EmailBody, Finding
from atarus_phishcheck.analyzers.htmlscan import strip_tags, iter_tags, iter_anchors, attr_value


URGENCY_PATTERNS = [
    r'\b(urgent|urgently|immediately|right away|asap|as soon as possible)\b',
    r'\b(act now|expires? (today|tomorrow|in \d+ hours?)|within \d+ hours?)\b',
    r'\b(suspend(ed|ing)?|terminat(ed|ing)?|deactivat(ed|ing)?|limit(ed|ing)?) (your )?(account|access)\b',
    r'\b(last chance|final (notice|warning)|final opportunity)\b',
    r'\b(verify|confirm|update|validate) (your )?(account|identity|information|password|credentials)\b',
    r'\bfailure to (act|respond|comply)\b',
]

CREDENTIAL_PATTERNS = [
    r'\b(click (here|below|the link|this link))\b',
    r'\b(log ?in|sign ?in) (here|below|now)\b',
    r'\b(enter|provide|confirm) (your )?(password|username|credentials|PIN|2FA|one.?time code)\b',
    r'\b(reset|change|update) (your )?password\b',
    r'\b(your )?(password|account) (will|has been|is about to) expir',
]

AUTHORITY_PATTERNS = [
    r'\b(IT (support|department|team|helpdesk)|system administrator)\b',
    r'\b(security (team|department|alert))\b',
    r'\b(account team|billing department|payroll department)\b',
    r'\b(CEO|CFO|CIO|CISO|president|director|manager) (urgent|request|asked)\b',
]

FINANCIAL_PATTERNS = [
    r'\b(wire transfer|bank transfer|payment (pending|due|overdue))\b',
    r'\b(invoice attached|receipt attached)\b',
    r'\b(gift card|iTunes card|Amazon card|bitcoin|cryptocurrency)\b',
    r'\b(tax (refund|rebate)|IRS|stimulus (check|payment))\b',
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer", "dear sir/madam",
    "dear member", "dear account holder", "hello dear", "attention customer",
]


def analyze_content(headers: EmailHeaders, body: EmailBody) -> list:
    """Analyze email content for phishing patterns. Returns list of Findings."""
    findings = []

    text = (body.text + " " + _strip_html(body.html) + " " + headers.subject).lower()

    urgency_matches = _count_matches(text, URGENCY_PATTERNS)
    if urgency_matches >= 2:
        findings.append(Finding(
            category="content",
            severity="medium" if urgency_matches >= 3 else "low",
            title=f"Urgency language detected ({urgency_matches} matches)",
            description="The email uses language designed to pressure the recipient into acting quickly. Urgency is one of the most common social engineering tactics in phishing.",
            recommendation="Pause and verify through a trusted channel before taking any action. Legitimate organizations rarely demand immediate action via email.",
        ))

    cred_matches = _count_matches(text, CREDENTIAL_PATTERNS)
    if cred_matches >= 1:
        findings.append(Finding(
            category="content",
            severity="medium",
            title=f"Credential-harvesting language detected ({cred_matches} matches)",
            description="The email contains language typical of credential phishing: requesting login, password verification, or account validation.",
            recommendation="Never enter credentials via links in email. Navigate to the legitimate site directly through a bookmark or typed URL.",
        ))

    auth_matches = _count_matches(text, AUTHORITY_PATTERNS)
    if auth_matches >= 1:
        findings.append(Finding(
            category="content",
            severity="low",
            title="Authority impersonation language",
            description="The email references IT, security, executive, or administrative authority. Attackers use authority claims to discourage questioning.",
            recommendation="Verify the sender through the organization's known directory or by calling a known phone number.",
        ))

    financial_matches = _count_matches(text, FINANCIAL_PATTERNS)
    if financial_matches >= 1:
        findings.append(Finding(
            category="content",
            severity="medium",
            title="Financial or payment-related language",
            description="The email discusses money, payments, or financial instruments commonly abused in phishing (gift cards, wire transfers, invoices).",
            recommendation="Any request involving money via email, especially unusual payment methods, requires verification through a known-good channel.",
        ))

    for greeting in GENERIC_GREETINGS:
        if greeting in text:
            findings.append(Finding(
                category="content",
                severity="low",
                title=f"Generic greeting: '{greeting}'",
                description="The email uses a generic greeting rather than addressing the recipient by name. Legitimate automated emails from services you use typically personalize with your name.",
                recommendation="Combined with other indicators, generic greetings suggest mass-distributed phishing.",
            ))
            break

    if body.html:
        if _hidden_text_in_html(body.html):
            findings.append(Finding(
                category="content",
                severity="high",
                title="Hidden text detected in HTML body",
                description="The HTML body contains hidden text (invisible characters, white-on-white, zero font size, or display:none). This is a technique to bypass content filters while displaying attacker-chosen content to the user.",
                recommendation="Examine the raw HTML before interacting. Hidden text combined with deceptive visible content is a strong malicious indicator.",
            ))

        if _mismatched_link_text(body.html):
            findings.append(Finding(
                category="content",
                severity="high",
                title="Link text does not match URL destination",
                description="The visible text of one or more links does not match the actual URL. For example, the text says 'https://bank.com' but the href points elsewhere.",
                recommendation="Always verify link destinations by hovering or inspecting the raw HTML before clicking. Mismatched link text is a hallmark of phishing.",
            ))

    return findings


def _count_matches(text: str, patterns: list) -> int:
    count = 0
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            count += 1
    return count


def _strip_html(html: str) -> str:
    return strip_tags(html)


_HIDDEN_STYLE_MARKERS = ("display:none", "visibility:hidden", "font-size:0")
_WHITE_MARKERS = ("color:#fff;", "color:#fff ", "color:#ffffff", "color:white")


def _hidden_text_in_html(html: str) -> bool:
    """Hidden text via display:none, visibility:hidden, font-size:0, or white text
    of at least 20 characters. Walks tags once; no backtracking regex."""
    for name, attrs, start, end in iter_tags(html):
        if name.startswith("/"):
            continue
        style = attr_value(attrs, "style")
        if not style:
            continue
        compact = "".join(style.lower().split())
        if any(marker in compact for marker in _HIDDEN_STYLE_MARKERS):
            return True
        if re.match(r'font-size:0(px|pt|em|%|;|$)', compact) or ";font-size:0" in compact:
            return True
        if any(marker in compact + ";" for marker in _WHITE_MARKERS):
            next_tag = html.find("<", end + 1)
            text = html[end + 1:next_tag if next_tag != -1 else len(html)]
            if len(text.strip()) >= 20:
                return True
    return False


def _mismatched_link_text(html: str) -> bool:
    for href, inner in iter_anchors(html):
        if not href:
            continue
        href = href.strip().lower()
        text = strip_tags(inner).strip().lower()

        if not text.startswith("http") and not text.startswith("www"):
            continue

        text_domain = _extract_domain(text)
        href_domain = _extract_domain(href)

        if text_domain and href_domain and text_domain != href_domain:
            return True
    return False


def _extract_domain(s: str) -> str:
    s = s[:2048]
    if s.startswith("https://"):
        s = s[8:]
    elif s.startswith("http://"):
        s = s[7:]
    if s.startswith("www."):
        s = s[4:]
    end = len(s)
    for stop in "/ ?#\t\n":
        i = s.find(stop)
        if i != -1 and i < end:
            end = i
    return s[:end].lower().split(":")[0]
