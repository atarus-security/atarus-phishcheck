"""Detect brand impersonation in email sender and content"""
import re
from atarus_phishcheck.models import EmailHeaders, EmailBody, Finding


BRAND_LIBRARY = {
    "paypal": {
        "legitimate_domains": ["paypal.com", "paypal.co.uk", "paypal.ca", "paypal.de", "paypal-communication.com", "mail.paypal.com"],
        "keywords": ["paypal"],
    },
    "microsoft": {
        "legitimate_domains": ["microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "hotmail.com", "msn.com", "microsoftonline.com", "azure.com", "sharepointonline.com"],
        "keywords": ["microsoft", "office 365", "office365", "outlook", "onedrive", "sharepoint", "azure"],
    },
    "google": {
        "legitimate_domains": ["google.com", "gmail.com", "googlemail.com", "accounts.google.com", "youtube.com", "workspace.google.com"],
        "keywords": ["google", "gmail", "google drive", "google workspace"],
    },
    "apple": {
        "legitimate_domains": ["apple.com", "icloud.com", "me.com", "mac.com", "itunes.com"],
        "keywords": ["apple id", "apple inc", "icloud", "itunes"],
    },
    "amazon": {
        "legitimate_domains": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.fr", "amazon.jp", "aws.amazon.com", "amazonses.com"],
        "keywords": ["amazon", "amazon prime", "aws"],
    },
    "facebook": {
        "legitimate_domains": ["facebook.com", "facebookmail.com", "fb.com", "meta.com", "instagram.com"],
        "keywords": ["facebook", "meta", "instagram"],
    },
    "linkedin": {
        "legitimate_domains": ["linkedin.com", "linkedinmail.com"],
        "keywords": ["linkedin"],
    },
    "netflix": {
        "legitimate_domains": ["netflix.com", "mailer.netflix.com"],
        "keywords": ["netflix"],
    },
    "dropbox": {
        "legitimate_domains": ["dropbox.com", "dropboxmail.com"],
        "keywords": ["dropbox"],
    },
    "chase": {
        "legitimate_domains": ["chase.com", "jpmorgan.com", "jpmorganchase.com"],
        "keywords": ["chase bank", "jpmorgan chase"],
    },
    "bank of america": {
        "legitimate_domains": ["bankofamerica.com", "bofa.com", "merrilledge.com"],
        "keywords": ["bank of america", "bofa"],
    },
    "wells fargo": {
        "legitimate_domains": ["wellsfargo.com", "wf.com"],
        "keywords": ["wells fargo"],
    },
    "citibank": {
        "legitimate_domains": ["citi.com", "citibank.com", "citigroup.com"],
        "keywords": ["citibank", "citigroup"],
    },
    "american express": {
        "legitimate_domains": ["americanexpress.com", "aexp.com"],
        "keywords": ["american express", "amex"],
    },
    "irs": {
        "legitimate_domains": ["irs.gov"],
        "keywords": ["irs", "internal revenue service", "tax refund", "tax return"],
    },
    "usps": {
        "legitimate_domains": ["usps.com", "usps.gov"],
        "keywords": ["usps", "us postal service"],
    },
    "ups": {
        "legitimate_domains": ["ups.com"],
        "keywords": ["ups tracking", "united parcel service"],
    },
    "fedex": {
        "legitimate_domains": ["fedex.com"],
        "keywords": ["fedex", "federal express"],
    },
    "dhl": {
        "legitimate_domains": ["dhl.com", "dhl.de"],
        "keywords": ["dhl express"],
    },
    "docusign": {
        "legitimate_domains": ["docusign.com", "docusign.net"],
        "keywords": ["docusign"],
    },
    "adobe": {
        "legitimate_domains": ["adobe.com", "adobesign.com", "echosign.com"],
        "keywords": ["adobe sign", "adobe acrobat"],
    },
    "zoom": {
        "legitimate_domains": ["zoom.us", "zoomgov.com"],
        "keywords": ["zoom meeting", "zoom invitation"],
    },
    "slack": {
        "legitimate_domains": ["slack.com"],
        "keywords": ["slack"],
    },
    "github": {
        "legitimate_domains": ["github.com", "githubusercontent.com"],
        "keywords": ["github"],
    },
    "okta": {
        "legitimate_domains": ["okta.com"],
        "keywords": ["okta"],
    },
}


def check_brand_impersonation(headers: EmailHeaders, body: EmailBody) -> list:
    """Detect when email claims to be from a known brand but sender domain doesn't match"""
    findings = []

    if not headers.from_domain:
        return findings

    search_text = " ".join([
        headers.from_name or "",
        headers.subject or "",
        (body.text or "")[:2000],
        _strip_html(body.html or "")[:2000],
    ]).lower()

    sender_domain = headers.from_domain.lower()

    for brand_name, brand_info in BRAND_LIBRARY.items():
        legit_domains = brand_info["legitimate_domains"]
        keywords = brand_info["keywords"]

        brand_mentioned = False
        matched_keyword = None
        for kw in keywords:
            if kw.lower() in search_text:
                brand_mentioned = True
                matched_keyword = kw
                break

        if not brand_mentioned:
            continue

        sender_legitimate = False
        for legit in legit_domains:
            if sender_domain == legit or sender_domain.endswith("." + legit):
                sender_legitimate = True
                break

        if sender_legitimate:
            continue

        severity = "high"
        brand_display = brand_name.upper() if len(brand_name) <= 4 else brand_name.title()

        findings.append(Finding(
            category="indicators",
            severity=severity,
            title=f"Brand impersonation: claims to be {brand_display}",
            description=f"The email references '{matched_keyword}' but the sender domain '{sender_domain}' is not a known legitimate domain for {brand_display}. Legitimate {brand_display} emails come from domains like: {', '.join(legit_domains[:3])}.",
            recommendation=f"Do not trust this email as coming from {brand_display}. Verify any {brand_display}-related action by logging into your account directly at the official website.",
            evidence=f"Sender domain: {sender_domain}\nClaimed brand: {brand_display}\nDetected in: {_where_detected(matched_keyword, headers, body)}",
        ))

    return findings


def _where_detected(keyword: str, headers: EmailHeaders, body: EmailBody) -> str:
    kw_lower = keyword.lower()
    locations = []
    if headers.from_name and kw_lower in headers.from_name.lower():
        locations.append("From display name")
    if headers.subject and kw_lower in headers.subject.lower():
        locations.append("Subject")
    if body.text and kw_lower in body.text.lower():
        locations.append("email body (text)")
    if body.html and kw_lower in _strip_html(body.html).lower():
        locations.append("email body (HTML)")
    return ", ".join(locations) if locations else "email content"


def _strip_html(html: str) -> str:
    if not html:
        return ""
    clean = re.sub(r'<[^>]+>', ' ', html)
    clean = re.sub(r'\s+', ' ', clean)
    return clean
