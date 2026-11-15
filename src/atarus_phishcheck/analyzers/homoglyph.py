"""Detect homoglyph and IDN lookalike attacks in domains"""
import re
from atarus_phishcheck.models import Finding, EmailHeaders, EmailBody
from atarus_phishcheck.analyzers.parser import url_hostname, canonical_domain


ASCII_LOOKALIKES = {
    "1": "l",
    "0": "o",
    "5": "s",
    "6": "g",
    "8": "b",
    "3": "e",
    "4": "a",
}

MAJOR_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "facebook", "linkedin",
    "netflix", "dropbox", "chase", "bankofamerica", "wellsfargo", "citibank",
    "americanexpress", "irs", "usps", "ups", "fedex", "dhl", "docusign",
    "adobe", "zoom", "slack", "github", "okta", "instagram", "twitter",
    "outlook", "office365", "icloud", "gmail",
]


def check_homoglyphs(headers: EmailHeaders, body: EmailBody) -> list:
    """Detect homoglyph/IDN lookalike attacks. Returns list of findings."""
    findings = []

    # One entry per domain in canonical IDNA form, so a domain written once
    # in Unicode and once as xn-- is one domain, not two.
    by_canonical = {}

    for sender in [headers.from_domain] + list(headers.sender_candidates)[:5]:
        if sender and len(sender) <= 253:
            by_canonical.setdefault(canonical_domain(sender), sender.lower())

    for url in body.urls:
        host = url_hostname(url)
        if host and len(host) <= 253:
            by_canonical.setdefault(canonical_domain(host), host)
    domains_to_check = list(by_canonical.values())

    seen = set()
    for domain in domains_to_check:
        if domain in seen:
            continue
        seen.add(domain)

        if not domain.isascii():
            try:
                encoded = domain.encode("idna").decode("ascii")
            except Exception:
                encoded = "(not a valid IDNA name)"
            findings.append(Finding(
                category="indicators",
                severity="high",
                title=f"Non-ASCII (IDN) domain detected: {domain}",
                description=f"The domain '{domain}' contains characters outside ASCII. Letters from other scripts can look identical to Latin ones (Cyrillic 'а' for Latin 'a'), which is the basis of homograph phishing. Its ASCII (Punycode) form is '{encoded}'.",
                recommendation="Do not trust IDN domains in email without independent verification. Compare the Punycode form with the domain the sender normally uses.",
                evidence=f"Domain: {domain}\nPunycode: {encoded}\nNon-ASCII characters: {', '.join(sorted({f'U+{ord(c):04X}' for c in domain if ord(c) > 127}))[:300]}",
            ))
            continue

        if _has_punycode(domain):
            try:
                decoded = _decode_punycode(domain)
                findings.append(Finding(
                    category="indicators",
                    severity="high",
                    title=f"Punycode/IDN domain detected: {domain}",
                    description=f"The domain '{domain}' uses Punycode encoding (xn--), which can hide Unicode characters that look identical to Latin characters. Decoded form: '{decoded}'. This is a common technique in homograph phishing attacks.",
                    recommendation="Do not trust IDN domains in email without independent verification. Most established organizations use standard ASCII domains.",
                    evidence=f"Encoded: {domain}\nDecoded: {decoded}",
                ))
            except Exception:
                findings.append(Finding(
                    category="indicators",
                    severity="medium",
                    title=f"Punycode domain detected: {domain}",
                    description=f"The domain '{domain}' uses Punycode encoding, commonly used to obscure Unicode homoglyph attacks.",
                    recommendation="Verify the domain through an independent channel before trusting any links.",
                    evidence=f"Domain: {domain}",
                ))
            continue

        try:
            from confusable_homoglyphs import confusables
            if confusables.is_dangerous(domain):
                groups = confusables.is_confusable(domain, greedy=True, preferred_aliases=["latin"])
                if groups:
                    chars = ", ".join(set(g["character"] for g in groups if "character" in g))
                    findings.append(Finding(
                        category="indicators",
                        severity="high",
                        title=f"Confusable Unicode characters in domain: {domain}",
                        description=f"The domain '{domain}' contains Unicode characters that visually resemble Latin letters but are different code points. Characters identified: {chars}. This is a homograph phishing technique.",
                        recommendation="Do not trust this domain. Copy it to a text editor and inspect character by character, or run it through a Punycode converter.",
                        evidence=f"Domain: {domain}\nConfusable characters: {chars}",
                    ))
                    continue
        except Exception:
            pass

        # Every label but the top-level one: login.paypa1.com hides the
        # lookalike in the second label, where the first-label check missed it.
        labels = [l for l in domain.lower().split(".")[:-1] if l] or [domain.lower()]

        for brand in MAJOR_BRANDS:
            brand_clean = brand.replace(" ", "").replace("-", "").lower()
            matched_segment = ""
            for label in labels:
                if brand_clean in label and brand_clean != label:
                    continue
                matched_segment = _find_lookalike_segment(label, brand_clean)
                if matched_segment:
                    break
            if matched_segment:
                findings.append(Finding(
                    category="indicators",
                    severity="high",
                    title=f"ASCII lookalike detected: {domain} impersonates {brand}",
                    description=f"The domain '{domain}' contains the segment '{matched_segment}' which resembles '{brand}' via number/letter substitution (e.g. 1 for l, 0 for o, 5 for s). This pattern is a hallmark of brand impersonation phishing.",
                    recommendation=f"Do not trust this domain. The real {brand} uses its registered domain without numeric substitutions.",
                    evidence=f"Suspicious domain: {domain}\nSuspicious segment: {matched_segment}\nImpersonating: {brand}",
                ))
                break

    return findings


def _has_punycode(domain: str) -> bool:
    return any(label.startswith("xn--") for label in domain.split("."))


def _decode_punycode(domain: str) -> str:
    try:
        return domain.encode("ascii").decode("idna")
    except Exception:
        return domain


def _find_lookalike_segment(candidate: str, target: str) -> str:
    """
    Scan candidate for a substring of length len(target) that normalizes to target.
    Returns the suspicious segment if found, else empty string.
    """
    if len(candidate) < len(target):
        return ""

    target_len = len(target)

    for i in range(len(candidate) - target_len + 1):
        segment = candidate[i:i + target_len]

        if segment == target:
            continue

        normalized = ""
        for ch in segment:
            normalized += ASCII_LOOKALIKES.get(ch, ch)

        if normalized == target:
            return segment

    return ""
