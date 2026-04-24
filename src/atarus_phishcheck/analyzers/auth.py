"""Check SPF, DKIM, DMARC for the sender domain"""
import dns.resolver
import re
from atarus_phishcheck.models import AuthResult, EmailHeaders, Finding


def check_authentication(headers: EmailHeaders) -> tuple:
    """Check SPF/DKIM/DMARC. Returns (AuthResult, list of Findings)"""
    result = AuthResult()
    findings = []

    if not headers.from_domain:
        return result, findings

    auth_results_header = headers.authentication_results.lower()
    if "spf=pass" in auth_results_header:
        result.spf_result = "pass"
    elif "spf=fail" in auth_results_header:
        result.spf_result = "fail"
    elif "spf=softfail" in auth_results_header:
        result.spf_result = "softfail"
    elif "spf=neutral" in auth_results_header:
        result.spf_result = "neutral"
    elif "spf=none" in auth_results_header:
        result.spf_result = "none"

    if "dkim=pass" in auth_results_header:
        result.dkim_result = "pass"
    elif "dkim=fail" in auth_results_header:
        result.dkim_result = "fail"
    elif "dkim=none" in auth_results_header:
        result.dkim_result = "none"

    if "dmarc=pass" in auth_results_header:
        result.dmarc_result = "pass"
    elif "dmarc=fail" in auth_results_header:
        result.dmarc_result = "fail"

    result.spf_record = _fetch_spf(headers.from_domain)
    result.dmarc_record = _fetch_dmarc(headers.from_domain)
    result.dmarc_policy = _extract_dmarc_policy(result.dmarc_record)

    if headers.dkim_signature:
        result.dkim_signature = headers.dkim_signature[:200]

    if result.spf_result == "fail":
        findings.append(Finding(
            category="authentication",
            severity="high",
            title="SPF authentication failed",
            description=f"The sender domain '{headers.from_domain}' SPF check failed. The sending IP is not authorized to send email for this domain.",
            recommendation="Treat this email with extreme caution. SPF failure on a sender domain that normally publishes SPF records is a strong indicator of sender spoofing.",
            evidence=headers.received_spf[:300] if headers.received_spf else "",
        ))
    elif result.spf_result in ("none", "softfail", "neutral") and result.spf_record:
        findings.append(Finding(
            category="authentication",
            severity="medium",
            title=f"SPF result is '{result.spf_result}'",
            description=f"SPF check returned '{result.spf_result}' for '{headers.from_domain}'. This is weaker than 'pass' and may indicate sender spoofing or misconfigured records.",
            recommendation="Verify the sender through an out-of-band channel before trusting email content or clicking links.",
        ))

    if result.dkim_result == "fail":
        findings.append(Finding(
            category="authentication",
            severity="high",
            title="DKIM signature verification failed",
            description="The DKIM signature on this email does not verify against the published public key. This indicates either content modification in transit or forgery.",
            recommendation="Do not trust this email. DKIM failure means the sender cannot be cryptographically verified.",
        ))

    if result.dmarc_result == "fail":
        findings.append(Finding(
            category="authentication",
            severity="high",
            title="DMARC alignment failed",
            description=f"DMARC alignment failed for '{headers.from_domain}'. Neither SPF nor DKIM aligned with the From header domain.",
            recommendation=f"This email should not be trusted as coming from '{headers.from_domain}'. DMARC failure is the strongest single indicator of sender spoofing.",
        ))
    elif not result.dmarc_record and headers.from_domain:
        findings.append(Finding(
            category="authentication",
            severity="low",
            title=f"Sender domain has no DMARC record",
            description=f"The domain '{headers.from_domain}' does not publish a DMARC record. This means anyone can spoof emails claiming to be from this domain without detection.",
            recommendation="Consider this when evaluating trust. Organizations without DMARC are easier targets for impersonation.",
        ))
    elif result.dmarc_policy == "none":
        findings.append(Finding(
            category="authentication",
            severity="low",
            title="DMARC policy is 'none' (monitor-only)",
            description=f"The domain '{headers.from_domain}' publishes a DMARC record but with policy 'p=none'. Failed DMARC checks will not result in rejection.",
            recommendation="Be aware that mail from this domain may be spoofed and still delivered to recipients.",
        ))

    return result, findings


def _fetch_spf(domain: str) -> str:
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for r in answers:
            txt = b"".join(r.strings).decode("utf-8", errors="ignore") if hasattr(r, 'strings') else str(r).strip('"')
            if txt.lower().startswith("v=spf1"):
                return txt
    except Exception:
        pass
    return ""


def _fetch_dmarc(domain: str) -> str:
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for r in answers:
            txt = b"".join(r.strings).decode("utf-8", errors="ignore") if hasattr(r, 'strings') else str(r).strip('"')
            if txt.lower().startswith("v=dmarc1"):
                return txt
    except Exception:
        pass
    return ""


def _extract_dmarc_policy(record: str) -> str:
    if not record:
        return ""
    m = re.search(r'p=(\w+)', record.lower())
    return m.group(1) if m else ""
