"""Read SPF, DKIM and DMARC results from the headers; fetch records only when online.

The results come from the Authentication-Results header as written by the
receiving mail server. If that server adds no such header, the sender can
supply one, so the result is only as trustworthy as the receiving server.
The tool does not verify DKIM signatures itself.
"""
import re
import dns.resolver
from atarus_phishcheck.models import AuthResult, EmailHeaders, Finding
from atarus_phishcheck.network import Policy, OFFLINE

NETWORK = [
    {
        "module": "auth",
        "destination": "your system DNS resolver (which may ask the sender domain's name servers)",
        "sends": "TXT queries for the From domain and for _dmarc.<From domain>",
        "when": "--online only",
    },
]

DNS_LIFETIME = 5


def check_authentication(headers: EmailHeaders, policy: Policy = None, notes: list = None) -> tuple:
    """Check SPF/DKIM/DMARC. Returns (AuthResult, list of Findings).

    ``notes`` collects (check, reason) pairs for checks that did not run.
    """
    policy = policy or OFFLINE
    notes = notes if notes is not None else []
    result = AuthResult()
    findings = []

    if not headers.from_domain:
        notes.append(("SPF, DKIM and DMARC", "no sender domain could be read from the From header"))
        return result, findings

    auth_results_header = headers.authentication_results.lower()
    if not auth_results_header:
        notes.append(("SPF, DKIM and DMARC results", "no Authentication-Results header; the receiving server recorded no result"))
    for key, attr in (("spf", "spf_result"), ("dkim", "dkim_result"), ("dmarc", "dmarc_result")):
        m = re.search(r'\b' + key + r'=([a-z]+)', auth_results_header)
        if m:
            setattr(result, attr, m.group(1))

    notes.append(("DKIM signature verification", "not performed by this tool; the DKIM result above is the receiving server's, read from Authentication-Results"))

    if policy.online:
        result.spf_record, spf_err = _fetch_txt(headers.from_domain, "v=spf1")
        result.dmarc_record, dmarc_err = _fetch_txt(f"_dmarc.{headers.from_domain}", "v=dmarc1")
        if spf_err:
            notes.append((f"SPF record lookup for {headers.from_domain}", f"DNS query failed: {spf_err}"))
        if dmarc_err:
            notes.append((f"DMARC record lookup for _dmarc.{headers.from_domain}", f"DNS query failed: {dmarc_err}"))
        result.records_looked_up = not spf_err and not dmarc_err
        result.dmarc_policy = _extract_dmarc_policy(result.dmarc_record)
    else:
        notes.append((f"SPF and DMARC record lookup for {headers.from_domain}", "offline: no DNS query was made (use --online)"))

    if headers.dkim_signature:
        result.dkim_signature = headers.dkim_signature[:200]

    if result.spf_result == "fail":
        findings.append(Finding(
            category="authentication",
            severity="high",
            title="SPF authentication failed",
            description=f"The receiving server recorded an SPF failure for '{headers.from_domain}': the sending IP is not authorized to send email for this domain.",
            recommendation="Treat this email with extreme caution. SPF failure on a sender domain that normally publishes SPF records is a strong indicator of sender spoofing.",
            evidence=headers.received_spf[:300] if headers.received_spf else "",
        ))
    elif result.spf_result in ("none", "softfail", "neutral") and result.spf_record:
        findings.append(Finding(
            category="authentication",
            severity="medium",
            title=f"SPF result is '{result.spf_result}'",
            description=f"SPF check returned '{result.spf_result}' for '{headers.from_domain}' although the domain publishes an SPF record. This is weaker than 'pass' and may indicate sender spoofing or misconfigured records.",
            recommendation="Verify the sender through an out-of-band channel before trusting email content or clicking links.",
        ))

    if result.dkim_result == "fail":
        findings.append(Finding(
            category="authentication",
            severity="high",
            title="DKIM signature verification failed",
            description="The receiving server recorded a DKIM failure: the signature does not verify against the published public key. This indicates either content modification in transit or forgery.",
            recommendation="Do not trust this email. DKIM failure means the sender cannot be cryptographically verified.",
        ))

    if result.dmarc_result == "fail":
        findings.append(Finding(
            category="authentication",
            severity="high",
            title="DMARC alignment failed",
            description=f"The receiving server recorded a DMARC failure for '{headers.from_domain}'. Neither SPF nor DKIM aligned with the From header domain.",
            recommendation=f"This email should not be trusted as coming from '{headers.from_domain}'. DMARC failure is the strongest single indicator of sender spoofing.",
        ))
    elif result.records_looked_up and not result.dmarc_record:
        findings.append(Finding(
            category="authentication",
            severity="low",
            title="Sender domain has no DMARC record",
            description=f"The domain '{headers.from_domain}' does not publish a DMARC record. This means anyone can spoof emails claiming to be from this domain without detection.",
            recommendation="Consider this when evaluating trust. Organizations without DMARC are easier targets for impersonation.",
        ))
    elif result.records_looked_up and result.dmarc_policy == "none":
        findings.append(Finding(
            category="authentication",
            severity="low",
            title="DMARC policy is 'none' (monitor-only)",
            description=f"The domain '{headers.from_domain}' publishes a DMARC record but with policy 'p=none'. Failed DMARC checks will not result in rejection.",
            recommendation="Be aware that mail from this domain may be spoofed and still delivered to recipients.",
        ))

    return result, findings


def _fetch_txt(name: str, prefix: str) -> tuple:
    """(record, error). record is the first TXT value starting with prefix, or ''."""
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=DNS_LIFETIME)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return "", None
    except Exception as e:
        return "", type(e).__name__
    for r in answers:
        try:
            txt = b"".join(r.strings).decode("utf-8", errors="ignore") if hasattr(r, "strings") else str(r).strip('"')
        except Exception:
            continue
        if txt.lower().startswith(prefix):
            return txt[:2048], None
    return "", None


def _extract_dmarc_policy(record: str) -> str:
    if not record:
        return ""
    m = re.search(r'\bp=(\w+)', record.lower())
    return m.group(1) if m else ""
