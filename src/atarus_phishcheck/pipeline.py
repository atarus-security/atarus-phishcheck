"""The one place an email is analysed. The CLI and batch mode both call this."""
from atarus_phishcheck.analyzers import parser, auth, indicators, content, scoring, brands, reputation, urlexpand, homoglyph
from atarus_phishcheck.models import AnalysisResult
from atarus_phishcheck.network import Policy, OFFLINE


def analyze_raw(raw: str, source: str, policy: Policy = None) -> AnalysisResult:
    """Analyse one raw email. Network use happens only if ``policy`` allows it."""
    policy = policy or OFFLINE
    notes = []

    headers, body = parser.parse_email(raw)
    auth_result, auth_findings = auth.check_authentication(headers, policy=policy, notes=notes)
    ioc_list, ioc_findings = indicators.extract_indicators(headers, body)
    content_findings = content.analyze_content(headers, body)
    brand_findings = brands.check_brand_impersonation(headers, body)
    homoglyph_findings = homoglyph.check_homoglyphs(headers, body)

    hash_indicators, _ = reputation.hash_attachments(body, raw)
    ioc_list.extend(hash_indicators)

    expanded_indicators, expand_findings = urlexpand.expand_urls(ioc_list, policy=policy, notes=notes)
    ioc_list.extend(expanded_indicators)
    rep_findings = reputation.check_urls(ioc_list, policy=policy, notes=notes)
    rep_findings.extend(reputation.check_hashes_malwarebazaar(ioc_list, policy=policy, notes=notes))

    result = AnalysisResult(source_file=source, headers=headers, body=body, auth=auth_result)
    result.mode = policy.mode
    result.lookups_enabled = _lookups(policy)
    result.indicators = ioc_list
    for f in auth_findings + ioc_findings + content_findings + brand_findings + homoglyph_findings + expand_findings + rep_findings:
        result.add_finding(f)
    for note in body.truncated:
        result.note_not_run("Full body analysis", note)
    for check, reason in notes:
        result.note_not_run(check, reason)

    scoring.score_result(result)
    return result


def analyze_file(path: str, policy: Policy = None) -> AnalysisResult:
    raw = parser.read_email_file(path)
    return analyze_raw(raw, path, policy)


def _lookups(policy: Policy) -> list:
    if not policy.online:
        return []
    enabled = ["dns-spf-dmarc", "urlhaus", "malwarebazaar"]
    if policy.expand_links:
        enabled.append("shortener-expansion")
    return enabled
