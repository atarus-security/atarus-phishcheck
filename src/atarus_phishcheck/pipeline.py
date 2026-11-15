"""The one place an email is analysed. The CLI and batch mode both call this."""
from atarus_phishcheck.analyzers import parser, auth, indicators, content, scoring, brands, reputation, urlexpand, homoglyph
from atarus_phishcheck.models import AnalysisResult, Finding
from atarus_phishcheck.network import Policy, OFFLINE


def analyze_raw(raw, source: str, policy: Policy = None) -> AnalysisResult:
    """Analyse one raw email, given as bytes (a file) or text (pasted input).
    Network use happens only if ``policy`` allows it."""
    policy = policy or OFFLINE
    notes = []

    raw = parser.as_bytes(raw)
    headers, body = parser.parse_email(raw)
    # The domain the receiving server recorded as the From domain is a
    # sender candidate too, so the sender checks never depend on this tool's
    # reading of From alone; when it differs from that reading, the server
    # and this tool saw different senders, which is a finding.
    # Domains are compared and deduplicated in their canonical IDNA form: a
    # receiver may record 'bücher.example' as 'xn--bcher-kva.example'.
    recorded = parser._unique_domains(auth.read_authentication_details(headers.authentication_results)["header_froms"])
    headers.sender_candidates = parser._unique_domains(list(headers.sender_candidates) + recorded)
    auth_result, auth_findings = auth.check_authentication(headers, policy=policy, notes=notes)
    # Compared as the same domain or a parent or child of it: some receivers
    # record the organizational domain of a subdomain sender.
    other = [d for d in recorded if headers.from_domain and not auth.same_organization(d, headers.from_domain)]
    if other:
        auth_findings.append(Finding(
            category="authentication",
            severity="high",
            title="The receiving server authenticated a different From domain",
            description=(f"This tool reads the sender domain as '{headers.from_domain}', but the receiving server recorded the From domain "
                         f"as '{', '.join(other)}' (header.from in Authentication-Results). Its DMARC result is for that domain, not for the "
                         "one shown. A From header written so that readers disagree on the domain is a known way to display a trusted "
                         "sender while authentication passes for another. The checks here ran on both."),
            recommendation="Treat the sender as unverified; read the From header in the raw source.",
            evidence=f"From domain read: {headers.from_domain}\nheader.from recorded: {', '.join(other)}",
        ))
    ioc_list, ioc_findings = indicators.extract_indicators(headers, body)
    content_findings = content.analyze_content(headers, body)
    brand_findings = brands.check_brand_impersonation(headers, body)
    homoglyph_findings = homoglyph.check_homoglyphs(headers, body)

    hash_indicators, _ = reputation.hash_attachments(body)
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
    if body.limited:
        result.analysis_limited = body.limited
        result.add_finding(Finding(
            category="technical",
            severity="high",
            title="MIME structure exceeds the analysis limits",
            description=f"The MIME structure passed the analysis limits: {body.limited}. A structure this large or deep has no use in ordinary mail and is a known way to push content past filters that give up, so the score is at least 75 ('likely phishing') whatever else was found.",
            recommendation="Treat the message as suspicious. Do not open its attachments or links; hand it to your security team with the original file.",
        ))
        result.note_not_run("Rest of the message", "not read by the MIME parser: " + body.limited)
    mbox_count = _mbox_messages(raw)
    if mbox_count > 1:
        result.note_not_run("Other messages in the file", f"the input looks like an mbox mailbox with about {mbox_count} messages; only the first was analysed. Give the file a .mbox name to analyse each message in batch mode")
    if not headers.header_count:
        result.note_not_run("Header analysis", "no email headers were found at the top of the input; it may not be an email message, so the score covers the body text only")
    for note in body.truncated:
        result.note_not_run("Full body analysis", note)
    for check, reason in notes:
        result.note_not_run(check, reason)

    scoring.score_result(result)
    return result


def analyze_file(path: str, policy: Policy = None) -> AnalysisResult:
    raw = parser.read_email_file(path)
    return analyze_raw(raw, path, policy)


def _mbox_messages(raw: bytes) -> int:
    """Approximate count of mbox "From " separator lines, or 0 if the input
    does not start like an mbox. A blank line before "From " is the mbox
    separator; one counted line per message is enough for a warning."""
    if not raw.startswith(b"From "):
        return 0
    return 1 + raw.count(b"\n\nFrom ") + raw.count(b"\r\n\r\nFrom ")


def _lookups(policy: Policy) -> list:
    if not policy.online:
        return []
    enabled = ["dns-spf-dmarc", "urlhaus", "malwarebazaar"]
    if policy.expand_links:
        enabled.append("shortener-expansion")
    return enabled
