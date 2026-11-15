"""Read SPF, DKIM and DMARC results from the headers; fetch records only when online.

The results come from the Authentication-Results header as written by the
receiving mail server. If that server adds no such header, the sender can
supply one, so the result is only as trustworthy as the receiving server.
The tool does not verify DKIM signatures itself.
"""
import re
from array import array
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

    details = read_authentication_details(headers.authentication_results)
    results, malformed = details["results"], details["malformed"]
    domain = headers.from_domain
    if not domain:
        # The recorded results never depend on reading the From header.
        domain = details["header_from"]
        if domain:
            notes.append(("Sender domain", f"no sender address could be read from the From header; the domain the receiving server recorded (header.from={domain}) is used"))
        else:
            notes.append(("Sender domain", "no sender address could be read from the From header or the Authentication-Results header; the recorded results are still read"))
    shown_domain = domain or "the sender (unreadable)"

    if not headers.authentication_results.strip():
        notes.append(("SPF, DKIM and DMARC results", "no Authentication-Results header; the receiving server recorded no result"))
    for key, attr in (("spf", "spf_result"), ("dmarc", "dmarc_result")):
        if key in results:
            setattr(result, attr, results[key])
    if details["dkim"]:
        result.dkim_result, result.alignment_dkim = dkim_result(details["dkim"], domain)
    if malformed:
        findings.append(Finding(
            category="authentication",
            severity="high" if malformed["lost_core"] else "medium",
            title="Authentication-Results header is malformed",
            description=("Part of the Authentication-Results header could not be read: " + malformed["reason"] + ". "
                         "Mail servers write balanced comments and quotes, so this usually comes from sender-controlled text, such as the "
                         "envelope sender, copied into the header to hide or change a result. The results in the unreadable part are "
                         "treated as unknown, not as a pass."),
            recommendation="Read the Authentication-Results header in the raw source and treat the sender as unverified.",
            evidence=malformed["evidence"],
        ))

    notes.append(("DKIM signature verification", "not performed by this tool; the DKIM result above is the receiving server's, read from Authentication-Results"))

    if policy.online and domain:
        result.spf_record, spf_err = _fetch_txt(domain, "v=spf1")
        result.dmarc_record, dmarc_err = _fetch_txt(f"_dmarc.{domain}", "v=dmarc1")
        if spf_err:
            notes.append((f"SPF record lookup for {domain}", f"DNS query failed: {spf_err}"))
        if dmarc_err:
            notes.append((f"DMARC record lookup for _dmarc.{domain}", f"DNS query failed: {dmarc_err}"))
        result.records_looked_up = not spf_err and not dmarc_err
        result.dmarc_policy = _extract_dmarc_policy(result.dmarc_record)
    elif policy.online:
        notes.append(("SPF and DMARC record lookup", "no sender domain to look up"))
    else:
        notes.append((f"SPF and DMARC record lookup for {shown_domain}", "offline: no DNS query was made (use --online)"))

    if headers.dkim_signature:
        result.dkim_signature = headers.dkim_signature[:200]

    if result.spf_result == "fail":
        findings.append(Finding(
            category="authentication",
            severity="high",
            title="SPF authentication failed",
            description=f"The receiving server recorded an SPF failure for '{shown_domain}': the sending IP is not authorized to send email for this domain.",
            recommendation="Treat this email with extreme caution. SPF failure on a sender domain that normally publishes SPF records is a strong indicator of sender spoofing.",
            evidence=headers.received_spf[:300] if headers.received_spf else "",
        ))
    elif result.spf_result in ("none", "softfail", "neutral") and result.spf_record:
        findings.append(Finding(
            category="authentication",
            severity="medium",
            title=f"SPF result is '{result.spf_result}'",
            description=f"SPF check returned '{result.spf_result}' for '{shown_domain}' although the domain publishes an SPF record. This is weaker than 'pass' and may indicate sender spoofing or misconfigured records.",
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
            description=f"The receiving server recorded a DMARC failure for '{shown_domain}'. Neither SPF nor DKIM aligned with the From header domain.",
            recommendation=f"This email should not be trusted as coming from '{shown_domain}'. DMARC failure is the strongest single indicator of sender spoofing.",
        ))
    elif result.records_looked_up and not result.dmarc_record:
        findings.append(Finding(
            category="authentication",
            severity="low",
            title="Sender domain has no DMARC record",
            description=f"The domain '{shown_domain}' does not publish a DMARC record. This means anyone can spoof emails claiming to be from this domain without detection.",
            recommendation="Consider this when evaluating trust. Organizations without DMARC are easier targets for impersonation.",
        ))
    elif result.records_looked_up and result.dmarc_policy == "none":
        findings.append(Finding(
            category="authentication",
            severity="low",
            title="DMARC policy is 'none' (monitor-only)",
            description=f"The domain '{shown_domain}' publishes a DMARC record but with policy 'p=none'. Failed DMARC checks will not result in rejection.",
            recommendation="Be aware that mail from this domain may be spoofed and still delivered to recipients.",
        ))

    return result, findings


# Methods whose results the checks use. Others (arc, iprev, auth) are read
# and ignored.
CORE_METHODS = ("spf", "dkim", "dmarc")
_METHODSPEC = re.compile(r"\s*([a-z0-9][a-z0-9_.-]*)(?:\s*/\s*[0-9]+)?\s*=\s*([a-z0-9][a-z0-9_-]*)(?=\s|$)")
_METHOD_NAME = re.compile(r"\s*([a-z0-9][a-z0-9_.-]*)\s*(?:/\s*[0-9]+\s*)?=")


def read_authentication_results(value: str) -> tuple:
    """Results from one Authentication-Results header, read the way RFC 8601
    defines it: the header is split on ";" outside comments and quoted
    strings, and only the leading ``method=result`` of each segment is a
    result. Text anywhere else (a comment, ``smtp.mailfrom=dmarc=pass@...``,
    a DKIM ``header.i``) is never read as a result. Returns ({method:
    result}, malformed or None); ``read_authentication_details`` also gives
    the ``header.from`` domain the receiving server recorded."""
    details = read_authentication_details(value)
    return details["results"], details["malformed"]


MAX_LITERAL = 10_000  # unclosed openers taken literally one by one; past this, quotes and comments are ignored from the first
_HEADER_FROM = re.compile(r"(?:^|\s)header\.from\s*=\s*\"?([^\s\";]+)")


def read_authentication_details(value: str) -> dict:
    """{"results", "malformed", "header_from"} for one Authentication-Results
    header.

    A backslash is a quoted-pair only inside a quoted string or a comment
    (RFC 5322 3.2.1, used by RFC 8601). Outside them a backslash, or a ")"
    with no "(", is outside the grammar: the segment holding it is
    malformed and its result unknown, and nothing else changes. An unclosed
    comment or quote makes the segment it opens in unreadable: the opening
    character is then taken literally, so the later segments are still
    read. If taking openers literally leaves others unclosed (a quote that
    opened inside a comment, say), quotes and comments are ignored from the
    first remaining problem on, so a later segment's result is never lost.

    For SPF and DMARC a message has one result each, so a second result can
    only come from someone adding it: a fail in any segment wins, then any
    other result that is not a pass, then a pass. DKIM has one result per
    signature, and a sender can add signatures of its own domain, so every
    DKIM result is kept with its signing domain (``header.d``, or the domain
    of ``header.i``) in ``dkim``, in order; ``dkim_result`` decides. A fail
    written at the start of an unreadable segment is still read as a fail.
    At most four linear passes."""
    value = value or ""
    literal = []
    segments, unclosed, stray = _segments(value, literal)
    plain_from = None
    passes = 0
    first_unclosed = unclosed[0] if unclosed else None
    while unclosed and passes < 3 and len(literal) + len(unclosed) <= MAX_LITERAL:
        literal = sorted(set(literal) | set(unclosed))
        passes += 1
        segments, unclosed, stray = _segments(value, literal)
    if unclosed:
        plain_from = unclosed[0]
        segments, _, stray = _segments(value, literal, plain_from)
    problem_at = sorted(set(literal) | set(stray) | ({plain_from} if plain_from is not None else set()))
    bad = set()
    k = 0
    for index, (start, end, _text) in enumerate(segments):  # both lists are sorted: one walk marks them
        while k < len(problem_at) and problem_at[k] < start:
            k += 1
        if k < len(problem_at) and problem_at[k] < end:
            bad.add(index)
    results = {}
    dkim = []  # (outcome, signing domain) per DKIM result, in order
    lost = []
    header_from = ""
    header_froms = []
    for index, (start, end, text) in enumerate(segments):
        text = text.lower()
        m = _METHODSPEC.match(text)
        if index in bad:
            if m and m.group(2) == "fail" and m.group(1) in CORE_METHODS:
                results[m.group(1)] = "fail"
                if m.group(1) == "dkim":
                    dkim.append(("fail", _signing_domain(text)))
                continue
            name = _METHOD_NAME.match(text)
            lost.append(name.group(1) if name else "")
            continue
        if not m:
            continue
        method, outcome = m.group(1), m.group(2)
        if index == 0 and method not in CORE_METHODS:
            continue  # the authserv-id
        if method == "dmarc":
            hf = _HEADER_FROM.search(text)
            if hf and len(header_froms) < 20:
                header_froms.append(hf.group(1).strip(".").lower())
                header_from = header_from or header_froms[-1]
        if method == "dkim":
            dkim.append((outcome, _signing_domain(text)))
            results.setdefault(method, outcome)
        elif method in ("spf", "dmarc"):
            # One SPF and one DMARC result is normal: an added one must never
            # turn a fail, or anything short of a pass, into a pass.
            before = results.get(method)
            if before is None or outcome == "fail" or (before == "pass" and outcome != "pass"):
                results[method] = outcome
        else:
            results.setdefault(method, outcome)
    malformed = None
    if bad:
        reasons = []
        if first_unclosed is not None:
            kind = "a quoted string" if value[first_unclosed] == '"' else "a comment"
            reasons.append(f"{kind} opened at character {first_unclosed + 1} is never closed")
        if stray:
            ch = value[stray[0]]
            reasons.append(f"a '{ch}' outside any quoted string or comment at character {stray[0] + 1}, which the RFC 8601 grammar does not allow there")
        first = problem_at[0]
        lost_core = any(m in CORE_METHODS or not m for m in lost)
        for method in lost:
            if method in CORE_METHODS:
                results.setdefault(method, "unknown")
                if method == "dkim" and not dkim:
                    dkim.append(("unknown", ""))
        malformed = {
            "reason": "; ".join(reasons) or "part of the header does not fit the RFC 8601 grammar",
            "lost_core": lost_core,
            "evidence": value[max(0, first - 120):first + 120],
        }
    return {"results": results, "malformed": malformed, "header_from": header_from, "header_froms": header_froms, "dkim": dkim}


_SIGNING_DOMAIN = re.compile(r"(?:^|\s)header\.(d|i)\s*=\s*\"?([^\s\";]+)")


def _signing_domain(text: str) -> str:
    """The signing domain of one DKIM result: header.d, or the domain of header.i."""
    found = {}
    for m in _SIGNING_DOMAIN.finditer(text):
        found.setdefault(m.group(1), m.group(2))
        if "d" in found:
            break
    value = found.get("d") or found.get("i", "")
    return value.rsplit("@", 1)[-1].strip(".").lower()


def same_organization(a: str, b: str) -> bool:
    """True when two domains are the same, or one is a parent of the other."""
    return _aligned(a, b)


def _aligned(signing: str, sender: str) -> bool:
    """True when the two domains, in canonical IDNA form, are equal or one
    is a parent of the other at a label boundary (mail.shop.example and
    shop.example). Siblings under a shared suffix (a.github.io and
    b.github.io, bank.com.pl and evil.com.pl) never count: without a full
    public suffix list there is no telling a shared organization from two
    registrations under one public suffix."""
    from atarus_phishcheck.analyzers.parser import canonical_domain
    a, b = canonical_domain(signing), canonical_domain(sender)
    return bool(a and b) and (a == b or a.endswith("." + b) or b.endswith("." + a))


def dkim_result(dkim: list, sender: str) -> tuple:
    """(result, aligned) from every DKIM result and the sender domain. A
    pass counts only when its signing domain aligns with the sender: a
    sender can always add a valid signature of its own domain, and list it
    first. Without an aligned pass, a fail anywhere wins; otherwise the
    first result stands (an unaligned pass gets no credit)."""
    if not dkim:
        return "unknown", False
    if any(outcome == "pass" and _aligned(domain, sender) for outcome, domain in dkim):
        return "pass", True
    if any(outcome == "fail" for outcome, _ in dkim):
        return "fail", False
    return dkim[0][0], False


def _segments(value: str, literal, plain_from=None) -> tuple:
    """([(start, end, text without comments)], sorted positions of unclosed
    openers, sorted positions of characters outside the grammar). Positions
    in ``literal`` (sorted) are taken as ordinary characters, and so is
    every quote, parenthesis and backslash from ``plain_from`` on. Kept text
    is gathered as slices and positions in a compact array, so memory stays
    proportional to the header."""
    literal_at = iter(literal)
    next_literal = next(literal_at, -1)
    segments = []
    kept = []  # slices of the current segment outside comments
    run = 0  # start of the current run of kept text
    start = 0
    depth = 0
    opens = array("q")  # positions of the outermost "(" still open, at most MAX_LITERAL + 1 of them
    stray = []
    quote_at = None
    escaped = False
    plain = len(value) if plain_from is None else plain_from
    for i, ch in enumerate(value):
        while -1 < next_literal < i:  # a literal position the scan stepped over inside a quote
            next_literal = next(literal_at, -1)
        if escaped:
            escaped = False
            continue
        if i >= plain:
            if ch == ";":
                kept.append(value[run:i])
                segments.append((start, i, "".join(kept)))
                kept = []
                start = run = i + 1
            continue
        if ch == "\\" and (quote_at is not None or depth):
            escaped = True  # a quoted-pair: only inside a quoted string or a comment
            continue
        if quote_at is not None:
            if ch == '"':
                quote_at = None
            continue
        if i == next_literal:
            next_literal = next(literal_at, -1)
            continue
        if ch == "(":
            if not depth:
                kept.append(value[run:i])
            depth += 1
            if len(opens) <= MAX_LITERAL:  # the caller needs the first openers only: deeper ones are counted by depth
                opens.append(i)
            continue
        if ch == ")":
            if depth:
                if depth <= len(opens):
                    opens.pop()
                depth -= 1
                if not depth:
                    kept.append(" ")
                    run = i + 1
            elif len(stray) < 100:
                stray.append(i)
            continue
        if depth:
            continue
        if ch == "\\":
            if len(stray) < 100:
                stray.append(i)
            continue
        if ch == '"':
            quote_at = i
            continue
        if ch == ";":
            kept.append(value[run:i])
            segments.append((start, i, "".join(kept)))
            kept = []
            start = run = i + 1
    if not depth or plain_from is not None:
        kept.append(value[run:])
    segments.append((start, len(value), "".join(kept)))
    unclosed = list(opens)
    if quote_at is not None:
        unclosed.append(quote_at)
        unclosed.sort()
    return segments, unclosed, stray


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
    # A DMARC record is a tag list: "v=DMARC1; p=reject; rua=mailto:...".
    # Read the p tag itself, never "p=" inside another tag's value.
    for tag in record.lower().split(";"):
        name, sep, value = tag.partition("=")
        if sep and name.strip() == "p":
            return value.strip()
    return ""
