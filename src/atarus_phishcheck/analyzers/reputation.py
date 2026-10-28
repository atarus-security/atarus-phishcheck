"""Check URLs and file hashes against public threat intel feeds (online only).

A lookup that fails is recorded as a check not run. A URL that URLhaus has
no record of is marked ``not_listed``, never ``clean``: absence from one feed
is not evidence of anything.
"""
import hashlib
import requests
from atarus_phishcheck import __version__
from atarus_phishcheck.models import Indicator, Finding, EmailBody
from atarus_phishcheck.network import Policy, OFFLINE

NETWORK = [
    {
        "module": "reputation",
        "destination": "urlhaus-api.abuse.ch over HTTPS",
        "sends": "each URL found in the email (which may carry a per-recipient token), up to 10, as a POST form field",
        "when": "--online only",
    },
    {
        "module": "reputation",
        "destination": "mb-api.abuse.ch over HTTPS",
        "sends": "the SHA-256 of each attachment, up to 10, as a POST form field",
        "when": "--online only",
    },
]

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"

USER_AGENT = f"atarus-phishcheck/{__version__}"
REQUEST_TIMEOUT = 8
MAX_LOOKUPS = 10


def check_urls(indicators: list, policy: Policy = None, notes: list = None) -> list:
    """Check URLs against URLhaus. Returns list of Findings. Sets indicator.reputation."""
    policy = policy or OFFLINE
    notes = notes if notes is not None else []
    findings = []

    url_indicators = [i for i in indicators if i.type == "url"]
    if not url_indicators:
        return findings

    if not policy.online:
        notes.append((f"URLhaus reputation ({len(url_indicators)} URL(s))", "offline: URLhaus was not queried (use --online)"))
        return findings

    if len(url_indicators) > MAX_LOOKUPS:
        notes.append(("URLhaus reputation", f"only the first {MAX_LOOKUPS} of {len(url_indicators)} URLs were queried"))

    for ind in url_indicators[:MAX_LOOKUPS]:
        data, error = _post(URLHAUS_API, {"url": ind.value})
        if error:
            notes.append((f"URLhaus reputation for {ind.value[:80]}", f"lookup failed: {error}"))
            continue

        query_status = data.get("query_status", "")
        if query_status == "ok":
            url_status = data.get("url_status", "")
            threat = data.get("threat", "unknown")
            tags = data.get("tags", []) or []
            date_added = data.get("date_added", "")

            if url_status == "online":
                ind.reputation = "malicious"
                findings.append(Finding(
                    category="indicators",
                    severity="high",
                    title=f"URL is actively listed on URLhaus as {threat}",
                    description=f"The URL '{ind.value}' is in the URLhaus database of malicious URLs. Threat type: {threat}. First seen: {date_added}. Tags: {', '.join(tags) if tags else 'none'}.",
                    recommendation="Do not visit this URL. It is a confirmed malicious resource. If a user has already clicked, initiate incident response.",
                    evidence=f"URL: {ind.value}\nThreat: {threat}\nStatus: online\nTags: {', '.join(tags)}",
                ))
            elif url_status == "offline":
                ind.reputation = "suspicious"
                findings.append(Finding(
                    category="indicators",
                    severity="medium",
                    title="URL previously listed as malicious on URLhaus",
                    description=f"The URL '{ind.value}' was previously listed on URLhaus as {threat} (status: offline). The attacker may have taken it down or rotated infrastructure.",
                    recommendation="Treat as malicious. URLs that were once hosting malware often become active again or indicate the sender is part of a known campaign.",
                    evidence=f"URL: {ind.value}\nThreat: {threat}\nStatus: offline\nDate added: {date_added}",
                ))
        elif query_status == "no_results":
            ind.reputation = "not_listed"
        else:
            notes.append((f"URLhaus reputation for {ind.value[:80]}", f"unexpected answer: {str(query_status)[:60] or 'empty'}"))

    return findings


def hash_attachments(body: EmailBody, raw_email: str) -> tuple:
    """Compute hashes for attachments. Returns (indicators, findings)."""
    import email
    import email.policy
    from email import message_from_string

    indicators = []
    findings = []

    if not body.attachments:
        return indicators, findings

    try:
        msg = message_from_string(raw_email, policy=email.policy.default)
    except Exception:
        return indicators, findings

    if not msg.is_multipart():
        return indicators, findings

    for part in msg.walk():
        cdisp = str(part.get("Content-Disposition", ""))
        if "attachment" not in cdisp.lower():
            continue

        filename = part.get_filename()
        if not filename:
            continue

        try:
            payload = part.get_payload(decode=True)
            if not payload:
                continue
        except Exception:
            continue

        md5 = hashlib.md5(payload).hexdigest()
        sha256 = hashlib.sha256(payload).hexdigest()

        indicators.append(Indicator(type="hash", value=sha256, context=f"SHA-256 of {filename}"))
        indicators.append(Indicator(type="hash", value=md5, context=f"MD5 of {filename}"))

    return indicators, findings


def check_hashes_malwarebazaar(indicators: list, policy: Policy = None, notes: list = None) -> list:
    """Check SHA-256 hashes against MalwareBazaar. Returns list of Findings."""
    policy = policy or OFFLINE
    notes = notes if notes is not None else []
    findings = []

    sha256_hashes = [i for i in indicators if i.type == "hash" and len(i.value) == 64]
    if not sha256_hashes:
        return findings

    if not policy.online:
        notes.append((f"MalwareBazaar attachment hash reputation ({len(sha256_hashes)} hash(es))", "offline: MalwareBazaar was not queried (use --online)"))
        return findings

    if len(sha256_hashes) > MAX_LOOKUPS:
        notes.append(("MalwareBazaar reputation", f"only the first {MAX_LOOKUPS} of {len(sha256_hashes)} hashes were queried"))

    for ind in sha256_hashes[:MAX_LOOKUPS]:
        data, error = _post(MALWAREBAZAAR_API, {"query": "get_info", "hash": ind.value})
        if error:
            notes.append((f"MalwareBazaar reputation for {ind.value[:16]}...", f"lookup failed: {error}"))
            continue

        query_status = data.get("query_status", "")
        if query_status == "ok":
            results = data.get("data", []) or []
            if results:
                r = results[0]
                signature = r.get("signature", "unknown") or "unknown"
                file_type = r.get("file_type", "unknown")
                first_seen = r.get("first_seen", "unknown")

                ind.reputation = "malicious"
                findings.append(Finding(
                    category="indicators",
                    severity="high",
                    title="Attachment matches known malware on MalwareBazaar",
                    description=f"The attachment hash '{ind.value[:16]}...' matches a known malware sample on MalwareBazaar. Signature: {signature}. File type: {file_type}. First seen: {first_seen}.",
                    recommendation="Do not open this attachment. This is a confirmed malware sample. Initiate incident response if anyone has already opened it.",
                    evidence=f"SHA-256: {ind.value}\nSignature: {signature}\nFile type: {file_type}\nFirst seen: {first_seen}",
                ))
        elif query_status in ("hash_not_found", "no_results"):
            ind.reputation = "not_listed"
        else:
            notes.append((f"MalwareBazaar reputation for {ind.value[:16]}...", f"unexpected answer: {str(query_status)[:60] or 'empty'}"))

    return findings


def _post(url: str, form: dict) -> tuple:
    """POST a form and return (json_dict, error)."""
    try:
        resp = requests.post(url, data=form, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as e:
        return {}, type(e).__name__
    if resp.status_code != 200:
        return {}, f"HTTP {resp.status_code}"
    try:
        data = resp.json()
    except ValueError:
        return {}, "response was not JSON"
    if not isinstance(data, dict):
        return {}, "response was not a JSON object"
    return data, None
