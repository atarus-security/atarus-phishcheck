"""Check URLs and file hashes against public threat intel feeds"""
import requests
import hashlib
from urllib.parse import urlparse
from atarus_phishcheck.models import Indicator, Finding, EmailBody


URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"

USER_AGENT = "atarus-phishcheck/0.2.0"
REQUEST_TIMEOUT = 8


def check_urls(indicators: list, offline: bool = False) -> list:
    """Check URLs against URLhaus. Returns list of Findings. Modifies indicators in-place with reputation."""
    findings = []

    if offline:
        return findings

    url_indicators = [i for i in indicators if i.type == "url"]
    if not url_indicators:
        return findings

    for ind in url_indicators[:10]:
        try:
            resp = requests.post(
                URLHAUS_API,
                data={"url": ind.value},
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
            )

            if resp.status_code != 200:
                continue

            data = resp.json()
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
                        title=f"URL previously listed as malicious on URLhaus",
                        description=f"The URL '{ind.value}' was previously listed on URLhaus as {threat} (status: offline). The attacker may have taken it down or rotated infrastructure.",
                        recommendation="Treat as malicious. URLs that were once hosting malware often become active again or indicate the sender is part of a known campaign.",
                        evidence=f"URL: {ind.value}\nThreat: {threat}\nStatus: offline\nDate added: {date_added}",
                    ))
            elif query_status == "no_results":
                ind.reputation = "clean"

        except requests.exceptions.RequestException:
            pass
        except ValueError:
            pass
        except Exception:
            pass

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
        sha1 = hashlib.sha1(payload).hexdigest()
        sha256 = hashlib.sha256(payload).hexdigest()

        indicators.append(Indicator(type="hash", value=sha256, context=f"SHA-256 of {filename}"))
        indicators.append(Indicator(type="hash", value=md5, context=f"MD5 of {filename}"))

    return indicators, findings


def check_hashes_malwarebazaar(indicators: list, offline: bool = False) -> list:
    """Check SHA-256 hashes against MalwareBazaar. Returns list of Findings."""
    findings = []

    if offline:
        return findings

    sha256_hashes = [i for i in indicators if i.type == "hash" and len(i.value) == 64]
    if not sha256_hashes:
        return findings

    for ind in sha256_hashes[:10]:
        try:
            resp = requests.post(
                MALWAREBAZAAR_API,
                data={"query": "get_info", "hash": ind.value},
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
            )

            if resp.status_code != 200:
                continue

            data = resp.json()
            query_status = data.get("query_status", "")

            if query_status == "ok":
                results = data.get("data", [])
                if results:
                    r = results[0]
                    signature = r.get("signature", "unknown") or "unknown"
                    file_type = r.get("file_type", "unknown")
                    first_seen = r.get("first_seen", "unknown")

                    ind.reputation = "malicious"
                    findings.append(Finding(
                        category="indicators",
                        severity="high",
                        title=f"Attachment matches known malware on MalwareBazaar",
                        description=f"The attachment hash '{ind.value[:16]}...' matches a known malware sample on MalwareBazaar. Signature: {signature}. File type: {file_type}. First seen: {first_seen}.",
                        recommendation="Do not open this attachment. This is a confirmed malware sample. Initiate incident response if anyone has already opened it.",
                        evidence=f"SHA-256: {ind.value}\nSignature: {signature}\nFile type: {file_type}\nFirst seen: {first_seen}",
                    ))

        except requests.exceptions.RequestException:
            pass
        except ValueError:
            pass
        except Exception:
            pass

    return findings
