"""Safely expand URL shorteners by following redirect chain without loading pages"""
import requests
from urllib.parse import urlparse
from atarus_phishcheck.models import Indicator, Finding


SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "t.co", "tiny.cc", "lnkd.in", "rb.gy", "cutt.ly", "shorturl.at",
    "bit.do", "rebrand.ly", "clck.ru", "soo.gd", "s2r.co",
    "tr.im", "adf.ly", "link.to", "po.st", "x.co",
}

USER_AGENT = "atarus-phishcheck/0.3.0"
REQUEST_TIMEOUT = 6
MAX_REDIRECTS = 8


def expand_urls(indicators: list, offline: bool = False) -> tuple:
    """Follow redirect chains for shortener URLs. Returns (new_indicators, findings)."""
    new_indicators = []
    findings = []

    if offline:
        return new_indicators, findings

    url_indicators = [i for i in indicators if i.type == "url"]

    for ind in url_indicators[:10]:
        url = ind.value
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        domain = parsed.netloc.lower().split(":")[0]
        base_domain = _get_base_domain(domain)

        if base_domain not in SHORTENER_DOMAINS:
            continue

        chain, final_url, error = _follow_redirects(url)

        if error:
            findings.append(Finding(
                category="indicators",
                severity="low",
                title=f"URL shortener could not be expanded: {base_domain}",
                description=f"The shortener '{url}' could not be followed: {error}. The destination remains unknown.",
                recommendation="Treat the URL as suspicious until the destination is verified through a safe URL expansion service.",
                evidence=f"URL: {url}\nError: {error}",
            ))
            continue

        if len(chain) <= 1 or final_url == url:
            continue

        final_parsed = urlparse(final_url)
        final_domain = final_parsed.netloc.lower().split(":")[0]

        new_indicators.append(Indicator(
            type="url",
            value=final_url,
            context=f"Expanded from {base_domain}",
        ))
        if final_domain:
            new_indicators.append(Indicator(
                type="domain",
                value=final_domain,
                context=f"Expanded destination of {base_domain}",
            ))

        severity = "medium"
        if _is_ip_address(final_domain):
            severity = "high"

        findings.append(Finding(
            category="indicators",
            severity=severity,
            title=f"URL shortener expanded: {base_domain} redirects to {final_domain}",
            description=f"The shortener '{url}' redirects to '{final_url}'. The actual destination can now be evaluated for reputation and content.",
            recommendation=f"Evaluate the final destination '{final_domain}' directly. Shorteners are used in phishing to obscure malicious destinations.",
            evidence=f"Shortener: {url}\nRedirect chain: {' -> '.join(chain)}\nFinal destination: {final_url}",
        ))

    return new_indicators, findings


def _follow_redirects(url: str) -> tuple:
    """Follow HTTP redirects without loading page body. Returns (chain, final_url, error)."""
    chain = [url]
    current = url

    try:
        for _ in range(MAX_REDIRECTS):
            resp = requests.head(
                current,
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )

            if resp.status_code in (301, 302, 303, 307, 308):
                next_url = resp.headers.get("Location", "")
                if not next_url:
                    break
                if not next_url.startswith("http"):
                    parsed = urlparse(current)
                    next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"
                chain.append(next_url)
                current = next_url
            else:
                break

        return chain, current, None

    except requests.exceptions.Timeout:
        return chain, current, "timeout"
    except requests.exceptions.TooManyRedirects:
        return chain, current, "too many redirects"
    except requests.exceptions.RequestException as e:
        return chain, current, str(e)[:100]
    except Exception as e:
        return chain, current, str(e)[:100]


def _get_base_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _is_ip_address(s: str) -> bool:
    import re
    return bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', s))
