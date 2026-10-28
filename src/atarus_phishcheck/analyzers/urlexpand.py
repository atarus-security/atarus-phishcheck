"""Read the first redirect of a URL shortener, without following it.

Opt-in only (``--online --expand-links``). For each shortener URL in the
email, at most one HEAD request goes to the shortener host itself, after
its addresses are checked to be public. The Location header is recorded as
the destination and is never contacted: a phisher's final host must not
learn that the email was opened, and a Location pointing at an internal or
cloud-metadata address must never be requested from the analyst's network.

Standard library only.
"""
import http.client
import socket
import ssl
from urllib.parse import urljoin
from atarus_phishcheck import __version__
from atarus_phishcheck.models import Indicator, Finding
from atarus_phishcheck.network import Policy, OFFLINE, public_addresses, split_url, looks_like_ip, is_public_address

NETWORK = [
    {
        "module": "urlexpand",
        "destination": "the URL shortener host named in the email (bit.ly, tinyurl.com and the others in SHORTENER_DOMAINS), after its addresses are checked to be public",
        "sends": "one HEAD request for the shortened path with User-Agent atarus-phishcheck/<version>; the Location header is read and never followed",
        "when": "--online --expand-links only",
    },
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "t.co", "tiny.cc", "lnkd.in", "rb.gy", "cutt.ly", "shorturl.at",
    "bit.do", "rebrand.ly", "clck.ru", "soo.gd", "s2r.co",
    "tr.im", "adf.ly", "link.to", "po.st", "x.co",
}

USER_AGENT = f"atarus-phishcheck/{__version__}"
REQUEST_TIMEOUT = 6
MAX_URLS = 10
REDIRECT_CODES = (301, 302, 303, 307, 308)


def expand_urls(indicators: list, policy: Policy = None, notes: list = None) -> tuple:
    """Read one redirect hop for shortener URLs. Returns (new_indicators, findings)."""
    policy = policy or OFFLINE
    notes = notes if notes is not None else []
    new_indicators = []
    findings = []

    shortener_urls = []
    for ind in indicators:
        if ind.type != "url":
            continue
        try:
            _, host, _, _ = split_url(ind.value)
        except ValueError:
            continue
        if _base_domain(host) in SHORTENER_DOMAINS:
            shortener_urls.append(ind.value)

    if not shortener_urls:
        return new_indicators, findings

    if not (policy.online and policy.expand_links):
        reason = "offline: no request was made (use --online --expand-links)" if not policy.online else "not enabled: no request was made (add --expand-links)"
        notes.append((f"URL shortener expansion ({len(shortener_urls)} shortener URL(s))", reason))
        return new_indicators, findings

    if len(shortener_urls) > MAX_URLS:
        notes.append(("URL shortener expansion", f"only the first {MAX_URLS} of {len(shortener_urls)} shortener URLs were queried"))

    for url in shortener_urls[:MAX_URLS]:
        scheme, host, port, path = split_url(url)
        base_domain = _base_domain(host)

        try:
            addresses = public_addresses(host, port)
        except ValueError as e:
            notes.append((f"URL shortener expansion for {host}", f"refused before any request: {e}"))
            findings.append(_not_expanded(url, base_domain, str(e)))
            continue

        status, location, error = _head_once(scheme, host, port, path, addresses[0])

        if error:
            notes.append((f"URL shortener expansion for {host}", f"request failed: {error}"))
            findings.append(_not_expanded(url, base_domain, error))
            continue

        if status not in REDIRECT_CODES or not location:
            findings.append(Finding(
                category="indicators",
                severity="low",
                title=f"URL shortener did not redirect: {base_domain} answered {status}",
                description=f"A HEAD request to '{url}' returned HTTP {status} with no redirect. The link may be expired, removed, or may hide its destination behind a page that needs a browser.",
                recommendation="Treat the URL as unverified. Do not open it outside an isolated analysis environment.",
                evidence=f"URL: {url}\nHTTP status: {status}",
            ))
            continue

        default_port = 443 if scheme == "https" else 80
        base = f"{scheme}://{host}{path}" if port == default_port else f"{scheme}://{host}:{port}{path}"
        destination = urljoin(base, location.strip())[:2048]
        try:
            _, dest_host, _, _ = split_url(destination)
        except ValueError:
            dest_host = ""

        new_indicators.append(Indicator(type="url", value=destination, context=f"Redirect target of {base_domain} (not contacted)"))
        if dest_host:
            new_indicators.append(Indicator(type="domain", value=dest_host, context=f"Redirect target of {base_domain} (not contacted)"))

        if dest_host and looks_like_ip(dest_host) and not is_public_address(dest_host):
            findings.append(Finding(
                category="indicators",
                severity="high",
                title=f"URL shortener redirects to a non-public address: {dest_host}",
                description=f"The shortener '{url}' redirects to '{destination}', an address inside a private, loopback, link-local or reserved range. A link that sends the victim's browser to an internal address is a sign of an attack on the recipient's own network, or of a link crafted to probe analysis tools. The address was not contacted.",
                recommendation="Do not open the link. Report the destination to the network owner.",
                evidence=f"Shortener: {url}\nLocation: {destination}\nNot followed",
            ))
            continue

        severity = "high" if looks_like_ip(dest_host) else "medium"
        onward = ""
        if dest_host and _base_domain(dest_host) in SHORTENER_DOMAINS:
            onward = " The destination is itself a shortener; only the first hop was read."
        findings.append(Finding(
            category="indicators",
            severity=severity,
            title=f"URL shortener redirects: {base_domain} points to {dest_host or destination}",
            description=f"The shortener '{url}' answered HTTP {status} with a redirect to '{destination}'. The destination was not contacted.{onward}",
            recommendation=f"Evaluate the destination '{dest_host or destination}' with a reputation source before anyone opens it. Shorteners are used in phishing to hide the real destination.",
            evidence=f"Shortener: {url}\nHTTP status: {status}\nLocation: {destination}\nHops followed: 0 (one request to the shortener, destination not contacted)",
        ))

    return new_indicators, findings


def _not_expanded(url: str, base_domain: str, reason: str) -> Finding:
    return Finding(
        category="indicators",
        severity="low",
        title=f"URL shortener could not be expanded: {base_domain}",
        description=f"The shortener '{url}' was not expanded: {reason}. The destination remains unknown.",
        recommendation="Treat the URL as suspicious until the destination is known.",
        evidence=f"URL: {url}\nReason: {reason}",
    )


def _head_once(scheme: str, host: str, port: int, path: str, ip: str) -> tuple:
    """One HEAD request to ``ip`` (already checked public) with Host/SNI ``host``.

    Returns (status, location, error). Redirects are never followed.
    """
    sock = None
    conn = None
    try:
        sock = socket.create_connection((ip, port), timeout=REQUEST_TIMEOUT)
        if scheme == "https":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        conn = http.client.HTTPConnection(host, port, timeout=REQUEST_TIMEOUT)
        conn.sock = sock
        conn.request("HEAD", path, headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"})
        resp = conn.getresponse()
        location = resp.getheader("Location", "") or ""
        return resp.status, location[:2048], None
    except socket.timeout:
        return 0, "", "timeout"
    except ssl.SSLError as e:
        return 0, "", f"TLS error: {getattr(e, 'reason', None) or type(e).__name__}"
    except (OSError, http.client.HTTPException) as e:
        return 0, "", f"{type(e).__name__}: {str(e)[:100]}"
    finally:
        try:
            if conn is not None:
                conn.close()
            elif sock is not None:
                sock.close()
        except Exception:
            pass


def _base_domain(domain: str) -> str:
    parts = domain.lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain.lower()
