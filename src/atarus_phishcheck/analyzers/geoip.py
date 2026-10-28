"""IP geolocation and ASN lookup for sender and routing analysis (online only)."""
import requests
from atarus_phishcheck import __version__
from atarus_phishcheck.models import Indicator, Finding, EmailHeaders
from atarus_phishcheck.network import Policy, OFFLINE, is_public_address

NETWORK = [
    {
        "module": "geoip",
        "destination": "ip-api.com over plain HTTP (the free endpoint has no TLS)",
        "sends": "each public IP address found in the Received and X-Originating-IP headers, up to 5",
        "when": "--online only",
    },
]

IPAPI_URL = "http://ip-api.com/json/"
USER_AGENT = f"atarus-phishcheck/{__version__}"
REQUEST_TIMEOUT = 5
MAX_IPS = 5


def lookup_ips(indicators: list, headers: EmailHeaders, policy: Policy = None, notes: list = None) -> list:
    """Enrich IP indicators with geolocation. Returns list of findings."""
    policy = policy or OFFLINE
    notes = notes if notes is not None else []
    findings = []

    ip_indicators = [i for i in indicators if i.type == "ip"]
    unique_ips = {}
    for ind in ip_indicators:
        if ind.value not in unique_ips:
            unique_ips[ind.value] = ind

    if not unique_ips:
        return findings

    if not policy.online:
        notes.append((f"IP geolocation ({len(unique_ips)} address(es))", "offline: ip-api.com was not queried (use --online)"))
        return findings

    public = {ip: ind for ip, ind in unique_ips.items() if is_public_address(ip)}
    skipped = len(unique_ips) - len(public)
    if skipped:
        notes.append(("IP geolocation", f"{skipped} non-public address(es) from the headers were not sent to ip-api.com"))
    if len(public) > MAX_IPS:
        notes.append(("IP geolocation", f"only the first {MAX_IPS} of {len(public)} public addresses were queried"))

    sender_brand_context = _infer_expected_region(headers)

    for ip, ind in list(public.items())[:MAX_IPS]:
        geo_data, error = _lookup_single_ip(ip)
        if error:
            notes.append((f"IP geolocation for {ip}", f"lookup failed: {error}"))
            continue

        country_code = geo_data.get("countryCode", "")
        country = geo_data.get("country", "")
        city = geo_data.get("city", "")
        region_name = geo_data.get("regionName", "")
        isp = geo_data.get("isp", "")
        org = geo_data.get("org", "")
        as_info = geo_data.get("as", "")
        is_proxy = geo_data.get("proxy", False)
        is_hosting = geo_data.get("hosting", False)

        ind.context = f"{ind.context} | {country_code} ({city}, {region_name}) | {isp} | {as_info}".strip(" |")

        context_parts = []
        if city:
            context_parts.append(city)
        if region_name and region_name != city:
            context_parts.append(region_name)
        if country:
            context_parts.append(country)
        location = ", ".join(context_parts) if context_parts else "Unknown"

        evidence_lines = [
            f"IP: {ip}",
            f"Location: {location}",
            f"ISP: {isp}" if isp else "",
            f"Organization: {org}" if org else "",
            f"ASN: {as_info}" if as_info else "",
        ]
        evidence = "\n".join([l for l in evidence_lines if l])

        if is_proxy:
            findings.append(Finding(
                category="indicators",
                severity="high",
                title=f"Email routed through proxy/VPN: {ip}",
                description=f"The IP '{ip}' ({location}) is flagged by ip-api.com as a proxy or anonymizer. Established email infrastructure does not route through consumer proxies.",
                recommendation="Treat with high suspicion. Proxy/VPN routing of outbound email is commonly associated with phishing campaigns attempting to obscure origin.",
                evidence=evidence,
            ))
        elif is_hosting and _is_received_ip(ip, headers):
            findings.append(Finding(
                category="indicators",
                severity="low",
                title=f"Email sent from hosting provider: {isp or 'unknown'}",
                description=f"The IP '{ip}' ({location}) belongs to a hosting/datacenter provider ({isp}). Many services use hosting, but phishing kits are frequently hosted on cheap VPS infrastructure.",
                recommendation="Combined with other indicators, hosting-provider origin can indicate attacker-controlled infrastructure.",
                evidence=evidence,
            ))

        if sender_brand_context and country_code:
            expected = sender_brand_context.get("expected_countries", [])
            if expected and country_code not in expected:
                findings.append(Finding(
                    category="indicators",
                    severity="high",
                    title=f"Geographic mismatch: email claims {sender_brand_context.get('name')} but originates from {country}",
                    description=f"The sending IP '{ip}' is located in {country} ({city}). The email claims to be from {sender_brand_context.get('name')}, whose email infrastructure typically originates from {', '.join(expected)}. Major brands and government agencies have geographically consistent email infrastructure.",
                    recommendation="Strong indicator of brand impersonation or sender spoofing. Brand emails rarely originate from geographically unrelated countries.",
                    evidence=evidence,
                ))

    return findings


def _lookup_single_ip(ip: str) -> tuple:
    """Query ip-api.com. Returns (data, error)."""
    try:
        resp = requests.get(
            f"{IPAPI_URL}{ip}?fields=status,message,country,countryCode,region,regionName,city,isp,org,as,mobile,proxy,hosting",
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.RequestException as e:
        return {}, type(e).__name__
    if resp.status_code != 200:
        return {}, f"HTTP {resp.status_code}"
    try:
        data = resp.json()
    except ValueError:
        return {}, "response was not JSON"
    if not isinstance(data, dict) or data.get("status") != "success":
        return {}, f"ip-api.com answered: {str((data or {}).get('message', 'no data'))[:100]}"
    return data, None


def _infer_expected_region(headers: EmailHeaders) -> dict:
    """Based on From domain and content, guess expected country codes for the claimed sender"""
    domain = (headers.from_domain or "").lower()
    from_name = (headers.from_name or "").lower()
    subject = (headers.subject or "").lower()

    combined = f"{domain} {from_name} {subject}"

    us_brands = ["paypal", "microsoft", "google", "apple", "amazon", "chase", "bank of america", "wells fargo", "citi", "amex", "american express", "irs", "usps", "ups", "fedex", "docusign", "adobe", "zoom", "slack", "github", "netflix", "dropbox", "outlook", "office365", "icloud", "gmail", "facebook", "linkedin", "instagram"]

    for brand in us_brands:
        if brand in combined:
            return {"name": brand.title(), "expected_countries": ["US", "CA", "IE", "NL", "DE", "GB", "SG", "AU", "JP"]}

    if domain.endswith(".gov"):
        return {"name": "US government", "expected_countries": ["US"]}
    if domain.endswith(".gov.uk"):
        return {"name": "UK government", "expected_countries": ["GB"]}
    if domain.endswith(".ca"):
        return {"name": "Canadian entity", "expected_countries": ["CA", "US"]}
    if domain.endswith(".de"):
        return {"name": "German entity", "expected_countries": ["DE", "NL", "US"]}

    return {}


def _is_received_ip(ip: str, headers: EmailHeaders) -> bool:
    for recv in headers.received_chain:
        if ip in recv:
            return True
    return False
