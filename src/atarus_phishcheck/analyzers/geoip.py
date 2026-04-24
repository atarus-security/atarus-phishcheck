"""IP geolocation and ASN lookup for sender and routing analysis"""
import requests
from atarus_phishcheck.models import Indicator, Finding, EmailHeaders


IPAPI_URL = "http://ip-api.com/json/"
USER_AGENT = "atarus-phishcheck/0.3.0"
REQUEST_TIMEOUT = 5


def lookup_ips(indicators: list, headers: EmailHeaders, offline: bool = False) -> list:
    """Enrich IP indicators with geolocation. Returns list of findings."""
    findings = []

    if offline:
        return findings

    ip_indicators = [i for i in indicators if i.type == "ip"]
    unique_ips = {}
    for ind in ip_indicators:
        if ind.value not in unique_ips:
            unique_ips[ind.value] = ind

    sender_brand_context = _infer_expected_region(headers)

    for ip, ind in list(unique_ips.items())[:5]:
        geo_data = _lookup_single_ip(ip)
        if not geo_data:
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
                description=f"The IP '{ip}' ({location}) is flagged as a proxy or anonymizer. Legitimate email infrastructure does not route through consumer proxies.",
                recommendation="Treat with high suspicion. Proxy/VPN routing of outbound email is commonly associated with phishing campaigns attempting to obscure origin.",
                evidence=evidence,
            ))
        elif is_hosting and _is_received_ip(ip, headers):
            findings.append(Finding(
                category="indicators",
                severity="low",
                title=f"Email sent from hosting provider: {isp or 'unknown'}",
                description=f"The IP '{ip}' ({location}) belongs to a hosting/datacenter provider ({isp}). While legitimate services often use hosting, phishing kits are frequently hosted on cheap VPS infrastructure.",
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
                    description=f"The sending IP '{ip}' is located in {country} ({city}). The email claims to be from {sender_brand_context.get('name')}, whose legitimate email infrastructure typically originates from {', '.join(expected)}. Major brands and government agencies have geographically consistent email infrastructure.",
                    recommendation="Strong indicator of brand impersonation or sender spoofing. Legitimate brand emails rarely originate from geographically unrelated countries.",
                    evidence=evidence,
                ))

    return findings


def _lookup_single_ip(ip: str) -> dict:
    """Query ip-api.com for geolocation data"""
    try:
        resp = requests.get(
            f"{IPAPI_URL}{ip}?fields=status,country,countryCode,region,regionName,city,isp,org,as,mobile,proxy,hosting",
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return {}
        data = resp.json()
        if data.get("status") != "success":
            return {}
        return data
    except Exception:
        return {}


def _infer_expected_region(headers: EmailHeaders) -> dict:
    """Based on From domain and content, guess expected country codes for legitimate mail"""
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
