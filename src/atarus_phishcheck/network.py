"""Network policy and address guard.

Nothing in this package opens a connection unless the Policy passed to it
says so. The default Policy is offline. Every module that can send anything
declares a NETWORK list describing the destination, what is sent and the
flag that enables it; the README table is written from those lists.

Standard library only.
"""
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit


class NetworkDisabled(Exception):
    """Raised when a lookup is attempted while the policy is offline."""


@dataclass
class Policy:
    """What this run is allowed to contact."""
    online: bool = False
    expand_links: bool = False

    @property
    def mode(self) -> str:
        return "online" if self.online else "offline"

    def destinations(self, from_domain: str = "") -> list:
        """Plain-English list of what an online run may contact, printed before any lookup."""
        if not self.online:
            return []
        domain = from_domain or "<sender domain>"
        lines = [
            f"your DNS resolver: TXT queries for {domain} and _dmarc.{domain} (SPF and DMARC records)",
            "urlhaus-api.abuse.ch over HTTPS: each URL found in the email, up to 10",
            "mb-api.abuse.ch over HTTPS: the SHA-256 of each attachment, up to 10",
            "ip-api.com over plain HTTP: each public IP address from the headers, up to 5",
        ]
        if self.expand_links:
            lines.append("each URL shortener host named in the email: one HEAD request, up to 10, the redirect is read but never followed")
        return lines


OFFLINE = Policy()


def is_public_address(text: str) -> bool:
    """True only for a literal IP address that is globally routable.

    Refuses private, loopback, link-local (including 169.254.169.254),
    carrier-grade NAT, multicast, reserved, unspecified and documentation
    ranges, IPv4-mapped IPv6 forms of those, and anything that is not an
    address at all.
    """
    try:
        addr = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped
        if mapped is not None:
            return is_public_address(str(mapped))
        if addr.sixtofour is not None or addr.teredo is not None:
            return False
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return False
    if addr.is_reserved or addr.is_unspecified:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        if addr in ipaddress.ip_network("100.64.0.0/10"):
            return False
        if addr in ipaddress.ip_network("0.0.0.0/8"):
            return False
    return addr.is_global


def looks_like_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]"))
        return True
    except ValueError:
        return False


def public_addresses(host: str, port: int = 80) -> list:
    """Resolve host and return its addresses, but only if every one is public.

    Raises ValueError with a plain reason when the host is a non-public
    literal, resolves to any non-public address, or does not resolve.
    """
    host = host.strip("[]")
    if not host:
        raise ValueError("empty host")
    if looks_like_ip(host):
        if not is_public_address(host):
            raise ValueError(f"{host} is not a public address")
        return [host]
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError) as e:
        raise ValueError(f"{host} did not resolve ({e})")
    addresses = []
    for info in infos:
        ip = info[4][0]
        if ip not in addresses:
            addresses.append(ip)
    if not addresses:
        raise ValueError(f"{host} did not resolve")
    bad = [ip for ip in addresses if not is_public_address(ip)]
    if bad:
        raise ValueError(f"{host} resolves to a non-public address ({', '.join(bad)})")
    return addresses


def split_url(url: str) -> tuple:
    """(scheme, host, port, path_with_query) for an http or https URL, else ValueError."""
    parts = urlsplit(url if "://" in url else f"http://{url}")
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme {scheme or '(none)'}")
    host = (parts.hostname or "").lower()
    if not host:
        raise ValueError("no host in URL")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("invalid port")
    if port is None:
        port = 443 if scheme == "https" else 80
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return scheme, host, port, path
