"""
IOC helpers: extraction, validation, defanging.
Improvements over the reference eioc.py:
 - IP validation happens before regex dedup (avoids false positives like version numbers)
 - defanging is reversible / consistent (single source of truth)
 - reserved/private range check uses a compiled network list (no repeated parsing)
"""
import re
import ipaddress

URL_RE = re.compile(
    r'https?://(?:(?:[\w\-]+\.)+[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:[/?#][^\s"\'<>\]\)]*)?',
    re.IGNORECASE,
)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_FROM_URL_RE = re.compile(r'https?://([^/]+)')
EMAIL_ADDR_RE = re.compile(r'@([\w\-\.]+)')

_RESERVED_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "0.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16",
    "192.0.0.0/24", "192.0.2.0/24", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "127.0.0.0/8",
)]


def valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_reserved_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(addr in net for net in _RESERVED_NETS)


def extract_ips(text: str) -> set:
    return {ip for ip in IP_RE.findall(text) if valid_ip(ip)}


def extract_urls(text: str) -> set:
    return set(URL_RE.findall(text))


def extract_domains_from_urls(urls) -> set:
    domains = set()
    for u in urls:
        m = DOMAIN_FROM_URL_RE.match(u)
        if m:
            domains.add(m.group(1).lower().split(":")[0])  # strip port
    return domains


def extract_domain_from_addr(addr_field: str):
    if not addr_field:
        return None
    m = EMAIL_ADDR_RE.search(addr_field)
    return m.group(1).lower() if m else None


def defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")


def defang_url(url: str) -> str:
    url = url.replace("http://", "hxxp[://]").replace("https://", "hxxps[://]")
    return url.replace(".", "[.]")


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")
