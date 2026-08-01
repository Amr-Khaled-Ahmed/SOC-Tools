"""
Online reputation lookups. Opt-in only, cached, never blocks GUI thread when
called via ThreadPoolExecutor from the GUI layer.
"""
from functools import lru_cache

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from .ioc import is_reserved_ip


def country_code_to_flag(code: str) -> str:
    code = (code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return chr(ord(code[0]) - ord("A") + 0x1F1E6) + chr(ord(code[1]) - ord("A") + 0x1F1E6)


@lru_cache(maxsize=512)
def ip_lookup_info(ip: str, timeout: int = 5):
    """Return geo details for a public IP, or None."""
    if not HAVE_REQUESTS or is_reserved_ip(ip):
        return None
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            return {
                "city": d.get("city", ""),
                "region": d.get("region", ""),
                "country": d.get("country", ""),
                "org": d.get("org", ""),
            }
    except Exception:
        pass
    return None


@lru_cache(maxsize=512)
def ip_lookup(ip: str, timeout: int = 5):
    """Return a short human-readable geo/ISP string for a public IP, or None."""
    info = ip_lookup_info(ip, timeout=timeout)
    if not info:
        return None
    city = info.get("city", "")
    region = info.get("region", "")
    country = info.get("country", "")
    org = info.get("org", "")
    parts = [part for part in (city, region, country) if part]
    prefix = ", ".join(parts)
    suffix = f" — {org}" if org else ""
    return f"{prefix}{suffix}" if prefix else org or None


@lru_cache(maxsize=512)
def virustotal_hash_lookup(sha256: str, api_key: str, timeout: int = 8):
    """Optional VT hash reputation lookup. Requires a user-supplied API key."""
    if not HAVE_REQUESTS or not api_key:
        return None
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=timeout,
        )
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            return f"{malicious}/{total} malicious, {suspicious} suspicious"
        elif r.status_code == 404:
            return "Not found in VirusTotal"
    except Exception:
        pass
    return None
