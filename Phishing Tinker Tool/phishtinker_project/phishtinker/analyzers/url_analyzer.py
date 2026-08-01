"""URL analysis helpers: classify and enrich extracted URLs.

This module performs local heuristics (IP-based URLs, punycode, suspicious TLDs)
and optional online enrichment (follow redirects) when `requests` is available.
"""
import re
from urllib.parse import urlparse

from ..utils.ioc import extract_domains_from_urls, extract_urls, valid_ip

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

SUSPICIOUS_TLDS = ('.zip', '.xyz', '.top', '.gq', '.tk', '.ml', '.cf', '.click', '.link', '.gdn')


def analyze_urls(urls, follow_redirects=False, timeout=6):
    """Analyze a set of URLs and return a summary dict.
    If follow_redirects=True and requests is available, the final URL and redirect
    chain will be fetched (HEAD request preferred).
    """
    urls = sorted(set(urls))
    summary = {
        'total': len(urls),
        'ip_urls': [],
        'suspicious_tld': [],
        'punycode': [],
        'details': [],
    }

    for u in urls:
        try:
            parsed = urlparse(u)
            host = parsed.hostname or ''
        except Exception:
            host = ''

        detail = {'url': u, 'host': host}

        # IP-based URL
        if valid_ip(host):
            summary['ip_urls'].append(u)
            detail['note'] = 'host_is_ip'

        # punycode
        if host.startswith('xn--') or 'xn--' in host:
            summary['punycode'].append(u)
            detail.setdefault('notes', []).append('punycode')

        # suspicious tld
        for t in SUSPICIOUS_TLDS:
            if host.endswith(t):
                summary['suspicious_tld'].append(u)
                detail.setdefault('notes', []).append('suspicious_tld')
                break

        # optional online follow
        if follow_redirects and HAVE_REQUESTS:
            try:
                r = requests.head(u, allow_redirects=True, timeout=timeout)
                chain = [h.url for h in r.history] + [r.url]
                detail['redirect_chain'] = chain
            except Exception:
                # try GET as fallback
                try:
                    r = requests.get(u, allow_redirects=True, timeout=timeout)
                    chain = [h.url for h in r.history] + [r.url]
                    detail['redirect_chain'] = chain
                except Exception:
                    detail['redirect_chain'] = None

        summary['details'].append(detail)

    return summary
