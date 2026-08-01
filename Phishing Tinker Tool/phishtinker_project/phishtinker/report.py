"""
Report generation: plain-text (for export/printing) and JSON (for tooling/CI use).
"""
import json
import datetime

from .utils.ioc import defang_ip, defang_url, defang_domain


def build_text_report(analysis, score_engine, defang=True):
    a = analysis
    lines = []
    verdict, _ = score_engine.verdict()

    lines.append("=" * 70)
    lines.append("PHISHTINKER ANALYSIS REPORT")
    lines.append(f"Generated: {datetime.datetime.now().isoformat()}")
    lines.append(f"Source file: {a.path}")
    lines.append("=" * 70)

    lines.append(f"\nVERDICT: {verdict}")
    lines.append(f"RISK SCORE: {score_engine.score}/100\n")

    lines.append("-- FINDINGS --")
    if not score_engine.findings:
        lines.append("  No notable heuristic findings.")
    for sev, text, pts in score_engine.sorted_findings():
        lines.append(f"  [{sev:6}] (+{pts:>2}) {text}")

    lines.append("\n-- AUTHENTICATION --")
    for mech, val in a.auth_results.items():
        lines.append(f"  {mech.upper():6}: {val}")

    lines.append("\n-- KEY HEADERS --")
    for k, v in a.headers.items():
        lines.append(f"  {k}: {v}")

    lines.append("\n-- IP ADDRESSES --")
    for ip in sorted(a.ips):
        lines.append(f"  {defang_ip(ip) if defang else ip}")

    lines.append("\n-- URLS --")
    for u in sorted(a.urls):
        lines.append(f"  {defang_url(u) if defang else u}")

    lines.append("\n-- DOMAINS --")
    for d in sorted(a.domains):
        lines.append(f"  {defang_domain(d) if defang else d}")

    lines.append("\n-- ATTACHMENTS --")
    if not a.attachments:
        lines.append("  None")
    for att in a.attachments:
        lines.append(f"  Filename : {att.filename}")
        lines.append(f"  Type     : {att.content_type}")
        lines.append(f"  Size     : {att.size} bytes")
        lines.append(f"  MD5      : {att.md5}")
        lines.append(f"  SHA1     : {att.sha1}")
        lines.append(f"  SHA256   : {att.sha256}")
        lines.append(f"  VirusTotal: {getattr(att, 'vt_summary', 'Not checked')}")
        lines.append("")

    if getattr(a, 'content_analysis', None):
        ca = a.content_analysis
        lines.append("\n-- CONTENT ANALYSIS --")
        summary = ca.get('summary', {})
        lines.append(f"  URLs found: {summary.get('url_count', 0)}")
        lines.append(f"  IPs found: {summary.get('ip_count', 0)}")
        lines.append(f"  Attachments: {summary.get('attachment_count', 0)}")
        lines.append(f"  Plain text parts: {summary.get('plain_parts', 0)}")
        lines.append(f"  HTML parts: {summary.get('html_parts', 0)}")
        lines.append(f"  Heuristic score: {summary.get('heuristic_score', 'N/A')}")
        if ca.get('phishing_types'):
            lines.append("  Phishing characteristics:")
            for item in ca['phishing_types']:
                lines.append(f"    - {item}")
        if ca.get('keywords'):
            lines.append(f"  Suspicious keywords: {', '.join(ca['keywords'])}")
        if ca.get('suspicious_hosts'):
            lines.append("  Suspicious hosts:")
            for host in ca['suspicious_hosts']:
                lines.append(f"    - {host}")
        if ca.get('url_analysis'):
            ua = ca['url_analysis']
            lines.append("\n  URL analysis:")
            lines.append(f"    - Total URLs: {ua.get('total', 0)}")
            lines.append(f"    - IP-based URLs: {len(ua.get('ip_urls', []))}")
            lines.append(f"    - Punycode URLs: {len(ua.get('punycode', []))}")
            lines.append(f"    - Suspicious TLD URLs: {len(ua.get('suspicious_tld', []))}")
        if ca.get('nlp_analysis'):
            lines.append("\n-- NLP / entity extraction --")
            lines.extend([f"  {line}" for line in ca['nlp_analysis'].splitlines()])

    return "\n".join(lines)


def build_json_report(analysis, score_engine):
    a = analysis
    verdict, _ = score_engine.verdict()
    return json.dumps({
        "source_file": a.path,
        "generated": datetime.datetime.now().isoformat(),
        "verdict": verdict,
        "score": score_engine.score,
        "findings": [{"severity": s, "text": t, "points": p} for s, t, p in score_engine.sorted_findings()],
        "auth_results": a.auth_results,
        "headers": a.headers,
        "ips": sorted(a.ips),
        "urls": sorted(a.urls),
        "domains": sorted(a.domains),
        "attachments": [
            {
                "filename": att.filename,
                "content_type": att.content_type,
                "size": att.size,
                "md5": att.md5,
                "sha1": att.sha1,
                "sha256": att.sha256,
                "virustotal": getattr(att, "vt_summary", None),
            }
            for att in a.attachments
        ],
        "content_analysis": getattr(a, "content_analysis", None),
    }, indent=2)


def build_markdown_report(analysis, score_engine, defang=True):
    a = analysis
    lines = [
        f"# PhishTinker Analysis Report",
        f"**Generated:** {datetime.datetime.now().isoformat()}  ",
        f"**Source file:** {a.path}  ",
        f"## Verdict",
        f"- **{score_engine.verdict()[0]}**",
        f"- Risk score: **{score_engine.score}/100**",
        "## Findings",
    ]

    if not score_engine.findings:
        lines.append("- No notable heuristic findings.")
    for sev, text, pts in score_engine.sorted_findings():
        lines.append(f"- **{sev}** (+{pts}): {text}")

    lines.extend([
        "## Authentication",
    ])
    for mech, val in a.auth_results.items():
        lines.append(f"- **{mech.upper()}**: {val}")

    lines.extend([
        "## Key Headers",
    ])
    for k, v in a.headers.items():
        lines.append(f"- **{k}**: {v}")

    lines.extend([
        "## IP Addresses",
    ])
    if not a.ips:
        lines.append("- None")
    for ip in sorted(a.ips):
        lines.append(f"- {defang_ip(ip) if defang else ip}")

    lines.extend([
        "## URLs",
    ])
    if not a.urls:
        lines.append("- None")
    for u in sorted(a.urls):
        lines.append(f"- {defang_url(u) if defang else u}")

    lines.extend([
        "## Domains",
    ])
    if not a.domains:
        lines.append("- None")
    for d in sorted(a.domains):
        lines.append(f"- {defang_domain(d) if defang else d}")

    lines.extend([
        "## Attachments",
    ])
    if not a.attachments:
        lines.append("- None")
    for att in a.attachments:
        lines.extend([
            f"- **Filename:** {att.filename}",
            f"  - Type: {att.content_type}",
            f"  - Size: {att.size} bytes",
            f"  - MD5: {att.md5}",
            f"  - SHA1: {att.sha1}",
            f"  - SHA256: {att.sha256}",
            f"  - VirusTotal: {getattr(att, 'vt_summary', 'Not checked')}",
        ])

    if getattr(a, 'content_analysis', None):
        ca = a.content_analysis
        lines.extend(["## Content Analysis", "### Summary"])
        summary = ca.get('summary', {})
        lines.extend([
            f"- URLs found: {summary.get('url_count', 0)}",
            f"- IPs found: {summary.get('ip_count', 0)}",
            f"- Attachments: {summary.get('attachment_count', 0)}",
            f"- Plain text parts: {summary.get('plain_parts', 0)}",
            f"- HTML parts: {summary.get('html_parts', 0)}",
            f"- Heuristic score: {summary.get('heuristic_score', 'N/A')}",
        ])

        if ca.get('phishing_types'):
            lines.append("### Detected phishing characteristics")
            for item in ca['phishing_types']:
                lines.append(f"- {item}")

        if ca.get('keywords'):
            lines.extend(["### Suspicious keywords", ""])
            lines.append(f"- {', '.join(ca['keywords'])}")

        if ca.get('suspicious_hosts'):
            lines.extend(["### Suspicious hosts", ""])
            for host in ca['suspicious_hosts']:
                lines.append(f"- {host}")

        if ca.get('attachment_summary'):
            lines.extend(["### Attachment summary", ""])
            for att in ca['attachment_summary']:
                flags = ", ".join(att['flags']) if att['flags'] else 'none'
                lines.append(f"- {att['filename']} — {flags}")
                if att.get('vt_summary'):
                    lines.append(f"  - VT: {att['vt_summary']}")

        if ca.get('url_analysis'):
            ua = ca['url_analysis']
            lines.extend(["### URL analysis", ""])
            lines.append(f"- Total URLs: {ua.get('total', 0)}")
            lines.append(f"- IP-based URLs: {len(ua.get('ip_urls', []))}")
            lines.append(f"- Punycode suspicious URLs: {len(ua.get('punycode', []))}")
            lines.append(f"- Suspicious TLD URLs: {len(ua.get('suspicious_tld', []))}")

        if ca.get('nlp_analysis'):
            lines.extend(["### NLP / entity extraction", ""])
            lines.append("```text")
            lines.extend(ca['nlp_analysis'].splitlines())
            lines.append("```")

    return "\n".join(lines)
