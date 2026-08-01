"""
Heuristic risk scoring. Pure function of an EmailAnalysis + attachment findings —
no I/O, easy to unit test.
"""
from ..utils.ioc import DOMAIN_FROM_URL_RE, is_reserved_ip, valid_ip

URGENCY_WORDS = [
    "urgent", "immediately", "verify your account", "suspended", "click here",
    "act now", "confirm your identity", "limited time", "password expires",
    "unauthorized login", "unusual activity", "final notice", "restricted",
    "your account will be", "security alert",
]

SUSPICIOUS_TLDS = (".zip", ".mov", ".xyz", ".top", ".gq", ".tk", ".ml", ".cf", ".click", ".link", ".gdn")
FREEMAIL_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com"}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


class ScoreEngine:
    def __init__(self, analysis, attachment_findings=None):
        self.analysis = analysis
        self.attachment_findings = attachment_findings or []
        self.findings = []  # list of (severity, text, points)
        self.score = 0
        self._run()

    def _add(self, severity, text, points):
        self.findings.append((severity, text, points))
        self.score += points

    def _run(self):
        a = self.analysis

        if a.reply_to_domain and a.from_domain and a.reply_to_domain != a.from_domain:
            self._add("HIGH", f"Reply-To domain ({a.reply_to_domain}) differs from From domain ({a.from_domain})", 25)

        if a.return_path_domain and a.from_domain and a.return_path_domain != a.from_domain:
            self._add("MEDIUM", f"Return-Path domain ({a.return_path_domain}) differs from From domain ({a.from_domain})", 15)

        for mech, val in a.auth_results.items():
            if val in ("fail", "softfail"):
                self._add("HIGH", f"{mech.upper()} authentication result: {val}", 20)
            elif val == "none":
                self._add("LOW", f"{mech.upper()} not present or not checked", 5)

        body_lower = a.all_text.lower()
        hits = [w for w in URGENCY_WORDS if w in body_lower]
        if hits:
            pts = 8 * min(len(hits), 3)
            self._add("MEDIUM", f"Urgency/social-engineering language: {', '.join(hits[:5])}", pts)

        for dom in a.domains:
            if any(dom.endswith(t) for t in SUSPICIOUS_TLDS):
                self._add("MEDIUM", f"Link domain uses suspicious TLD: {dom}", 10)

        for u in a.urls:
            m = DOMAIN_FROM_URL_RE.match(u)
            if m and valid_ip(m.group(1).split(":")[0]):
                self._add("HIGH", f"URL uses a raw IP address instead of a domain: {u}", 20)

        if a.from_domain in FREEMAIL_DOMAINS and any(
            w in body_lower for w in ("invoice", "wire transfer", "payment", "bank details", "swift")
        ):
            self._add("MEDIUM", "Free-mail sender domain combined with financial/payment language", 10)

        for att_result in self.attachment_findings:
            sev = att_result.get("severity", "LOW")
            for f in att_result["findings"]:
                pts = {"HIGH": 20, "MEDIUM": 10, "LOW": 3}[sev]
                self._add(sev, f"[{att_result['filename']}] {f}", pts)

        self.score = min(self.score, 100)

    def sorted_findings(self):
        return sorted(self.findings, key=lambda x: SEVERITY_ORDER[x[0]])

    def verdict(self):
        if self.score >= 50:
            return "MALICIOUS / HIGH RISK", "#c0392b"
        elif self.score >= 20:
            return "SUSPICIOUS", "#e67e22"
        return "LIKELY BENIGN", "#27ae60"
