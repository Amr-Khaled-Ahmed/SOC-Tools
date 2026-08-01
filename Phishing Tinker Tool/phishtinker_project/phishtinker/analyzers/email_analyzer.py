"""
Core .eml parsing: headers, auth results, received chain, attachments, body IOCs.
"""
import hashlib
from email import policy
from email.parser import BytesParser

from urllib.parse import urlparse

from ..utils.ioc import (
    extract_ips, extract_urls, extract_domains_from_urls,
    extract_domain_from_addr, valid_ip,
)

KEY_HEADERS = [
    "Date", "Subject", "From", "To", "Reply-To", "Return-Path",
    "Message-ID", "X-Originating-IP", "X-Sender-IP", "Authentication-Results",
    "X-Mailer", "Sender",
]

EXECUTABLE_EXT = (".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".jar",
                   ".hta", ".ps1", ".bat", ".cmd", ".wsf", ".msi", ".cpl")
MACRO_EXT = (".docm", ".xlsm", ".pptm", ".dotm", ".xltm")
ARCHIVE_EXT = (".zip", ".rar", ".7z", ".iso", ".img")


class Attachment:
    def __init__(self, filename, content_type, payload: bytes):
        self.filename = filename or "unnamed"
        self.content_type = content_type
        self.size = len(payload)
        self.payload = payload
        self.md5 = hashlib.md5(payload).hexdigest()
        self.sha1 = hashlib.sha1(payload).hexdigest()
        self.sha256 = hashlib.sha256(payload).hexdigest()

    @property
    def is_executable(self):
        return self.filename.lower().endswith(EXECUTABLE_EXT)

    @property
    def is_macro_office(self):
        return self.filename.lower().endswith(MACRO_EXT)

    @property
    def is_archive(self):
        return self.filename.lower().endswith(ARCHIVE_EXT)

    @property
    def is_html(self):
        return self.filename.lower().endswith((".html", ".htm"))

    @property
    def is_pdf(self):
        return self.filename.lower().endswith(".pdf") or self.content_type == "application/pdf"

    @property
    def is_office_ole(self):
        return self.filename.lower().endswith((".doc", ".xls", ".ppt", ".rtf"))


class EmailAnalysis:
    """Parses a single .eml file and exposes structured, analyzer-ready data."""

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            raw = f.read()
        self.msg = BytesParser(policy=policy.default).parsebytes(raw)

        self.headers = {k: self.msg.get(k) for k in KEY_HEADERS if self.msg.get(k)}
        self.raw_headers = "\n".join(f"{k}: {v}" for k, v in self.msg.items())
        self.received_chain = self.msg.get_all("Received", []) or []
        self.auth_results = self._parse_auth_results()

        self.from_domain = extract_domain_from_addr(self.msg.get("From", ""))
        self.reply_to_domain = extract_domain_from_addr(self.msg.get("Reply-To", ""))
        self.return_path_domain = extract_domain_from_addr(self.msg.get("Return-Path", ""))

        self.body_text = ""
        self.body_html = ""
        self.ips = set()
        self.urls = set()
        self.attachments = []
        # preserve individual text parts (content_type, text, index)
        self.parts = []

        self._walk_parts()
        self.domains = extract_domains_from_urls(self.urls)
        for rec in self.received_chain:
            self.ips.update(extract_ips(rec))

    def _parse_auth_results(self):
        import re
        auth = self.msg.get("Authentication-Results", "") or ""
        result = {}
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf'{mech}=(\w+)', auth, re.IGNORECASE)
            result[mech] = m.group(1).lower() if m else "none"
        return result

    def get_header_analysis(self):
        issues = []
        if self.reply_to_domain and self.from_domain and self.reply_to_domain != self.from_domain:
            issues.append({
                "severity": "HIGH",
                "title": "Reply-To domain mismatch",
                "detail": f"Reply-To domain {self.reply_to_domain} differs from From domain {self.from_domain}.",
            })
        if self.return_path_domain and self.from_domain and self.return_path_domain != self.from_domain:
            issues.append({
                "severity": "MEDIUM",
                "title": "Return-Path domain mismatch",
                "detail": f"Return-Path domain {self.return_path_domain} differs from From domain {self.from_domain}.",
            })
        for mech, val in self.auth_results.items():
            if val == "fail":
                issues.append({
                    "severity": "HIGH",
                    "title": f"{mech.upper()} authentication failed",
                    "detail": f"{mech.upper()} result is {val}.",
                })
            elif val == "softfail":
                issues.append({
                    "severity": "MEDIUM",
                    "title": f"{mech.upper()} authentication soft-fail",
                    "detail": f"{mech.upper()} result is {val}, which is a weaker rejection policy.",
                })
            elif val == "none":
                issues.append({
                    "severity": "LOW",
                    "title": f"{mech.upper()} not present",
                    "detail": f"{mech.upper()} was not seen in Authentication-Results.",
                })
        return issues

    def _walk_parts(self):
        for part in self.msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            ctype = part.get_content_type()
            disp = part.get("Content-Disposition", "") or ""
            filename = part.get_filename()

            is_attachment = "attachment" in disp or (
                filename and ctype not in ("text/plain", "text/html")
            )

            if is_attachment:
                payload = part.get_payload(decode=True) or b""
                self.attachments.append(Attachment(filename, ctype, payload))
                continue

            if ctype in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="ignore")
                # store per-part data to allow user selection
                idx = len(self.parts) + 1
                self.parts.append({"content_type": ctype, "text": text, "index": idx})
                if ctype == "text/plain":
                    self.body_text += text + "\n"
                else:
                    self.body_html += text + "\n"
                self.ips.update(extract_ips(text))
                self.urls.update(extract_urls(text))

    def _rebuild_body_cache(self):
        self.body_text = "\n".join(p["text"] for p in self.parts if p["content_type"] == "text/plain")
        self.body_html = "\n".join(p["text"] for p in self.parts if p["content_type"] == "text/html")

    def update_part(self, part_index: int, new_text: str):
        if not (0 <= part_index < len(self.parts)):
            raise IndexError("Mail part index out of range")
        self.parts[part_index]["text"] = new_text
        self._rebuild_body_cache()

    @property
    def all_text(self):
        return self.body_text + "\n" + self.body_html

    def get_summary(self):
        return {
            "subject": self.headers.get("Subject", ""),
            "from": self.headers.get("From", ""),
            "date": self.headers.get("Date", ""),
            "num_attachments": len(self.attachments),
            "num_urls": len(self.urls),
            "num_ips": len(self.ips),
        }

    def analyze_content(self):
        """Return a structured content analysis summary for the email."""
        all_text = self.all_text
        text_low = all_text.lower()
        from_dom = self.from_domain or ""

        summary = {
            "source": self.path,
            "total_characters": len(all_text),
            "url_count": len(self.urls),
            "ip_count": len(self.ips),
            "attachment_count": len(self.attachments),
            "plain_parts": sum(1 for p in self.parts if p["content_type"] == "text/plain"),
            "html_parts": sum(1 for p in self.parts if p["content_type"] == "text/html"),
            "sender_domain": from_dom,
            "reply_to_domain": self.reply_to_domain,
            "return_path_domain": self.return_path_domain,
            "heuristic_score": getattr(self, "heuristic_score", None),
        }

        phishing_types = []
        if any(w in text_low for w in ("verify your account", "sign in to", "confirm your identity", "login to", "password")):
            phishing_types.append("Credential harvesting / login scam")
        if any(w in text_low for w in ("invoice", "wire transfer", "payment", "bank account", "pay now", "bill due")):
            phishing_types.append("Business Email Compromise / financial fraud")
        if any(w in text_low for w in ("urgent", "immediately", "final notice", "act now", "suspended", "locked")):
            phishing_types.append("Urgent / social engineering")
        if any(w in text_low for w in ("security alert", "unauthorized", "unexpected login", "account locked", "verify your identity")):
            phishing_types.append("Security warning / account scam")

        form_flag = False
        for part in self.msg.walk():
            if part.get_content_type() == "text/html":
                payload = part.get_payload(decode=True) or b""
                html = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
                if "<form" in html.lower() or "<input" in html.lower():
                    form_flag = True
                    break
        if form_flag:
            phishing_types.append("HTML form / credential collection")

        attachment_flags = []
        for att in self.attachments:
            if att.is_executable:
                attachment_flags.append("executable")
            if att.is_macro_office:
                attachment_flags.append("macro-enabled office")
            if att.is_html:
                attachment_flags.append("html")
        if attachment_flags:
            phishing_types.append("Attachment-based risk detected")

        suspicious_links = []
        external_domains = set()
        for url in sorted(self.urls):
            try:
                parsed = urlparse(url)
                host = (parsed.hostname or "").lower()
            except Exception:
                host = ""
            if host:
                if valid_ip(host) and url not in suspicious_links:
                    suspicious_links.append(url)
                if "xn--" in host and url not in suspicious_links:
                    suspicious_links.append(url)
                if from_dom and host and from_dom not in host:
                    external_domains.add(host)
                if from_dom and host and host not in from_dom and from_dom not in host:
                    suspicious_links.append(url)
        if external_domains:
            phishing_types.append("Link target differs from sender domain")

        summary["suspicious_hosts"] = sorted(external_domains)
        summary["suspicious_links"] = suspicious_links

        keyword_matches = [
            w for w in ("urgent", "immediately", "verify your account", "suspended", "payment", "invoice", "password", "security alert")
            if w in text_low
        ]
        summary["keywords"] = sorted(set(keyword_matches))

        if not phishing_types:
            phishing_types.append("No strong phishing-type indicators detected")

        attachment_summary = []
        for att in self.attachments:
            flags = []
            if att.is_executable:
                flags.append("executable")
            if att.is_macro_office:
                flags.append("macro-enabled office")
            if att.is_html:
                flags.append("html")
            attachment_summary.append({
                "filename": att.filename,
                "content_type": att.content_type,
                "size": att.size,
                "flags": flags,
                "vt_summary": getattr(att, "vt_summary", None),
            })

        return {
            "summary": summary,
            "phishing_types": phishing_types,
            "keywords": summary["keywords"],
            "suspicious_hosts": sorted(external_domains),
            "suspicious_links": suspicious_links,
            "attachment_summary": attachment_summary,
            "has_html_form": form_flag,
            "url_count": len(self.urls),
            "ip_count": len(self.ips),
            "text_summary": {
                "plain_parts": summary["plain_parts"],
                "html_parts": summary["html_parts"],
            },
            "heuristic_score": summary["heuristic_score"],
        }
