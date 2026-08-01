"""
Attachment content inspection — goes beyond hashing.

- OLE/Office (.doc, .xls, .docm, .xlsm, ...): detect VBA macro streams, and
  flag common malicious macro API calls (Shell, AutoOpen, CreateObject, etc.)
  using oletools if available, else a raw-bytes heuristic fallback.
- PDF: detect JavaScript, /Launch, /OpenAction, /EmbeddedFile, /AA (auto-action)
  keywords using pikepdf/pypdf if available, else a raw-bytes heuristic fallback.
- Archives: just flag as "requires extraction, not auto-opened".

Design note: we deliberately never execute or open attachments — purely static
byte/stream inspection.
"""
import io
import re

# Optional stronger backends
try:
    from oletools.olevba import VBA_Parser
    HAVE_OLETOOLS = True
except ImportError:
    HAVE_OLETOOLS = False

try:
    import pypdf
    HAVE_PYPDF = True
except ImportError:
    HAVE_PYPDF = False


SUSPICIOUS_MACRO_KEYWORDS = [
    "Shell", "WScript.Shell", "CreateObject", "AutoOpen", "AutoExec",
    "Document_Open", "Auto_Open", "URLDownloadToFile", "PowerShell",
    "cmd.exe", "regsvr32", "mshta", "Chr(", "Base64",
]

PDF_SUSPICIOUS_MARKERS = [
    b"/JavaScript", b"/JS", b"/Launch", b"/OpenAction",
    b"/EmbeddedFile", b"/AA", b"/RichMedia", b"/SubmitForm",
]


def analyze_office_ole(attachment) -> dict:
    """Inspect .doc/.docm/.xls/.xlsm/.ppt/.pptm payloads for macros."""
    findings = []
    has_macros = False

    if HAVE_OLETOOLS:
        try:
            vba = VBA_Parser(attachment.filename, data=attachment.payload)
            has_macros = vba.detect_vba_macros()
            if has_macros:
                for (_, _, vba_filename, code) in vba.extract_macros():
                    for kw in SUSPICIOUS_MACRO_KEYWORDS:
                        if kw.lower() in code.lower():
                            findings.append(f"Macro '{vba_filename}' calls suspicious API: {kw}")
            vba.close()
        except Exception as e:
            findings.append(f"oletools parse error: {e}")
    else:
        # Fallback: raw substring search (less accurate, no false-negative-proof)
        raw = attachment.payload
        has_macros = b"VBA" in raw or b"Macros" in raw
        text = raw.decode("latin-1", errors="ignore")
        for kw in SUSPICIOUS_MACRO_KEYWORDS:
            if kw in text:
                findings.append(f"Suspicious string present in binary: {kw} (install 'oletools' for accurate macro extraction)")

    return {"has_macros": has_macros, "findings": findings}


def analyze_pdf(attachment) -> dict:
    findings = []
    marker_hits = []

    raw = attachment.payload
    for marker in PDF_SUSPICIOUS_MARKERS:
        if marker in raw:
            marker_hits.append(marker.decode())

    if marker_hits:
        findings.append(f"PDF contains suspicious markers: {', '.join(marker_hits)}")

    if HAVE_PYPDF:
        try:
            reader = pypdf.PdfReader(io.BytesIO(raw))
            if reader.is_encrypted:
                findings.append("PDF is encrypted/password-protected (common phishing evasion tactic)")
            if "/OpenAction" in (reader.trailer.get("/Root", {}) or {}):
                findings.append("PDF has an /OpenAction (auto-executes on open)")
        except Exception as e:
            findings.append(f"pypdf parse note: {e}")

    return {"marker_hits": marker_hits, "findings": findings}


def analyze_attachment(attachment) -> dict:
    """Dispatch to the right content analyzer based on file type. Returns dict of findings."""
    result = {"filename": attachment.filename, "findings": [], "severity": "LOW"}

    if attachment.is_executable:
        result["findings"].append("Executable/script file type — never run; extremely high risk in email context")
        result["severity"] = "HIGH"

    elif attachment.is_office_ole or attachment.is_macro_office:
        ole_result = analyze_office_ole(attachment)
        if ole_result["has_macros"]:
            result["findings"].append("Contains VBA macros")
            result["severity"] = "HIGH" if ole_result["findings"] else "MEDIUM"
        result["findings"].extend(ole_result["findings"])

    elif attachment.is_pdf:
        pdf_result = analyze_pdf(attachment)
        result["findings"].extend(pdf_result["findings"])
        if pdf_result["marker_hits"]:
            result["severity"] = "MEDIUM"

    elif attachment.is_html:
        result["findings"].append("HTML attachment — commonly used for local credential-harvesting forms")
        result["severity"] = "MEDIUM"

    elif attachment.is_archive:
        result["findings"].append("Archive file — contents not auto-extracted; inspect manually before opening")
        result["severity"] = "LOW"

    return result
