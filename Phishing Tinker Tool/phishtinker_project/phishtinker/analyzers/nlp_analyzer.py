"""Lightweight natural-language / entity heuristics for content analysis.

This is intentionally small and local: regex-based email/phone extraction and
credential-looking strings. Optionally can be extended to use spaCy or similar
if available.
"""
import re

EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PHONE_RE = re.compile(r"\+?\d[\d \-()]{6,}\d")

CREDENTIAL_KEYWORDS = ['password', 'passcode', 'pwd', 'username', 'user id', 'login']


def analyze_text_for_entities(text, max_items=50):
    text_low = text.lower()
    out = []
    emails = sorted(set(EMAIL_RE.findall(text)))[:max_items]
    phones = sorted(set(PHONE_RE.findall(text)))[:max_items]
    out.append(f"Email addresses detected: {len(emails)}")
    if emails:
        out.extend([f"  - {e}" for e in emails[:10]])
    out.append(f"Phone-like strings detected: {len(phones)}")
    if phones:
        out.extend([f"  - {p}" for p in phones[:10]])

    cred_hits = [kw for kw in CREDENTIAL_KEYWORDS if kw in text_low]
    out.append(f"Credential-related keywords present: {', '.join(cred_hits) if cred_hits else 'none'}")

    # Extract likely usernames / tokens: short alphanumeric strings that look like codes
    tokens = re.findall(r"\b[a-zA-Z0-9\-_]{6,}\b", text)
    tokens = [t for t in tokens if not EMAIL_RE.match(t)]
    tokens = sorted(set(tokens))[:20]
    out.append(f"Potential tokens/IDs found (sample): {', '.join(tokens[:10]) if tokens else 'none'}")

    return '\n'.join(out)
