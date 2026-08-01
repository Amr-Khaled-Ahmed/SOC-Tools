"""
Translates technical findings into plain, beginner-friendly language.
Every finding produced by the scoring engine starts with a recognizable phrase
(see analyzers/scoring.py) — we pattern-match on that to give a simple,
non-jargon explanation + a concrete "what to do" tip.

This module is deliberately conservative: if nothing matches, we fall back to
showing the original technical text so nothing is ever hidden.
"""

RULES = [
    ("Reply-To domain", {
        "title": "The reply address doesn't match the sender",
        "plain": "The email claims to be from one company, but if you hit \u201cReply\u201d, "
                 "your response would secretly go to a completely different address. "
                 "This is one of the most common phishing tricks.",
        "tip": "Do not reply. Check the sender's real address by hovering over or tapping the name.",
    }),
    ("Return-Path domain", {
        "title": "Hidden delivery address looks unrelated",
        "plain": "The technical \u201creturn address\u201d used to actually send this email doesn't "
                 "match who it claims to be from.",
        "tip": "Treat this email with caution, especially if it's asking you to click or pay.",
    }),
    ("SPF authentication result", {
        "title": "This email failed a sender-verification check (SPF)",
        "plain": "Mail servers checked whether this email was really allowed to be sent from "
                 "that domain \u2014 and it failed. Legitimate companies almost always pass this.",
        "tip": "Be very cautious. This is a strong signal of a spoofed sender.",
    }),
    ("DMARC authentication result", {
        "title": "This email failed a domain-authenticity check (DMARC)",
        "plain": "This is another automated check that verifies an email is genuinely from the "
                 "domain it claims. It failed here.",
        "tip": "Strong red flag \u2014 avoid clicking links or downloading attachments.",
    }),
    ("DKIM not present", {
        "title": "No digital signature found (DKIM)",
        "plain": "Most legitimate businesses digitally sign their emails. This one has no such "
                 "signature, which makes it easier to fake.",
        "tip": "Not proof of phishing by itself, but combine with other warnings above.",
    }),
    ("Urgency/social-engineering language", {
        "title": "Uses pressure tactics and urgent language",
        "plain": "Phrases like \u201cact now\u201d, \u201caccount suspended\u201d, or \u201cverify immediately\u201d "
                 "are classic tactics used to make you panic and click without thinking.",
        "tip": "Slow down. Real companies rarely threaten immediate account loss over email.",
    }),
    ("suspicious TLD", {
        "title": "Link uses an unusual web address ending",
        "plain": "A link in this email points to a domain ending that's rarely used by legitimate "
                 "businesses and is popular with scammers because it's cheap to register.",
        "tip": "Don't click the link. Type the company's known website address directly instead.",
    }),
    ("raw IP address instead of a domain", {
        "title": "Link uses a raw number instead of a website name",
        "plain": "Instead of a normal address like \u201cbank.com\u201d, this link points straight to a "
                 "server number (an IP address). Real companies essentially never do this.",
        "tip": "Do not click this link under any circumstances.",
    }),
    ("Free-mail sender domain combined with financial", {
        "title": "Personal email account requesting money/payment info",
        "plain": "This message comes from a free personal email service (like Gmail) but talks "
                 "about invoices, payments, or bank details \u2014 unusual for a real business.",
        "tip": "Verify by phone or a separate known channel before sending any money or details.",
    }),
    ("Executable/script file", {
        "title": "Attachment is a program, not a document",
        "plain": "This attachment can run code on your computer the moment it's opened \u2014 like "
                 "installing a virus. Documents (Word, PDF, images) never need to \u201crun\u201d.",
        "tip": "Never open this attachment. Delete the email.",
    }),
    ("Contains VBA macros", {
        "title": "Document contains hidden automated commands (macros)",
        "plain": "This Office file has \u201cmacros\u201d \u2014 small programs that can run automatically "
                 "and silently install malware if you click \u201cEnable Content\u201d.",
        "tip": "Do not enable macros/content when opening. When in doubt, don't open it at all.",
    }),
    ("HTML attachment", {
        "title": "Attachment is a fake login page",
        "plain": "HTML attachments are often used to build a convincing fake login page that "
                 "steals your password when opened locally in your browser.",
        "tip": "Don't open this file or enter any password into it.",
    }),
    ("PDF contains suspicious markers", {
        "title": "PDF has hidden active content",
        "plain": "This PDF contains code or auto-actions that can run automatically, launch links, "
                 "or even open programs when the file is viewed.",
        "tip": "Open with caution using an updated PDF reader, or avoid opening entirely.",
    }),
    ("PDF is encrypted", {
        "title": "PDF is password-protected",
        "plain": "Attackers sometimes encrypt malicious PDFs so security scanners can't inspect "
                 "them before you open them.",
        "tip": "Be suspicious of an unexpected password-protected PDF, especially with a password given in the same email.",
    }),
    ("Archive file", {
        "title": "Attachment is a compressed folder (zip/rar)",
        "plain": "Archives can hide malicious files inside so they slip past email scanners.",
        "tip": "Only extract and open if you were expecting this file from someone you trust.",
    }),
]


def explain(finding_text: str):
    """Return a dict with title/plain/tip for a technical finding string, best-effort."""
    for keyword, info in RULES:
        if keyword.lower() in finding_text.lower():
            return info
    return {
        "title": "Technical finding",
        "plain": finding_text,
        "tip": "Review this detail carefully or ask a security-savvy colleague if unsure.",
    }


VERDICT_PLAIN = {
    "MALICIOUS / HIGH RISK": (
        "Multiple strong warning signs were found. This email is very likely a phishing "
        "or scam attempt.",
        "Do not click any links, do not open attachments, do not reply. "
        "Report it to your IT/security team and delete it."
    ),
    "SUSPICIOUS": (
        "Some warning signs were found, but not enough to be certain. This could still be "
        "a legitimate email with unusual formatting.",
        "Proceed carefully: verify the sender through another channel before clicking, "
        "replying, or opening attachments."
    ),
    "LIKELY BENIGN": (
        "No major warning signs were detected in this scan.",
        "Still use normal caution \u2014 no automated tool catches everything."
    ),
}
