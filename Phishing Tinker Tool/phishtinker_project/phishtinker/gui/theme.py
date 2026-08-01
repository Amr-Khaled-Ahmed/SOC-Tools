"""
Central theme: colors, fonts, spacing. Change here to re-skin the whole app.
"""

# Palette — soft, high-contrast, colorblind-considerate (not pure red/green only;
# we always pair color with an icon/word too)
BG = "#f5f6fa"
BG_CARD = "#ffffff"
BG_SIDEBAR = "#1e2430"

TEXT_PRIMARY = "#1e2430"
TEXT_SECONDARY = "#6b7280"
TEXT_ON_DARK = "#f5f6fa"

DANGER = "#e5484d"
DANGER_BG = "#fdecec"
WARNING = "#f5a524"
WARNING_BG = "#fef6e6"
SAFE = "#17a34a"
SAFE_BG = "#e9f9ef"
INFO = "#3b82f6"
INFO_BG = "#eaf2fe"

BORDER = "#e5e7eb"
ACCENT = "#4f46e5"

FONT_FAMILY = "Segoe UI"
FONT_TITLE = (FONT_FAMILY, 20, "bold")
FONT_SUBTITLE = (FONT_FAMILY, 11)
FONT_H2 = (FONT_FAMILY, 13, "bold")
FONT_BODY = (FONT_FAMILY, 10)
FONT_BODY_BOLD = (FONT_FAMILY, 10, "bold")
FONT_SMALL = (FONT_FAMILY, 9)
FONT_MONO = ("Consolas", 10)
FONT_BIG_NUMBER = (FONT_FAMILY, 30, "bold")

SEVERITY_COLORS = {
    "HIGH": (DANGER, DANGER_BG),
    "MEDIUM": (WARNING, WARNING_BG),
    "LOW": (INFO, INFO_BG),
}

SEVERITY_ICON = {
    "HIGH": "\u26D4",     # no entry
    "MEDIUM": "\u26A0",   # warning
    "LOW": "\u2139",      # info
}

VERDICT_STYLE = {
    "MALICIOUS / HIGH RISK": ("This looks like a PHISHING email", DANGER, DANGER_BG, "\U0001F6A8"),
    "SUSPICIOUS": ("This email looks suspicious", WARNING, WARNING_BG, "\u26A0"),
    "LIKELY BENIGN": ("This email looks safe", SAFE, SAFE_BG, "\u2705"),
}
