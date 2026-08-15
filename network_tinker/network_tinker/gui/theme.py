BG_DARK = "#1b1e23"
BG_PANEL = "#22262d"
BG_SIDEBAR = "#171a1f"
FG_MAIN = "#e6e6e6"
FG_DIM = "#9aa0a6"
ACCENT = "#4fd1c5"
ACCENT_DARK = "#2b8a80"
RISK_HIGH = "#ff5c5c"
RISK_MED = "#ffb74d"
RISK_LOW = "#8bc34a"
FONT = ("JetBrains Mono", 10)
FONT_BOLD = ("JetBrains Mono", 11, "bold")
FONT_TITLE = ("JetBrains Mono", 15, "bold")
FONT_SMALL = ("JetBrains Mono", 8)


def apply_ttk_style(style):
    style.theme_use("clam")
    style.configure("Treeview", background=BG_PANEL, fieldbackground=BG_PANEL,
                     foreground=FG_MAIN, rowheight=24, font=FONT, borderwidth=0)
    style.configure("Treeview.Heading", background=BG_SIDEBAR, foreground=ACCENT,
                     font=FONT_BOLD, borderwidth=0)
    style.map("Treeview", background=[("selected", ACCENT_DARK)])
    style.configure("TProgressbar", troughcolor=BG_PANEL, background=ACCENT)
    style.configure("TNotebook", background=BG_DARK, borderwidth=0)
    style.configure("TNotebook.Tab", background=BG_SIDEBAR, foreground=FG_MAIN,
                     font=FONT, padding=(12, 6))
    style.map("TNotebook.Tab", background=[("selected", BG_PANEL)],
              foreground=[("selected", ACCENT)])
