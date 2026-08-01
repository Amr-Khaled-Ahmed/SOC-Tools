import tkinter as tk
from tkinter import ttk

from . import theme


class ScrollableFrame(ttk.Frame):
    """A vertically scrollable frame — used so card layouts can grow beyond the window."""

    def __init__(self, parent, bg=theme.BG, **kwargs):
        super().__init__(parent, **kwargs)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0)
        self.vbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.body = ttk.Frame(self.canvas)

        self.body.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.window = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.canvas.bind("<Configure>", self._on_canvas_resize)
        self.canvas.configure(yscrollcommand=self.vbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.vbar.pack(side="right", fill="y")

        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", lambda e: self.canvas.yview_scroll(-1, "units"))
        self.canvas.bind_all("<Button-5>", lambda e: self.canvas.yview_scroll(1, "units"))

    def _on_canvas_resize(self, event):
        self.canvas.itemconfig(self.window, width=event.width)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")


class Card(ttk.Frame):
    """A white rounded-look card with an optional colored left accent bar."""

    def __init__(self, parent, accent=None, bg=theme.BG_CARD, padding=14, **kwargs):
        outer = kwargs.pop("outer_pad", (0, 0, 0, 10))
        super().__init__(parent, style="Card.TFrame")
        self.configure(padding=padding)
        self.pack_propagate(True)
        if accent:
            bar = tk.Frame(self, bg=accent, width=4)
            bar.pack(side="left", fill="y")
        self.inner = ttk.Frame(self, style="Card.TFrame")
        self.inner.pack(side="left", fill="both", expand=True, padx=(10 if accent else 0, 0))


class RiskGauge(tk.Canvas):
    """A simple semicircular risk gauge (0-100) drawn on a canvas — no external deps."""

    def __init__(self, parent, size=180, **kwargs):
        kwargs.setdefault("bg", theme.BG_CARD)
        super().__init__(parent, width=size, height=size // 2 + 30, highlightthickness=0, **kwargs)
        self.size = size
        self.set_value(0, theme.TEXT_SECONDARY, "--")

    def set_value(self, score, color, label):
        self.delete("all")
        size = self.size
        cx, cy, r = size // 2, size // 2, size // 2 - 12

        # background arc (track)
        self.create_arc(cx - r, cy - r, cx + r, cy + r, start=180, extent=180,
                         style="arc", outline=theme.BORDER, width=14)

        # value arc
        extent = 180 * (score / 100.0)
        if extent > 0:
            self.create_arc(cx - r, cy - r, cx + r, cy + r, start=180, extent=extent,
                             style="arc", outline=color, width=14)

        self.create_text(cx, cy - 6, text=str(score), font=theme.FONT_BIG_NUMBER, fill=theme.TEXT_PRIMARY)
        self.create_text(cx, cy + 22, text=label, font=theme.FONT_SMALL, fill=theme.TEXT_SECONDARY)
        self.create_text(cx, cy + 40, text="risk score / 100", font=theme.FONT_SMALL, fill=theme.TEXT_SECONDARY)


class Pill(tk.Label):
    """A small colored rounded-look badge label, e.g. severity tags."""

    def __init__(self, parent, text, fg, bg, **kwargs):
        super().__init__(parent, text=f"  {text}  ", fg=fg, bg=bg, font=theme.FONT_SMALL, padx=4, pady=2, **kwargs)


def apply_global_styles(root):
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=theme.BG)

    style.configure("TFrame", background=theme.BG)
    style.configure("Card.TFrame", background=theme.BG_CARD)
    style.configure("Sidebar.TFrame", background=theme.BG_SIDEBAR)

    style.configure("TLabel", background=theme.BG, foreground=theme.TEXT_PRIMARY, font=theme.FONT_BODY)
    style.configure("Card.TLabel", background=theme.BG_CARD, foreground=theme.TEXT_PRIMARY, font=theme.FONT_BODY)
    style.configure("CardSecondary.TLabel", background=theme.BG_CARD, foreground=theme.TEXT_SECONDARY, font=theme.FONT_SMALL)
    style.configure("CardTertiary.TLabel", background=theme.BG_CARD, foreground=theme.TEXT_SECONDARY, font=theme.FONT_SMALL)
    style.configure("CardTitle.TLabel", background=theme.BG_CARD, foreground=theme.TEXT_PRIMARY, font=theme.FONT_H2)
    style.configure("Sidebar.TLabel", background=theme.BG_SIDEBAR, foreground=theme.TEXT_ON_DARK, font=theme.FONT_BODY)
    style.configure("Title.TLabel", background=theme.BG, foreground=theme.TEXT_PRIMARY, font=theme.FONT_TITLE)
    style.configure("Subtitle.TLabel", background=theme.BG, foreground=theme.TEXT_SECONDARY, font=theme.FONT_SUBTITLE)

    style.configure("Accent.TButton", font=theme.FONT_BODY_BOLD, padding=(14, 8))
    style.map("Accent.TButton",
              background=[("!disabled", theme.ACCENT), ("active", "#4338ca")],
              foreground=[("!disabled", "white")])

    style.configure("Secondary.TButton", font=theme.FONT_BODY, padding=(10, 6))

    style.configure("TNotebook", background=theme.BG, borderwidth=0)
    style.configure("TNotebook.Tab", font=theme.FONT_BODY_BOLD, padding=(16, 10))
    style.map("TNotebook.Tab", background=[("selected", theme.BG_CARD)], foreground=[("selected", theme.ACCENT)])

    style.configure("TCheckbutton", background=theme.BG, font=theme.FONT_BODY)
    style.configure("Card.TCheckbutton", background=theme.BG_CARD, font=theme.FONT_BODY)

    style.configure("Treeview", font=theme.FONT_BODY, rowheight=28, background=theme.BG_CARD,
                     fieldbackground=theme.BG_CARD, borderwidth=0)
    style.configure("Treeview.Heading", font=theme.FONT_BODY_BOLD)
    style.map("Treeview", background=[("selected", theme.INFO_BG)], foreground=[("selected", theme.TEXT_PRIMARY)])

    return style
