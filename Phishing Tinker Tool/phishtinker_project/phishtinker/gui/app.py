import hashlib
import os
import tempfile
import webbrowser
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog, scrolledtext

from ..analyzers import EmailAnalysis, analyze_attachment, ScoreEngine
from ..analyzers import url_analyzer, nlp_analyzer

try:
    from tkhtmlview import HTMLLabel
    HAVE_HTML_PREVIEW = True
except ImportError:
    HTMLLabel = None
    HAVE_HTML_PREVIEW = False
from ..utils.ioc import defang_ip, defang_url, defang_domain, valid_ip
from ..utils.reputation import ip_lookup, ip_lookup_info, country_code_to_flag, HAVE_REQUESTS, virustotal_hash_lookup

from ..report import build_text_report, build_json_report, build_markdown_report
from . import theme
from .widgets import ScrollableFrame, Card, RiskGauge, Pill, apply_global_styles
from .explain import explain, VERDICT_PLAIN

try:
    # Optional drag-and-drop support (works if tkinterdnd2 is installed)
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAVE_DND = True
except ImportError:
    HAVE_DND = False


class PhishTinkerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PhishTinker — SOC Analyst Console")
        self.root.geometry("1180x760")
        self.root.minsize(900, 600)

        self.style = apply_global_styles(root)

        self.analysis = None
        self.score_engine = None
        self.attachment_results = []

        self.defang_var = tk.BooleanVar(value=True)
        self.lookup_var = tk.BooleanVar(value=False)
        self.auto_analyze_var = tk.BooleanVar(value=True)
        self.beginner_mode = tk.BooleanVar(value=True)
        self.vt_api_key = None

        self._build_layout()
        self._show_empty_state()

    # ---------------- Layout scaffolding ----------------

    def _build_layout(self):
        root_frame = ttk.Frame(self.root)
        root_frame.pack(fill="both", expand=True)

        self._build_sidebar(root_frame)

        main = ttk.Frame(root_frame, padding=(20, 18))
        main.pack(side="left", fill="both", expand=True)
        self.main = main

        header = ttk.Frame(main)
        header.pack(fill="x")
        ttk.Label(header, text="PhishTinker SOC Analyst Console", style="Title.TLabel").pack(anchor="w")
        self.subtitle_var = tk.StringVar(value="Open a suspicious email to begin the investigation workflow.")
        ttk.Label(header, textvariable=self.subtitle_var, style="Subtitle.TLabel").pack(anchor="w", pady=(2, 12))

        self.banner_holder = ttk.Frame(main)
        self.banner_holder.pack(fill="x", pady=(0, 14))

        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill="both", expand=True)

        self.tab_overview = ScrollableFrame(self.notebook)
        self.tab_findings = ScrollableFrame(self.notebook)
        self.tab_attach = ScrollableFrame(self.notebook)
        self.tab_iocs = ScrollableFrame(self.notebook)
        self.tab_headers = ScrollableFrame(self.notebook)
        self.tab_mailview = ScrollableFrame(self.notebook)
        self.tab_content = ScrollableFrame(self.notebook)  # content analysis
        
        self.notebook.add(self.tab_overview, text="  Overview  ")
        self.notebook.add(self.tab_findings, text="  Why? (Findings)  ")
        self.notebook.add(self.tab_attach, text="  Attachments  ")
        self.notebook.add(self.tab_iocs, text="  Links & IPs  ")
        self.notebook.add(self.tab_headers, text="  Header Analysis  ")
        self.notebook.add(self.tab_mailview, text="  Mail View  ")
        self.notebook.add(self.tab_content, text="  Content Analysis  ")

        status = ttk.Frame(main)
        status.pack(fill="x", pady=(10, 0))
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(status, textvariable=self.status_var, style="Subtitle.TLabel").pack(side="left")

    def _build_sidebar(self, parent):
        sidebar = ttk.Frame(parent, style="Sidebar.TFrame", padding=18, width=260)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="\U0001F41F  PhishTinker", bg=theme.BG_SIDEBAR, fg="white",
                 font=(theme.FONT_FAMILY, 16, "bold")).pack(anchor="w", pady=(0, 4))
        tk.Label(sidebar, text="Automated phishing triage", bg=theme.BG_SIDEBAR, fg="#9aa3b2",
                 font=theme.FONT_SMALL).pack(anchor="w", pady=(0, 24))

        ttk.Button(sidebar, text="\U0001F4C2  Open Email (.eml)", style="Accent.TButton",
                   command=self.open_file).pack(fill="x", pady=(0, 6))

        drop_hint = "or drag & drop a .eml file here" if HAVE_DND else "(tip: install tkinterdnd2 to enable drag & drop)"
        tk.Label(sidebar, text=drop_hint, bg=theme.BG_SIDEBAR, fg="#9aa3b2", font=theme.FONT_SMALL,
                 wraplength=220, justify="left").pack(anchor="w", pady=(0, 20))

        self.drop_zone = tk.Frame(sidebar, bg="#2a3140", height=70, highlightbackground="#3d4759",
                                   highlightthickness=1)
        self.drop_zone.pack(fill="x", pady=(0, 20))
        tk.Label(self.drop_zone, text="Drop .eml file here", bg="#2a3140", fg="#9aa3b2",
                 font=theme.FONT_SMALL).pack(expand=True)
        if HAVE_DND:
            self.drop_zone.drop_target_register(DND_FILES)
            self.drop_zone.dnd_bind("<<Drop>>", self._on_drop)

        ttk.Separator(sidebar).pack(fill="x", pady=14)

        tk.Label(sidebar, text="DISPLAY MODE", bg=theme.BG_SIDEBAR, fg="#9aa3b2",
                 font=theme.FONT_SMALL).pack(anchor="w", pady=(0, 6))
        mode_frame = tk.Frame(sidebar, bg=theme.BG_SIDEBAR)
        mode_frame.pack(fill="x", pady=(0, 16))
        ttk.Radiobutton(mode_frame, text="Simple (beginner)", variable=self.beginner_mode, value=True,
                         command=self.refresh).pack(anchor="w")
        ttk.Radiobutton(mode_frame, text="Technical", variable=self.beginner_mode, value=False,
                         command=self.refresh).pack(anchor="w")

        tk.Label(sidebar, text="OPTIONS", bg=theme.BG_SIDEBAR, fg="#9aa3b2",
                 font=theme.FONT_SMALL).pack(anchor="w", pady=(4, 6))
        cb1 = tk.Checkbutton(sidebar, text="Hide/defang dangerous links", variable=self.defang_var,
                              command=self.refresh, bg=theme.BG_SIDEBAR, fg="white", selectcolor="#2a3140",
                              activebackground=theme.BG_SIDEBAR, activeforeground="white", font=theme.FONT_SMALL,
                              anchor="w")
        cb1.pack(fill="x", pady=2)

        cb2 = tk.Checkbutton(sidebar, text="Look up sender IP location online", variable=self.lookup_var,
                              command=self._maybe_lookup, bg=theme.BG_SIDEBAR, fg="white", selectcolor="#2a3140",
                              activebackground=theme.BG_SIDEBAR, activeforeground="white", font=theme.FONT_SMALL,
                              anchor="w")
        cb2.pack(fill="x", pady=2)
        if not HAVE_REQUESTS:
            cb2.configure(state="disabled")

        # Auto content analysis option and manual run
        ttk.Separator(sidebar).pack(fill="x", pady=(12,6))
        tk.Label(sidebar, text="CONTENT ANALYSIS", bg=theme.BG_SIDEBAR, fg="#9aa3b2",
                 font=theme.FONT_SMALL).pack(anchor="w", pady=(0, 6))
        tk.Checkbutton(sidebar, text="Auto analyze on open", variable=self.auto_analyze_var,
                       bg=theme.BG_SIDEBAR, fg="white", selectcolor="#2a3140", font=theme.FONT_SMALL, anchor="w").pack(fill="x", pady=2)
        ttk.Button(sidebar, text="Run Content Analysis", style="Secondary.TButton",
                   command=self.run_content_analysis).pack(fill="x", pady=6)

        ttk.Separator(sidebar).pack(fill="x", pady=14)

        tk.Label(sidebar, text="EXPORT REPORT", bg=theme.BG_SIDEBAR, fg="#9aa3b2",
                 font=theme.FONT_SMALL).pack(anchor="w", pady=(0, 6))
        ttk.Button(sidebar, text="Save as .txt", style="Secondary.TButton",
                   command=self.export_text).pack(fill="x", pady=2)
        ttk.Button(sidebar, text="Save as .md (markdown)", style="Secondary.TButton",
                   command=self.export_markdown).pack(fill="x", pady=2)
        ttk.Button(sidebar, text="Save as .json (for tools)", style="Secondary.TButton",
                   command=self.export_json).pack(fill="x", pady=2)
        ttk.Button(sidebar, text="Copy all IOCs", style="Secondary.TButton",
                   command=self.copy_all_iocs).pack(fill="x", pady=2)

        ttk.Separator(sidebar).pack(fill="x", pady=12)
        tk.Label(sidebar, text="VIRUSTOTAL (optional)", bg=theme.BG_SIDEBAR, fg="#9aa3b2",
                 font=theme.FONT_SMALL).pack(anchor="w", pady=(0, 6))
        ttk.Button(sidebar, text="Set VT API Key", style="Secondary.TButton", command=self.set_vt_api_key).pack(fill="x", pady=2)
        ttk.Button(sidebar, text="Scan attachments (VT)", style="Secondary.TButton", command=self.scan_attachments_vt).pack(fill="x", pady=2)

        ttk.Separator(sidebar).pack(fill="x", pady=14)
        tk.Label(sidebar, text="INVESTIGATION NOTES", bg=theme.BG_SIDEBAR, fg="#9aa3b2",
                 font=theme.FONT_SMALL).pack(anchor="w", pady=(0, 6))
        self.notes_box = scrolledtext.ScrolledText(sidebar, height=8, wrap="word", bg="#252f44",
                                                   fg="white", insertbackground="white", font=theme.FONT_SMALL,
                                                   relief="flat", borderwidth=0)
        self.notes_box.pack(fill="both", pady=(0, 8))
        self.notes_box.insert("1.0", "Investigator notes:\n")
        filler = tk.Frame(sidebar, bg=theme.BG_SIDEBAR)
        filler.pack(fill="both", expand=True)
        tk.Label(sidebar, text="100% local analysis.\nNothing is sent online unless\nyou enable IP lookup above.",
                 bg=theme.BG_SIDEBAR, fg="#6b7688", font=theme.FONT_SMALL, justify="left").pack(anchor="w")

    def _on_drop(self, event):
        path = event.data.strip("{}")
        if path.lower().endswith(".eml"):
            self._load(path)
        else:
            messagebox.showwarning("Unsupported file", "Please drop a .eml email file.")

    # ---------------- Empty state ----------------

    def _show_empty_state(self):
        card = Card(self.tab_overview.body, accent=theme.ACCENT)
        card.pack(fill="x", padx=4, pady=4)
        ttk.Label(card.inner, text="\U0001F440  No email loaded yet", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(card.inner, text="Click \u201cOpen Email (.eml)\u201d in the sidebar, or drag a file in, to "
                                    "scan it for phishing warning signs in plain English.",
                  style="Card.TLabel", wraplength=700, justify="left").pack(anchor="w", pady=(6, 0))

    # ---------------- File loading ----------------

    def open_file(self):
        path = filedialog.askopenfilename(filetypes=[("Email files", "*.eml"), ("All files", "*.*")])
        if not path:
            return
        self._load(path)

    def _load(self, path):
        self.status_var.set(f"Reading {os.path.basename(path)}...")
        self.root.update_idletasks()
        try:
            self.analysis = EmailAnalysis(path)
        except Exception as e:
            messagebox.showerror("Couldn't read this file", f"This doesn't look like a valid email file.\n\n{e}")
            self.status_var.set("Error parsing file.")
            return

        self.attachment_results = [analyze_attachment(att) for att in self.analysis.attachments]
        self.score_engine = ScoreEngine(self.analysis, self.attachment_results)
        self.subtitle_var.set(f"Scanned: {os.path.basename(path)}")
        self.status_var.set("Scan complete.")
        # Auto-run content analysis if enabled
        if self.auto_analyze_var.get():
            try:
                self.run_content_analysis()
            except Exception:
                pass
        # Auto-run IP geolocation lookup if requested
        if self.lookup_var.get():
            self._maybe_lookup()
        # Attach heuristic score back to analysis for content analyzer reference
        try:
            setattr(self.analysis, 'heuristic_score', getattr(self.score_engine, 'score', None))
        except Exception:
            pass
        self.refresh()

    # ---------------- Rendering ----------------

    def refresh(self):
        if not self.analysis:
            return
        self._render_banner()
        self._render_overview()
        self._render_findings()
        self._render_attachments()
        self._render_iocs()
        self._render_headers()
        self._render_mail_view()
        self._render_content()

    def _render_banner(self):
        for w in self.banner_holder.winfo_children():
            w.destroy()

        se = self.score_engine
        verdict, _ = se.verdict()
        headline, color, bg, icon = theme.VERDICT_STYLE[verdict]

        banner = tk.Frame(self.banner_holder, bg=bg, padx=18, pady=14)
        banner.pack(fill="x")

        left = tk.Frame(banner, bg=bg)
        left.pack(side="left", fill="both", expand=True)
        tk.Label(left, text=f"{icon}  {headline}", bg=bg, fg=color,
                 font=(theme.FONT_FAMILY, 15, "bold")).pack(anchor="w")

        plain, tip = VERDICT_PLAIN[verdict]
        tk.Label(left, text=plain, bg=bg, fg=theme.TEXT_PRIMARY, font=theme.FONT_BODY,
                 wraplength=680, justify="left").pack(anchor="w", pady=(4, 2))
        tk.Label(left, text=f"\u2192 {tip}", bg=bg, fg=theme.TEXT_PRIMARY, font=theme.FONT_BODY_BOLD,
                 wraplength=680, justify="left").pack(anchor="w")

        gauge = RiskGauge(banner, size=140, bg=bg)
        gauge.set_value(se.score, color, verdict.split("/")[0].strip().title())
        gauge.pack(side="right")

    def _render_overview(self):
        tab = self.tab_overview
        for w in tab.body.winfo_children():
            w.destroy()

        a, se = self.analysis, self.score_engine
        beginner = self.beginner_mode.get()

        facts_card = Card(tab.body)
        facts_card.pack(fill="x", padx=4, pady=(4, 10))
        grid = ttk.Frame(facts_card.inner, style="Card.TFrame")
        grid.pack(fill="x")

        facts = [
            ("From", a.headers.get("From", "Unknown")),
            ("Subject", a.headers.get("Subject", "(no subject)")),
            ("Date", a.headers.get("Date", "Unknown")),
            ("Links found", str(len(a.urls))),
            ("Attachments", str(len(a.attachments))),
        ]
        for i, (k, v) in enumerate(facts):
            ttk.Label(grid, text=k.upper(), style="CardSecondary.TLabel").grid(row=i, column=0, sticky="w", pady=3, padx=(0, 12))
            ttk.Label(grid, text=str(v), style="Card.TLabel", wraplength=650, justify="left").grid(row=i, column=1, sticky="w", pady=3)

        top_findings = se.sorted_findings()[:3]
        if top_findings:
            header_lbl = ttk.Label(tab.body, text="Top reasons for this result" if beginner else "Top-weighted findings",
                                    font=theme.FONT_H2)
            header_lbl.pack(anchor="w", padx=4, pady=(6, 6))

            for sev, text, pts in top_findings:
                color, bg = theme.SEVERITY_COLORS[sev]
                card = Card(tab.body, accent=color)
                card.pack(fill="x", padx=4, pady=4)
                info = explain(text) if beginner else {"title": text, "plain": "", "tip": ""}
                row = ttk.Frame(card.inner, style="Card.TFrame")
                row.pack(fill="x")
                Pill(row, theme.SEVERITY_ICON[sev] + " " + sev, color, bg).pack(side="left", anchor="n")
                textcol = ttk.Frame(row, style="Card.TFrame")
                textcol.pack(side="left", fill="x", expand=True, padx=(10, 0))
                ttk.Label(textcol, text=info["title"], style="CardTitle.TLabel", wraplength=680, justify="left").pack(anchor="w")
                if info.get("plain"):
                    ttk.Label(textcol, text=info["plain"], style="Card.TLabel", wraplength=680, justify="left").pack(anchor="w", pady=(3, 0))
                if beginner and info.get("tip"):
                    ttk.Label(textcol, text="\U0001F4A1 " + info["tip"], style="CardSecondary.TLabel",
                              wraplength=680, justify="left").pack(anchor="w", pady=(4, 0))
        else:
            card = Card(tab.body, accent=theme.SAFE)
            card.pack(fill="x", padx=4, pady=4)
            ttk.Label(card.inner, text="No warning signs detected", style="CardTitle.TLabel").pack(anchor="w")
            ttk.Label(card.inner, text="This scan didn't find any of the common phishing red flags. "
                                        "Still, stay alert with unexpected emails.",
                      style="Card.TLabel", wraplength=700, justify="left").pack(anchor="w", pady=(4, 0))

        if len(se.findings) > 3:
            ttk.Label(tab.body, text=f"+ {len(se.findings) - 3} more \u2014 see the \u201cWhy? (Findings)\u201d tab for the full list.",
                      style="Subtitle.TLabel").pack(anchor="w", padx=4, pady=(4, 10))

    def _render_findings(self):
        tab = self.tab_findings
        for w in tab.body.winfo_children():
            w.destroy()

        se = self.score_engine
        beginner = self.beginner_mode.get()

        if not se.findings:
            card = Card(tab.body, accent=theme.SAFE)
            card.pack(fill="x", padx=4, pady=4)
            ttk.Label(card.inner, text="Nothing suspicious found.", style="CardTitle.TLabel").pack(anchor="w")
            return

        for sev, text, pts in se.sorted_findings():
            color, bg = theme.SEVERITY_COLORS[sev]
            card = Card(tab.body, accent=color)
            card.pack(fill="x", padx=4, pady=4)
            row = ttk.Frame(card.inner, style="Card.TFrame")
            row.pack(fill="x")

            Pill(row, f"{theme.SEVERITY_ICON[sev]} {sev}  (+{pts})", color, bg).pack(side="left", anchor="n")
            textcol = ttk.Frame(row, style="Card.TFrame")
            textcol.pack(side="left", fill="x", expand=True, padx=(10, 0))

            if beginner:
                info = explain(text)
                ttk.Label(textcol, text=info["title"], style="CardTitle.TLabel", wraplength=780, justify="left").pack(anchor="w")
                ttk.Label(textcol, text=info["plain"], style="Card.TLabel", wraplength=780, justify="left").pack(anchor="w", pady=(3, 0))
                ttk.Label(textcol, text="\U0001F4A1 " + info["tip"], style="CardSecondary.TLabel",
                          wraplength=780, justify="left").pack(anchor="w", pady=(4, 0))
                ttk.Label(textcol, text="Technical detail: " + text, style="CardSecondary.TLabel",
                          wraplength=780, justify="left").pack(anchor="w", pady=(6, 0))
            else:
                ttk.Label(textcol, text=text, style="Card.TLabel", wraplength=780, justify="left").pack(anchor="w")

    def _render_attachments(self):
        tab = self.tab_attach
        for w in tab.body.winfo_children():
            w.destroy()

        a = self.analysis
        if not a.attachments:
            card = Card(tab.body)
            card.pack(fill="x", padx=4, pady=4)
            ttk.Label(card.inner, text="No attachments", style="CardTitle.TLabel").pack(anchor="w")
            ttk.Label(card.inner, text="This email has no files attached.", style="Card.TLabel").pack(anchor="w", pady=(4, 0))
            return

        for att, result in zip(a.attachments, self.attachment_results):
            sev = result["severity"]
            has_findings = bool(result["findings"])
            color, bg = theme.SEVERITY_COLORS.get(sev, (theme.SAFE, theme.SAFE_BG))
            card = Card(tab.body, accent=color if has_findings else theme.SAFE)
            card.pack(fill="x", padx=4, pady=4)

            top = ttk.Frame(card.inner, style="Card.TFrame")
            top.pack(fill="x")
            ttk.Label(top, text="\U0001F4CE " + att.filename, style="CardTitle.TLabel").pack(side="left")
            if has_findings:
                Pill(top, f"{theme.SEVERITY_ICON.get(sev,'')} {sev} risk", color, bg).pack(side="right")
            else:
                Pill(top, "\u2705 clean", theme.SAFE, theme.SAFE_BG).pack(side="right")

            ttk.Label(card.inner, text=f"{att.content_type}  \u2022  {att.size:,} bytes",
                      style="CardSecondary.TLabel").pack(anchor="w", pady=(2, 6))

            for f in result["findings"]:
                if self.beginner_mode.get():
                    info = explain(f)
                    ttk.Label(card.inner, text="\u2022 " + info["title"], style="Card.TLabel",
                              wraplength=760, justify="left").pack(anchor="w")
                    ttk.Label(card.inner, text="   " + info["plain"], style="CardSecondary.TLabel",
                              wraplength=760, justify="left").pack(anchor="w", pady=(0, 4))
                else:
                    ttk.Label(card.inner, text="\u2022 " + f, style="Card.TLabel",
                              wraplength=760, justify="left").pack(anchor="w")

            hash_row = ttk.Frame(card.inner, style="Card.TFrame")
            hash_row.pack(fill="x", pady=(6, 0))
            ttk.Label(hash_row, text=f"SHA256: {att.sha256}", style="CardSecondary.TLabel",
                      wraplength=760).pack(anchor="w")

            # VirusTotal quick summary if available
            vt = getattr(att, 'vt_summary', None)
            if vt:
                ttk.Label(card.inner, text=f"VirusTotal: {vt}", style="CardSecondary.TLabel",
                          wraplength=760, justify="left").pack(anchor="w", pady=(4, 0))

    def _render_iocs(self, lookup_cache=None):
        tab = self.tab_iocs
        for w in tab.body.winfo_children():
            w.destroy()

        a = self.analysis
        defang = self.defang_var.get()
        lookup_cache = lookup_cache or {}

        if a.urls:
            card = Card(tab.body, accent=theme.INFO)
            card.pack(fill="x", padx=4, pady=4)
            ttk.Label(card.inner, text=f"\U0001F517 Links found in this email ({len(a.urls)})",
                      style="CardTitle.TLabel").pack(anchor="w", pady=(0, 6))
            for u in sorted(a.urls):
                ttk.Label(card.inner, text=defang_url(u) if defang else u, style="Card.TLabel",
                          wraplength=760, justify="left").pack(anchor="w", pady=1)

        if a.ips:
            geo_card = Card(tab.body, accent=theme.INFO)
            geo_card.pack(fill="x", padx=4, pady=4)
            ttk.Label(geo_card.inner, text=f"\U0001F310 Server addresses (IPs) involved ({len(a.ips)})",
                      style="CardTitle.TLabel").pack(anchor="w", pady=(0, 6))
            geo_summary = []
            for ip in sorted(a.ips):
                disp = defang_ip(ip) if defang else ip
                extra = lookup_cache.get(ip)
                flag = ""
                country = None
                if isinstance(extra, dict):
                    country = extra.get("country")
                    flag = country_code_to_flag(country)
                location = None
                if isinstance(extra, dict) and extra.get("display"):
                    location = extra["display"]
                elif lookup_cache and extra is None and not HAVE_REQUESTS:
                    location = "IP lookup unavailable"
                text = disp
                if flag:
                    text += f"  {flag}"
                if location:
                    text += f"   — {location}"
                ttk.Label(geo_card.inner, text=text, style="Card.TLabel", wraplength=760, justify="left").pack(anchor="w", pady=1)
                if country:
                    geo_summary.append((country, flag, ip))

            if not lookup_cache and HAVE_REQUESTS:
                ttk.Label(geo_card.inner, text="Enable 'Look up sender IP location online' to display country flags and geolocation data for these IP addresses.", style="CardSecondary.TLabel", wraplength=760, justify="left").pack(anchor="w", pady=(6, 0))

            if geo_summary:
                summary_card = Card(tab.body, accent=theme.INFO)
                summary_card.pack(fill="x", padx=4, pady=4)
                ttk.Label(summary_card.inner, text="Geolocation flags and anomalies", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 6))
                seen_countries = set()
                for country, flag, ip in geo_summary:
                    if country in seen_countries:
                        continue
                    seen_countries.add(country)
                    ttk.Label(summary_card.inner, text=f"{flag} {country} — {len([i for i in geo_summary if i[0] == country])} IP(s)", style="Card.TLabel", wraplength=760, justify="left").pack(anchor="w", pady=1)

        if not a.urls and not a.ips:
            card = Card(tab.body)
            card.pack(fill="x", padx=4, pady=4)
            ttk.Label(card.inner, text="No links or IP addresses found in this email.", style="Card.TLabel").pack(anchor="w")

    def _render_headers(self):
        tab = self.tab_headers
        for w in tab.body.winfo_children():
            w.destroy()

        a = self.analysis
        card = Card(tab.body)
        card.pack(fill="x", padx=4, pady=4)
        ttk.Label(card.inner, text="Email headers", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 8))
        for k, v in a.headers.items():
            row = ttk.Frame(card.inner, style="Card.TFrame")
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=k, style="CardSecondary.TLabel", width=22, anchor="w").pack(side="left")
            ttk.Label(row, text=str(v), style="Card.TLabel", wraplength=600, justify="left").pack(side="left", fill="x", expand=True)

        header_issues = a.get_header_analysis()
        if header_issues:
            severity = "HIGH" if any(issue["severity"] == "HIGH" for issue in header_issues) else "MEDIUM"
            accent = theme.DANGER if severity == "HIGH" else theme.WARNING
            issue_card = Card(tab.body, accent=accent)
            issue_card.pack(fill="x", padx=4, pady=4)
            ttk.Label(issue_card.inner, text="Header analysis summary", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 8))
            for issue in header_issues:
                ttk.Label(issue_card.inner, text=f"• [{issue['severity']}] {issue['title']}", style="CardTitle.TLabel" if issue['severity'] == 'HIGH' else "CardTertiary.TLabel", wraplength=760, justify="left").pack(anchor="w", pady=(2, 0))
                ttk.Label(issue_card.inner, text=issue['detail'], style="CardSecondary.TLabel", wraplength=760, justify="left").pack(anchor="w", pady=(0, 4))
        else:
            safe_card = Card(tab.body, accent=theme.SAFE)
            safe_card.pack(fill="x", padx=4, pady=4)
            ttk.Label(safe_card.inner, text="Header analysis did not reveal obvious issues.", style="CardTitle.TLabel").pack(anchor="w")
            ttk.Label(safe_card.inner, text="Sender alignment and authentication look consistent based on the extracted headers.", style="Card.TLabel", wraplength=760, justify="left").pack(anchor="w", pady=(4, 0))

        auth_card = Card(tab.body, accent=theme.ACCENT)
        auth_card.pack(fill="x", padx=4, pady=4)
        ttk.Label(auth_card.inner, text="Authentication results", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 8))
        for mech, val in a.auth_results.items():
            color = theme.SAFE if val == "pass" else (theme.DANGER if val in ("fail", "softfail") else theme.TEXT_SECONDARY)
            row = ttk.Frame(auth_card.inner, style="Card.TFrame")
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=mech.upper(), style="CardSecondary.TLabel", width=10, anchor="w").pack(side="left")
            tk.Label(row, text=val, fg=color, bg=theme.BG_CARD, font=theme.FONT_BODY_BOLD).pack(side="left")

        if a.received_chain:
            chain_card = Card(tab.body)
            chain_card.pack(fill="x", padx=4, pady=4)
            ttk.Label(chain_card.inner, text="Delivery path (Received chain)", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 8))
            for i, rec in enumerate(a.received_chain):
                ttk.Label(chain_card.inner, text=f"[{i}] {rec.strip()}", style="CardSecondary.TLabel",
                          wraplength=760, justify="left").pack(anchor="w", pady=3)

        source_card = Card(tab.body)
        source_card.pack(fill="both", padx=4, pady=4, expand=True)
        ttk.Label(source_card.inner, text="Raw headers", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 8))
        raw_text = scrolledtext.ScrolledText(source_card.inner, wrap="none", height=14)
        raw_text.insert("1.0", getattr(a, 'raw_headers', ''))
        raw_text.configure(state="disabled", font=("Consolas", 10))
        raw_text.pack(fill="both", expand=True)

    def _render_mail_view(self):
        tab = getattr(self, 'tab_mailview', None)
        if tab is None:
            return
        for w in tab.body.winfo_children():
            w.destroy()
        a = self.analysis

        card = Card(tab.body)
        card.pack(fill="both", padx=4, pady=4, expand=True)
        ttk.Label(card.inner, text="Mail View", style="CardTitle.TLabel").pack(anchor="w")

        summary = [
            ("From", a.headers.get("From", "")),
            ("To", a.headers.get("To", "")),
            ("Subject", a.headers.get("Subject", "")),
            ("Date", a.headers.get("Date", "")),
        ]
        meta = ttk.Frame(card.inner, style="Card.TFrame")
        meta.pack(fill="x", pady=(6, 10))
        for label, value in summary:
            row = ttk.Frame(meta, style="Card.TFrame")
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=f"{label}: ", style="CardSecondary.TLabel", width=10).pack(side="left")
            ttk.Label(row, text=value, style="Card.TLabel", wraplength=660, justify="left").pack(side="left", fill="x", expand=True)

        parts = getattr(a, 'parts', [])
        options = [f"{p['index']}: {p['content_type']}" for p in parts]
        if a.attachments:
            for i, att in enumerate(a.attachments, start=1):
                if att.is_html:
                    options.append(f"A{i}: attachment HTML: {att.filename}")

        if not options:
            ttk.Label(card.inner, text="No textual parts or HTML attachments available to preview.", style="CardTertiary.TLabel").pack(anchor="w")
            return

        sel_var = tk.StringVar(value=options[0])
        cb = ttk.Combobox(card.inner, values=options, textvariable=sel_var, state="readonly")
        cb.pack(anchor="w", pady=(0, 8), fill="x")

        view_mode = tk.StringVar(value="source")
        mode_frame = ttk.Frame(card.inner)
        mode_frame.pack(anchor="w", pady=(0, 8))
        ttk.Radiobutton(mode_frame, text="Source", variable=view_mode, value="source").pack(side="left")
        ttk.Radiobutton(mode_frame, text="Preview", variable=view_mode, value="preview").pack(side="left", padx=6)
        ttk.Radiobutton(mode_frame, text="Edit", variable=view_mode, value="edit").pack(side="left", padx=6)

        note_label = ttk.Label(card.inner, text="", style="CardSecondary.TLabel", wraplength=760, justify="left")
        note_label.pack(anchor="w", pady=(0, 6))

        viewer_frame = ttk.Frame(card.inner)
        viewer_frame.pack(fill='both', expand=True)

        st = scrolledtext.ScrolledText(viewer_frame, wrap='none', height=24)
        st.pack(fill='both', expand=True)

        preview_widget = None
        if HAVE_HTML_PREVIEW:
            preview_widget = HTMLLabel(viewer_frame, html='', background=theme.BG_CARD)

        def current_content():
            choice = sel_var.get()
            if choice.startswith("A"):
                idx = int(choice[1:].split(":", 1)[0]) - 1
                att = a.attachments[idx]
                return att.payload.decode('utf-8', errors='ignore'), "text/html", True, att
            idx = int(choice.split(":", 1)[0]) - 1
            part = parts[idx]
            return part['text'], part['content_type'], False, part

        def open_in_browser():
            content, ctype, _, _ = current_content()
            if ctype != 'text/html':
                messagebox.showinfo('Open in browser', 'Browser preview is only available for HTML content.')
                return
            try:
                with tempfile.NamedTemporaryFile('w', suffix='.html', delete=False, encoding='utf-8') as tmp:
                    tmp.write(content)
                webbrowser.open(f'file://{tmp.name}')
            except Exception as e:
                messagebox.showerror('Browser preview error', str(e))

        def save_source():
            raw_text = st.get('1.0', 'end').rstrip('\n')
            path = filedialog.asksaveasfilename(defaultextension='.html', filetypes=[('HTML file', '*.html'), ('Text', '*.txt')])
            if not path:
                return
            try:
                with open(path, 'w', encoding='utf-8') as fh:
                    fh.write(raw_text)
                messagebox.showinfo('Saved', f'Source saved to:\n{path}')
            except Exception as e:
                messagebox.showerror('Save error', str(e))

        def apply_edits():
            if view_mode.get() != 'edit':
                messagebox.showinfo('Edit mode', 'Switch to Edit mode before applying changes.')
                return
            content, ctype, is_attachment, item = current_content()
            new_text = st.get('1.0', 'end').rstrip('\n')
            if is_attachment:
                try:
                    payload = new_text.encode('utf-8')
                    item.payload = payload
                    item.md5 = hashlib.md5(payload).hexdigest()
                    item.sha1 = hashlib.sha1(payload).hexdigest()
                    item.sha256 = hashlib.sha256(payload).hexdigest()
                    messagebox.showinfo('Edit applied', 'HTML attachment changes are saved locally in this session.')
                except Exception as e:
                    messagebox.showerror('Edit error', f'Failed to apply attachment edit: {e}')
                    return
            else:
                part_index = int(sel_var.get().split(":", 1)[0]) - 1
                try:
                    self.analysis.update_part(part_index, new_text)
                    messagebox.showinfo('Edit applied', 'Mail body changes are saved locally in this session.')
                except Exception as e:
                    messagebox.showerror('Edit error', str(e))
                    return
            self.status_var.set('Updated selected part locally; rerun content analysis if needed.')
            update_mail_view()

        def update_mail_view():
            content, ctype, is_attachment, _ = current_content()
            if view_mode.get() == 'preview' and ctype == 'text/html' and HAVE_HTML_PREVIEW:
                if st.winfo_ismapped():
                    st.pack_forget()
                preview_widget.set_html(content)
                preview_widget.pack(fill='both', expand=True)
                note_label.configure(text='Previewing rendered HTML; use Open in browser if inline rendering is unavailable.')
            else:
                if preview_widget and preview_widget.winfo_ismapped():
                    preview_widget.pack_forget()
                if not st.winfo_ismapped():
                    st.pack(fill='both', expand=True)
                st.configure(state='normal')
                st.delete('1.0', 'end')
                st.insert('1.0', content)
                if view_mode.get() == 'source':
                    st.configure(state='disabled')
                else:
                    st.configure(state='normal')
                if view_mode.get() == 'preview' and ctype == 'text/html' and not HAVE_HTML_PREVIEW:
                    note_label.configure(text='HTML preview is not available. Install tkhtmlview to enable inline rendering or use Open in browser.')
                elif view_mode.get() == 'edit':
                    note_label.configure(text='Edit the selected mail part and click Apply edits to keep changes locally.')
                else:
                    note_label.configure(text=f'Viewing source for {ctype}.')

        btn_frame = ttk.Frame(card.inner)
        btn_frame.pack(anchor="w", pady=(0, 8))
        ttk.Button(btn_frame, text="Load selected part", command=update_mail_view).pack(side="left")
        ttk.Button(btn_frame, text="Open in browser", command=open_in_browser).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Save current text", command=save_source).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Apply edits", command=apply_edits).pack(side="left", padx=6)

        cb.bind('<<ComboboxSelected>>', lambda e: update_mail_view())
        view_mode.trace_add('write', lambda *args: update_mail_view())
        update_mail_view()

    def _render_content(self):
        tab = getattr(self, 'tab_content', None)
        if tab is None:
            return
        for w in tab.body.winfo_children():
            w.destroy()
        content = getattr(self.analysis, 'content_analysis', None)
        if not content:
            card = Card(tab.body)
            card.pack(fill="x", padx=4, pady=4)
            ttk.Label(card.inner, text="Content analysis not run.", style="CardTitle.TLabel").pack(anchor="w")
            ttk.Label(card.inner, text="Click \"Run Content Analysis\" in the sidebar to run heuristics on the body.", style="Card.TLabel").pack(anchor="w")
            return

        if isinstance(content, dict):
            summary = content.get('summary', {})
            stat_card = Card(tab.body)
            stat_card.pack(fill="x", padx=4, pady=4)
            ttk.Label(stat_card.inner, text="Content analysis summary", style="CardTitle.TLabel").pack(anchor="w")
            stats = [
                ("Word/char length", summary.get('total_characters', 0)),
                ("Plain text parts", summary.get('plain_parts', 0)),
                ("HTML parts", summary.get('html_parts', 0)),
                ("URLs found", summary.get('url_count', 0)),
                ("IPs found", summary.get('ip_count', 0)),
                ("Attachments", summary.get('attachment_count', 0)),
                ("Heuristic score", summary.get('heuristic_score', 'N/A')),
            ]
            grid = ttk.Frame(stat_card.inner, style="Card.TFrame")
            grid.pack(fill="x", pady=(8, 0))
            for i, (label, value) in enumerate(stats):
                ttk.Label(grid, text=label + ":", style="CardSecondary.TLabel").grid(row=i, column=0, sticky="w", padx=(0, 12), pady=2)
                ttk.Label(grid, text=str(value), style="Card.TLabel").grid(row=i, column=1, sticky="w", pady=2)

            if content.get('phishing_types'):
                card = Card(tab.body, accent=theme.DANGER if any('No strong' not in t for t in content['phishing_types']) else theme.SAFE)
                card.pack(fill="x", padx=4, pady=4)
                ttk.Label(card.inner, text="Detected phishing characteristics", style="CardTitle.TLabel").pack(anchor="w")
                for item in content['phishing_types']:
                    ttk.Label(card.inner, text=f"• {item}", style="Card.TLabel", wraplength=760, justify="left").pack(anchor="w", pady=1)

            if content.get('keywords'):
                card = Card(tab.body)
                card.pack(fill="x", padx=4, pady=4)
                ttk.Label(card.inner, text="Suspicious keywords found", style="CardTitle.TLabel").pack(anchor="w")
                ttk.Label(card.inner, text=", ".join(content['keywords']), style="Card.TLabel", wraplength=760, justify="left").pack(anchor="w", pady=(4, 0))

            if content.get('suspicious_hosts'):
                card = Card(tab.body, accent=theme.WARNING)
                card.pack(fill="x", padx=4, pady=4)
                ttk.Label(card.inner, text="Domains that differ from sender domain", style="CardTitle.TLabel").pack(anchor="w")
                for host in content['suspicious_hosts'][:10]:
                    ttk.Label(card.inner, text=f"• {host}", style="CardSecondary.TLabel", wraplength=760, justify="left").pack(anchor="w", pady=1)

            if content.get('attachment_summary'):
                card = Card(tab.body)
                card.pack(fill="x", padx=4, pady=4)
                ttk.Label(card.inner, text="Attachments review", style="CardTitle.TLabel").pack(anchor="w")
                for att in content['attachment_summary']:
                    flags = ", ".join(att['flags']) if att['flags'] else "none"
                    summary_text = f"• {att['filename']} ({att['content_type']}, {att['size']} bytes) — {flags}"
                    ttk.Label(card.inner, text=summary_text, style="CardSecondary.TLabel", wraplength=760, justify="left").pack(anchor="w", pady=1)
                    if att.get('vt_summary'):
                        ttk.Label(card.inner, text=f"   VT: {att['vt_summary']}", style="CardSecondary.TLabel", wraplength=760, justify="left").pack(anchor="w", pady=(0, 2))

            if content.get('url_analysis'):
                ua = content['url_analysis']
                card = Card(tab.body)
                card.pack(fill="x", padx=4, pady=4)
                ttk.Label(card.inner, text="URL analysis", style="CardTitle.TLabel").pack(anchor="w")
                details = [
                    ("Total URLs", ua.get('total')),
                    ("IP-based URLs", len(ua.get('ip_urls', []))),
                    ("Punycode URLs", len(ua.get('punycode', []))),
                    ("Suspicious TLDs", len(ua.get('suspicious_tld', []))),
                ]
                for k, v in details:
                    ttk.Label(card.inner, text=f"• {k}: {v}", style="CardSecondary.TLabel", wraplength=760, justify="left").pack(anchor="w", pady=1)

            if content.get('nlp_analysis'):
                card = Card(tab.body)
                card.pack(fill="x", padx=4, pady=4)
                ttk.Label(card.inner, text="Entity / keyword extraction", style="CardTitle.TLabel").pack(anchor="w")
                text_widget = scrolledtext.ScrolledText(card.inner, wrap="word", height=10)
                text_widget.insert("1.0", content['nlp_analysis'])
                text_widget.configure(state="disabled", font=("Consolas", 10))
                text_widget.pack(fill="both", expand=True, pady=(8, 0))
            return

        card = Card(tab.body)
        card.pack(fill="both", padx=4, pady=4)
        st = scrolledtext.ScrolledText(card.inner, wrap="word", height=20)
        st.insert("1.0", content)
        st.configure(state="disabled", font=("Consolas", 10))
        st.pack(fill="both", expand=True)

    # ---------------- Actions ----------------

    def _maybe_lookup(self):
        if not self.lookup_var.get() or not self.analysis:
            return
        self.status_var.set("Looking up IP locations online...")

        def worker():
            cache = {}
            for ip in self.analysis.ips:
                info = ip_lookup_info(ip)
                if info:
                    cache[ip] = {
                        "display": ip_lookup(ip),
                        "country": info.get("country"),
                        "org": info.get("org"),
                        "city": info.get("city"),
                        "region": info.get("region"),
                    }
                else:
                    cache[ip] = None
            self.root.after(0, lambda: self._on_lookup_done(cache))

        threading.Thread(target=worker, daemon=True).start()

    def _on_lookup_done(self, cache):
        self._render_iocs(lookup_cache=cache)
        self.status_var.set("IP location lookup complete.")

    def copy_all_iocs(self):
        if not self.analysis:
            messagebox.showinfo("No email loaded", "Open an .eml file first.")
            return
        items = []
        items.extend(sorted(self.analysis.urls))
        items.extend(sorted(self.analysis.ips))
        items.extend(sorted(self.analysis.domains))
        if not items:
            messagebox.showinfo("No IOCs", "No URLs, IPs, or domains were found to copy.")
            return
        if self.defang_var.get():
            normalized = []
            for item in items:
                if item.startswith("http"):
                    normalized.append(defang_url(item))
                elif valid_ip(item):
                    normalized.append(defang_ip(item))
                else:
                    normalized.append(defang_domain(item))
            items = normalized
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(items))
        self.status_var.set("All IOCs copied to clipboard.")
        messagebox.showinfo("Copied", f"Copied {len(items)} IOCs to the clipboard.")

    def set_vt_api_key(self):
        key = simpledialog.askstring("VirusTotal API Key", "Enter VirusTotal API v3 key (x-apikey):", show='*')
        if key:
            self.vt_api_key = key
            messagebox.showinfo("VT API", "VirusTotal API key set for this session.")

    def scan_attachments_vt(self):
        if not self.analysis:
            messagebox.showinfo("No email loaded", "Open an .eml file first.")
            return
        if not HAVE_REQUESTS:
            messagebox.showerror("Missing dependency", "requests library not available for VT lookups.")
            return
        api_key = self.vt_api_key or simpledialog.askstring("VirusTotal API Key", "Enter VirusTotal API v3 key (x-apikey):", show='*')
        if not api_key:
            return
        self.status_var.set("Querying VirusTotal for attachments...")

        def worker():
            failures = []
            for att in self.analysis.attachments:
                res = virustotal_hash_lookup(att.sha256, api_key)
                if res:
                    setattr(att, 'vt_summary', res)
                else:
                    failures.append(att.filename)
            self.root.after(0, lambda: self._on_vt_done(failures))

        threading.Thread(target=worker, daemon=True).start()

    def _on_vt_done(self, failures):
        self.refresh()
        if failures:
            self.status_var.set(f"VT: some lookups failed ({len(failures)})")
            messagebox.showwarning("VT lookups completed", f"Some VT lookups failed: {', '.join(failures[:10])}")
        else:
            self.status_var.set("VT lookups completed")
            messagebox.showinfo("VT lookups completed", "All attachments looked up on VirusTotal.")

    def run_content_analysis(self):
        if not self.analysis:
            messagebox.showinfo("No email loaded", "Open an .eml file first.")
            return
        try:
            analysis_result = self.analysis.analyze_content()
            try:
                url_summary = url_analyzer.analyze_urls(self.analysis.urls, follow_redirects=False)
                analysis_result["url_analysis"] = url_summary
            except Exception:
                analysis_result["url_analysis"] = None

            try:
                nlp = nlp_analyzer.analyze_text_for_entities(self.analysis.all_text)
                analysis_result["nlp_analysis"] = nlp
            except Exception:
                analysis_result["nlp_analysis"] = "NLP analysis unavailable."

            setattr(self.analysis, 'content_analysis', analysis_result)
            self._render_content()
            self.status_var.set("Content analysis complete.")
            messagebox.showinfo("Content analysis", "Content analysis complete and available in the 'Content Analysis' tab.")
        except Exception as e:
            messagebox.showerror("Analysis error", str(e))
            self.status_var.set("Content analysis failed.")

    def export_text(self):
        if not self.analysis:
            messagebox.showinfo("No email loaded", "Open an .eml file first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text file", "*.txt")])
        if not path:
            return
        report = build_text_report(self.analysis, self.score_engine, defang=self.defang_var.get())
        with open(path, "w", encoding="utf-8") as f:
            f.write(report)
        messagebox.showinfo("Saved", f"Report saved to:\n{path}")

    def export_markdown(self):
        if not self.analysis:
            messagebox.showinfo("No email loaded", "Open an .eml file first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".md", filetypes=[("Markdown file", "*.md")])
        if not path:
            return
        report = build_markdown_report(self.analysis, self.score_engine, defang=self.defang_var.get())
        with open(path, "w", encoding="utf-8") as f:
            f.write(report)
        messagebox.showinfo("Saved", f"Markdown report saved to:\n{path}")

    def export_json(self):
        if not self.analysis:
            messagebox.showinfo("No email loaded", "Open an .eml file first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON file", "*.json")])
        if not path:
            return
        report = build_json_report(self.analysis, self.score_engine)
        with open(path, "w", encoding="utf-8") as f:
            f.write(report)
        messagebox.showinfo("Saved", f"Report saved to:\n{path}")


def run():
    if HAVE_DND:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    PhishTinkerApp(root)
    root.mainloop()
