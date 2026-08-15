"""Network Tinker GUI -- dark sidebar app in the same style as PhishTinker.

Views: Dashboard, Packets, Top Talkers, DNS Explorer, Follow Stream,
       Carved Files, IOC Hunter, Snort Rule Lab, Search (grep), Export.
"""

import os
import re
import json
import datetime
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

from . import theme as th

try:
    from ..core.analysis import PcapAnalysis, defang
    from ..core.filters import apply_filter, to_tcpdump_equivalent
    from ..core import snort as snortlib
    from ..core import exporter
    SCAPY_OK = True
    SCAPY_ERR = None
except Exception as e:
    SCAPY_OK = False
    SCAPY_ERR = str(e)


class NetworkTinkerApp(tk.Tk):
    def __init__(self, initial_pcap=None):
        super().__init__()
        self.title("Network Tinker — PCAP Triage Tool")
        self.geometry("1360x840")
        self.configure(bg=th.BG_DARK)
        self.minsize(1100, 680)

        self.analysis = None
        style = ttk.Style(self)
        th.apply_ttk_style(style)
        self._build_layout()

        if not SCAPY_OK:
            self.after(300, lambda: messagebox.showerror(
                "scapy not found",
                f"scapy failed to import:\n{SCAPY_ERR}\n\n"
                "Install it with:\n  pip install scapy --break-system-packages"))
        elif initial_pcap:
            self.after(200, lambda: self._begin_load(initial_pcap))

    # ------------------------------------------------------------ layout
    def _build_layout(self):
        self.sidebar = tk.Frame(self, bg=th.BG_SIDEBAR, width=220)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        tk.Label(self.sidebar, text="🛰  Network\n    Tinker", bg=th.BG_SIDEBAR, fg=th.ACCENT,
                 font=th.FONT_TITLE, justify="left").pack(pady=(24, 10), padx=16, anchor="w")

        self.file_label = tk.Label(self.sidebar, text="No PCAP loaded", bg=th.BG_SIDEBAR,
                                    fg=th.FG_DIM, font=th.FONT, wraplength=195, justify="left")
        self.file_label.pack(padx=16, anchor="w", pady=(0, 14))

        tk.Button(self.sidebar, text="📂 Open PCAP", command=self.open_pcap,
                  bg=th.ACCENT, fg="#0d0f12", font=th.FONT_BOLD, relief="flat",
                  activebackground=th.ACCENT_DARK, cursor="hand2").pack(fill="x", padx=16, pady=(0, 6))
        tk.Button(self.sidebar, text="💾 Save session", command=self.save_session,
                  bg=th.BG_PANEL, fg=th.FG_MAIN, font=th.FONT, relief="flat",
                  activebackground=th.BG_PANEL, cursor="hand2").pack(fill="x", padx=16, pady=(0, 4))
        tk.Button(self.sidebar, text="📥 Load session", command=self.load_session,
                  bg=th.BG_PANEL, fg=th.FG_MAIN, font=th.FONT, relief="flat",
                  activebackground=th.BG_PANEL, cursor="hand2").pack(fill="x", padx=16, pady=(0, 18))

        self.nav_buttons = {}
        nav_items = [
            ("dashboard", "📊  Dashboard"),
            ("packets", "📦  Packets"),
            ("talkers", "🗣  Top Talkers"),
            ("dns", "🌐  DNS Explorer"),
            ("streams", "🔗  Follow Stream"),
            ("files", "🗃  Carved Files"),
            ("iocs", "🚩  IOC Hunter"),
            ("snort", "🛡  Snort Rule Lab"),
            ("search", "🔍  Search / Grep"),
            ("export", "📝  Export Report"),
        ]
        for key, label in nav_items:
            b = tk.Button(self.sidebar, text=label, command=lambda k=key: self.show_view(k),
                          bg=th.BG_SIDEBAR, fg=th.FG_MAIN, font=th.FONT, relief="flat", anchor="w",
                          activebackground=th.BG_PANEL, activeforeground=th.ACCENT, cursor="hand2",
                          padx=16)
            b.pack(fill="x", pady=1)
            self.nav_buttons[key] = b

        self.progress = ttk.Progressbar(self.sidebar, mode="determinate")
        self.progress.pack(side="bottom", fill="x", padx=16, pady=(0, 6))
        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(self.sidebar, textvariable=self.status_var, bg=th.BG_SIDEBAR, fg=th.FG_DIM,
                 font=th.FONT_SMALL, wraplength=195, justify="left").pack(
            side="bottom", padx=16, pady=(0, 10), anchor="w")

        self.content = tk.Frame(self, bg=th.BG_DARK)
        self.content.pack(side="left", fill="both", expand=True)

        self.views = {}
        self.views["dashboard"] = self._build_dashboard()
        self.views["packets"] = self._build_packets_view()
        self.views["talkers"] = self._build_talkers_view()
        self.views["dns"] = self._build_dns_view()
        self.views["streams"] = self._build_streams_view()
        self.views["files"] = self._build_files_view()
        self.views["iocs"] = self._build_iocs_view()
        self.views["snort"] = self._build_snort_view()
        self.views["search"] = self._build_search_view()
        self.views["export"] = self._build_export_view()

        self.show_view("dashboard")

    def show_view(self, key):
        for v in self.views.values():
            v.pack_forget()
        self.views[key].pack(fill="both", expand=True)
        for k, b in self.nav_buttons.items():
            b.configure(bg=th.BG_PANEL if k == key else th.BG_SIDEBAR,
                        fg=th.ACCENT if k == key else th.FG_MAIN)

    def _section_title(self, parent, text, subtitle=None):
        tk.Label(parent, text=text, bg=th.BG_DARK, fg=th.FG_MAIN, font=th.FONT_TITLE).pack(
            anchor="w", padx=24, pady=(20, 4 if subtitle else 10))
        if subtitle:
            tk.Label(parent, text=subtitle, bg=th.BG_DARK, fg=th.FG_DIM, font=th.FONT,
                     wraplength=900, justify="left").pack(anchor="w", padx=24, pady=(0, 10))

    # ------------------------------------------------------------ Dashboard
    def _build_dashboard(self):
        frame = tk.Frame(self.content, bg=th.BG_DARK)
        self._section_title(frame, "Dashboard")

        self.dash_stats = tk.Frame(frame, bg=th.BG_DARK)
        self.dash_stats.pack(fill="x", padx=24)
        self.stat_labels = {}
        for key in ["Total packets", "Duration", "TCP streams", "Files carved",
                    "IOCs found", "High-risk IOCs"]:
            card = tk.Frame(self.dash_stats, bg=th.BG_PANEL, padx=14, pady=12)
            card.pack(side="left", padx=(0, 10), fill="both", expand=True)
            val = tk.Label(card, text="—", bg=th.BG_PANEL, fg=th.ACCENT, font=("JetBrains Mono", 17, "bold"))
            val.pack(anchor="w")
            tk.Label(card, text=key, bg=th.BG_PANEL, fg=th.FG_DIM, font=th.FONT_SMALL).pack(anchor="w")
            self.stat_labels[key] = val

        tk.Label(frame, text="Protocol breakdown", bg=th.BG_DARK, fg=th.FG_MAIN, font=th.FONT_BOLD).pack(
            anchor="w", padx=24, pady=(20, 6))
        self.proto_canvas = tk.Frame(frame, bg=th.BG_DARK)
        self.proto_canvas.pack(fill="x", padx=24)

        tk.Label(frame, text="Auto-triage summary", bg=th.BG_DARK, fg=th.FG_MAIN, font=th.FONT_BOLD).pack(
            anchor="w", padx=24, pady=(20, 6))
        self.summary_box = scrolledtext.ScrolledText(frame, bg=th.BG_PANEL, fg=th.FG_MAIN, font=th.FONT,
                                                       relief="flat", height=12, insertbackground=th.FG_MAIN)
        self.summary_box.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        self.summary_box.configure(state="disabled")
        return frame

    # ------------------------------------------------------------ Packets
    def _build_packets_view(self):
        frame = tk.Frame(self.content, bg=th.BG_DARK)
        self._section_title(frame, "Packets")

        filter_row = tk.Frame(frame, bg=th.BG_DARK)
        filter_row.pack(fill="x", padx=24, pady=(0, 4))
        tk.Label(filter_row, text="Filter:", bg=th.BG_DARK, fg=th.FG_DIM, font=th.FONT).pack(side="left")
        self.filter_var = tk.StringVar()
        entry = tk.Entry(filter_row, textvariable=self.filter_var, bg=th.BG_PANEL, fg=th.FG_MAIN,
                          insertbackground=th.FG_MAIN, font=th.FONT, relief="flat")
        entry.pack(side="left", fill="x", expand=True, padx=8, ipady=4)
        entry.bind("<Return>", lambda e: self.refresh_packet_view())
        tk.Button(filter_row, text="Apply", command=self.refresh_packet_view, bg=th.ACCENT,
                  fg="#0d0f12", font=th.FONT_BOLD, relief="flat", cursor="hand2").pack(side="left", padx=4)
        tk.Button(filter_row, text="Clear", command=self._clear_filter, bg=th.BG_PANEL,
                  fg=th.FG_MAIN, font=th.FONT, relief="flat", cursor="hand2").pack(side="left")
        tk.Button(filter_row, text="Export CSV", command=self._export_filtered_csv, bg=th.BG_PANEL,
                  fg=th.FG_MAIN, font=th.FONT, relief="flat", cursor="hand2").pack(side="left", padx=4)

        self.tcpdump_equiv_var = tk.StringVar(value="")
        tk.Label(frame, textvariable=self.tcpdump_equiv_var, bg=th.BG_DARK, fg=th.FG_DIM,
                 font=th.FONT_SMALL, anchor="w").pack(anchor="w", padx=24)
        tk.Label(frame, text='e.g.  host 10.10.1.5 and port 443   |   tcp and not port 22   |   http',
                 bg=th.BG_DARK, fg=th.FG_DIM, font=th.FONT_SMALL).pack(anchor="w", padx=24, pady=(0, 6))

        cols = ("no", "time", "src", "dst", "proto", "len", "info")
        self.pkt_tree = ttk.Treeview(frame, columns=cols, show="headings", height=20)
        headers = {"no": "#", "time": "Time", "src": "Source", "dst": "Destination",
                   "proto": "Proto", "len": "Len", "info": "Info"}
        widths = {"no": 50, "time": 90, "src": 150, "dst": 150, "proto": 70, "len": 60, "info": 420}
        for c in cols:
            self.pkt_tree.heading(c, text=headers[c])
            self.pkt_tree.column(c, width=widths[c], anchor="w")
        self.pkt_tree.pack(fill="both", expand=True, padx=24, pady=(0, 6))
        self.pkt_tree.bind("<<TreeviewSelect>>", self._on_packet_select)

        self.pkt_detail = scrolledtext.ScrolledText(frame, bg=th.BG_PANEL, fg=th.FG_MAIN, font=th.FONT,
                                                      relief="flat", height=7, insertbackground=th.FG_MAIN)
        self.pkt_detail.pack(fill="x", padx=24, pady=(0, 16))
        self.pkt_detail.configure(state="disabled")
        return frame

    def _clear_filter(self):
        self.filter_var.set("")
        self.refresh_packet_view()

    def refresh_packet_view(self):
        if not self.analysis:
            return
        self.pkt_tree.delete(*self.pkt_tree.get_children())
        expr = self.filter_var.get()
        filtered = apply_filter(self.analysis.packets, expr)
        self.tcpdump_equiv_var.set("CLI equivalent: " + to_tcpdump_equivalent(expr))
        for rec in filtered[:5000]:
            t = datetime.datetime.fromtimestamp(rec.time).strftime("%H:%M:%S.%f")[:-3]
            self.pkt_tree.insert("", "end", iid=str(rec.no),
                                 values=(rec.no, t, rec.src, rec.dst, rec.proto, rec.length, rec.info))
        self.status_var.set(f"Showing {len(filtered)} / {self.analysis.total} packets")
        self._last_filtered = filtered

    def _on_packet_select(self, event):
        sel = self.pkt_tree.selection()
        if not sel or not self.analysis:
            return
        no = int(sel[0])
        rec = self.analysis.packets[no - 1]
        self.pkt_detail.configure(state="normal")
        self.pkt_detail.delete("1.0", "end")
        detail = (f"Packet #{rec.no}  |  stream #{rec.stream_id}\n"
                  f"Time: {datetime.datetime.fromtimestamp(rec.time)}\n"
                  f"{rec.src}:{rec.sport} -> {rec.dst}:{rec.dport}   proto={rec.proto} len={rec.length} flags={rec.flags}\n\n")
        if rec.raw_payload:
            try:
                text = rec.raw_payload.decode(errors="replace")
            except Exception:
                text = repr(rec.raw_payload)
            detail += "Payload (decoded):\n" + text[:3000]
        self.pkt_detail.insert("1.0", detail)
        self.pkt_detail.configure(state="disabled")

    def _export_filtered_csv(self):
        if not self.analysis:
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                             initialfile="packets_filtered.csv")
        if not path:
            return
        rows = getattr(self, "_last_filtered", self.analysis.packets)
        exporter.export_packets_csv(self.analysis, path, packets=rows)
        messagebox.showinfo("Exported", f"Saved {len(rows)} packets to:\n{path}")

    # ------------------------------------------------------------ Talkers
    def _build_talkers_view(self):
        frame = tk.Frame(self.content, bg=th.BG_DARK)
        self._section_title(frame, "Top Talkers",
                             "Conversations sorted by packet count — one IP dominating "
                             "the list is a classic beaconing / C2 indicator.")
        cols = ("src", "dst", "packets", "bytes")
        self.talk_tree = ttk.Treeview(frame, columns=cols, show="headings", height=25)
        for c, w in zip(cols, (200, 200, 100, 120)):
            self.talk_tree.heading(c, text=c.capitalize())
            self.talk_tree.column(c, width=w, anchor="w")
        self.talk_tree.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        self.talk_tree.bind("<Double-1>", self._talker_to_filter)
        return frame

    def _talker_to_filter(self, event):
        sel = self.talk_tree.selection()
        if not sel:
            return
        vals = self.talk_tree.item(sel[0], "values")
        self.filter_var.set(f"host {vals[0]} and host {vals[1]}")
        self.show_view("packets")
        self.refresh_packet_view()

    def refresh_talkers_view(self):
        self.talk_tree.delete(*self.talk_tree.get_children())
        for (src, dst), count in self.analysis.top_talkers(200):
            b = self.analysis.talker_bytes[(src, dst)]
            self.talk_tree.insert("", "end", values=(src, dst, count, f"{b:,}"))

    # ------------------------------------------------------------ DNS
    def _build_dns_view(self):
        frame = tk.Frame(self.content, bg=th.BG_DARK)
        self._section_title(frame, "DNS Explorer",
                             "Every DNS query, sorted by frequency. A domain queried far more "
                             "than any other is a strong beaconing signal.")
        cols = ("domain", "count")
        self.dns_tree = ttk.Treeview(frame, columns=cols, show="headings", height=25)
        self.dns_tree.heading("domain", text="Domain")
        self.dns_tree.heading("count", text="Query count")
        self.dns_tree.column("domain", width=500, anchor="w")
        self.dns_tree.column("count", width=120, anchor="w")
        self.dns_tree.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        return frame

    def refresh_dns_view(self):
        self.dns_tree.delete(*self.dns_tree.get_children())
        for domain, count in self.analysis.dns_stats():
            self.dns_tree.insert("", "end", values=(domain, count))

    # ------------------------------------------------------------ Follow Stream
    def _build_streams_view(self):
        frame = tk.Frame(self.content, bg=th.BG_DARK)
        self._section_title(frame, "Follow Stream",
                             "Reconstructed TCP conversations, client (>>>) vs server (<<<) — "
                             "same idea as Wireshark's Follow TCP Stream.")
        body = tk.Frame(frame, bg=th.BG_DARK)
        body.pack(fill="both", expand=True, padx=24, pady=(0, 20))

        left = tk.Frame(body, bg=th.BG_DARK)
        left.pack(side="left", fill="y")
        cols = ("id", "client", "server", "bytes")
        self.stream_tree = ttk.Treeview(left, columns=cols, show="headings", height=28)
        widths = {"id": 40, "client": 160, "server": 160, "bytes": 80}
        for c in cols:
            self.stream_tree.heading(c, text=c.capitalize())
            self.stream_tree.column(c, width=widths[c], anchor="w")
        self.stream_tree.pack(fill="y")
        self.stream_tree.bind("<<TreeviewSelect>>", self._on_stream_select)

        right = tk.Frame(body, bg=th.BG_DARK)
        right.pack(side="left", fill="both", expand=True, padx=(12, 0))
        self.stream_text = scrolledtext.ScrolledText(right, bg=th.BG_PANEL, fg=th.FG_MAIN, font=th.FONT,
                                                       relief="flat", insertbackground=th.FG_MAIN)
        self.stream_text.pack(fill="both", expand=True)
        self.stream_text.tag_configure("client", foreground=th.ACCENT)
        self.stream_text.tag_configure("server", foreground=th.RISK_MED)
        self.stream_text.configure(state="disabled")
        return frame

    def refresh_streams_view(self):
        self.stream_tree.delete(*self.stream_tree.get_children())
        for s in self.analysis.stream_summary():
            self.stream_tree.insert("", "end", iid=str(s["id"]),
                                    values=(s["id"], s["client"], s["server"], s["bytes"]))

    def _on_stream_select(self, event):
        sel = self.stream_tree.selection()
        if not sel or not self.analysis:
            return
        sid = int(sel[0])
        stream = self.analysis.streams[sid]
        self.stream_text.configure(state="normal")
        self.stream_text.delete("1.0", "end")
        for direction, t, data in stream.segments:
            tag = "client" if direction == "C" else "server"
            arrow = ">>>" if direction == "C" else "<<<"
            try:
                text = data.decode(errors="replace")
            except Exception:
                text = repr(data)
            self.stream_text.insert("end", f"{arrow} ", tag)
            self.stream_text.insert("end", text + "\n\n")
        self.stream_text.configure(state="disabled")

    # ------------------------------------------------------------ Carved Files
    def _build_files_view(self):
        frame = tk.Frame(self.content, bg=th.BG_DARK)
        self._section_title(frame, "Carved Files",
                             "Files detected inside reconstructed streams (via Content-Disposition "
                             "header or magic-byte signature), with SHA256 for quick VirusTotal lookup.")
        cols = ("name", "signature", "sha256", "size", "stream")
        self.file_tree = ttk.Treeview(frame, columns=cols, show="headings", height=20)
        widths = {"name": 220, "signature": 160, "sha256": 340, "size": 90, "stream": 70}
        for c in cols:
            self.file_tree.heading(c, text=c.capitalize())
            self.file_tree.column(c, width=widths[c], anchor="w")
        self.file_tree.pack(fill="both", expand=True, padx=24, pady=(0, 8))
        tk.Button(frame, text="💾 Save selected file to disk", command=self._save_carved_file,
                  bg=th.ACCENT, fg="#0d0f12", font=th.FONT_BOLD, relief="flat",
                  cursor="hand2").pack(anchor="w", padx=24, pady=(0, 20))
        return frame

    def refresh_files_view(self):
        self.file_tree.delete(*self.file_tree.get_children())
        for i, f in enumerate(self.analysis.carved_files):
            self.file_tree.insert("", "end", iid=str(i),
                                  values=(f["name"], f["signature"], f["sha256"], f["size"], f["stream_id"]))

    def _save_carved_file(self):
        sel = self.file_tree.selection()
        if not sel or not self.analysis:
            messagebox.showinfo("No selection", "Select a carved file first.")
            return
        idx = int(sel[0])
        out_dir = filedialog.askdirectory(title="Choose output folder")
        if not out_dir:
            return
        path = self.analysis.export_carved_file(idx, out_dir)
        messagebox.showinfo("Saved", f"File written to:\n{path}")

    # ------------------------------------------------------------ IOC Hunter
    def _build_iocs_view(self):
        frame = tk.Frame(self.content, bg=th.BG_DARK)
        self._section_title(frame, "IOC Hunter",
                             "Automated scan for credentials, suspicious User-Agents, dropped files, "
                             "C2-style domains, insecure protocols, and scan patterns.")
        cols = ("risk", "kind", "detail", "count", "packet")
        self.ioc_tree = ttk.Treeview(frame, columns=cols, show="headings", height=24)
        widths = {"risk": 70, "kind": 260, "detail": 420, "count": 60, "packet": 70}
        for c in cols:
            self.ioc_tree.heading(c, text=c.capitalize())
            self.ioc_tree.column(c, width=widths[c], anchor="w")
        self.ioc_tree.tag_configure("high", foreground=th.RISK_HIGH)
        self.ioc_tree.tag_configure("med", foreground=th.RISK_MED)
        self.ioc_tree.tag_configure("low", foreground=th.RISK_LOW)
        self.ioc_tree.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        return frame

    def refresh_iocs_view(self):
        self.ioc_tree.delete(*self.ioc_tree.get_children())
        risk_order = {"high": 0, "med": 1, "low": 2}
        for ioc in sorted(self.analysis.iocs, key=lambda x: risk_order.get(x["risk"], 3)):
            self.ioc_tree.insert("", "end", tags=(ioc["risk"],),
                                 values=(ioc["risk"].upper(), ioc["kind"],
                                        str(ioc["detail"])[:130], ioc.get("count", 1), ioc["packet_no"]))

    # ------------------------------------------------------------ Snort Rule Lab
    def _build_snort_view(self):
        frame = tk.Frame(self.content, bg=th.BG_DARK)
        self._section_title(frame, "Snort Rule Lab",
                             "Build a Snort rule manually, or one-click generate the classic "
                             "SOC101 patterns (LFI, brute force, key exfil, outbound FTP).")

        quick = tk.Frame(frame, bg=th.BG_DARK)
        quick.pack(fill="x", padx=24, pady=(0, 12))
        for label, fn in [
            ("LFI (../ in URI)", lambda: snortlib.rule_lfi_detection()),
            ("Brute force (10x 401 / 30s)", lambda: snortlib.rule_bruteforce_401()),
            ("Successful login (302)", lambda: snortlib.rule_successful_login_302()),
            ("SSH key exfil", lambda: snortlib.rule_ssh_key_exfil()),
            ("Outbound FTP", lambda: snortlib.rule_outbound_ftp()),
        ]:
            tk.Button(quick, text=label, command=lambda f=fn: self._insert_snort_rule(f()),
                      bg=th.BG_PANEL, fg=th.FG_MAIN, font=th.FONT_SMALL, relief="flat",
                      cursor="hand2", padx=8, pady=4).pack(side="left", padx=(0, 6))

        form = tk.Frame(frame, bg=th.BG_DARK)
        form.pack(fill="x", padx=24, pady=(0, 10))
        self.snort_fields = {}
        field_defs = [("action", "alert"), ("protocol", "tcp"), ("src_ip", "any"),
                      ("src_port", "any"), ("dst_ip", "any"), ("dst_port", "any"),
                      ("msg", "Custom detection"), ("content", "")]
        for i, (name, default) in enumerate(field_defs):
            col = i % 4
            row = i // 4
            cell = tk.Frame(form, bg=th.BG_DARK)
            cell.grid(row=row, column=col, sticky="ew", padx=4, pady=4)
            tk.Label(cell, text=name, bg=th.BG_DARK, fg=th.FG_DIM, font=th.FONT_SMALL).pack(anchor="w")
            var = tk.StringVar(value=default)
            tk.Entry(cell, textvariable=var, bg=th.BG_PANEL, fg=th.FG_MAIN,
                     insertbackground=th.FG_MAIN, font=th.FONT, relief="flat", width=16).pack(fill="x")
            self.snort_fields[name] = var
        for c in range(4):
            form.grid_columnconfigure(c, weight=1)

        tk.Button(frame, text="Generate rule", command=self._generate_manual_rule,
                  bg=th.ACCENT, fg="#0d0f12", font=th.FONT_BOLD, relief="flat",
                  cursor="hand2", padx=10, pady=6).pack(anchor="w", padx=24, pady=(0, 10))

        self.snort_output = scrolledtext.ScrolledText(frame, bg=th.BG_PANEL, fg=th.ACCENT, font=th.FONT,
                                                        relief="flat", height=14, insertbackground=th.FG_MAIN)
        self.snort_output.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        return frame

    def _insert_snort_rule(self, rule_text):
        self.snort_output.insert("end", rule_text + "\n")
        self.snort_output.see("end")

    def _generate_manual_rule(self):
        f = {k: v.get() for k, v in self.snort_fields.items()}
        rule = snortlib.build_rule(action=f["action"], protocol=f["protocol"],
                                    src_ip=f["src_ip"], src_port=f["src_port"],
                                    dst_ip=f["dst_ip"], dst_port=f["dst_port"],
                                    msg=f["msg"], content=f["content"] or None)
        self._insert_snort_rule(rule)

    # ------------------------------------------------------------ Search / Grep
    def _build_search_view(self):
        frame = tk.Frame(self.content, bg=th.BG_DARK)
        self._section_title(frame, "Search / Grep",
                             "Regex search across every packet payload — like "
                             "`tcpdump -A | grep <pattern>` but instant and clickable.")
        row = tk.Frame(frame, bg=th.BG_DARK)
        row.pack(fill="x", padx=24, pady=(0, 10))
        self.search_var = tk.StringVar()
        entry = tk.Entry(row, textvariable=self.search_var, bg=th.BG_PANEL, fg=th.FG_MAIN,
                          insertbackground=th.FG_MAIN, font=th.FONT, relief="flat")
        entry.pack(side="left", fill="x", expand=True, ipady=4)
        entry.bind("<Return>", lambda e: self._run_search())
        tk.Button(row, text="Search", command=self._run_search, bg=th.ACCENT, fg="#0d0f12",
                  font=th.FONT_BOLD, relief="flat", cursor="hand2").pack(side="left", padx=4)

        cols = ("no", "src", "dst", "match")
        self.search_tree = ttk.Treeview(frame, columns=cols, show="headings", height=22)
        widths = {"no": 60, "src": 150, "dst": 150, "match": 560}
        for c in cols:
            self.search_tree.heading(c, text=c.capitalize())
            self.search_tree.column(c, width=widths[c], anchor="w")
        self.search_tree.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        return frame

    def _run_search(self):
        if not self.analysis:
            return
        pattern = self.search_var.get()
        if not pattern:
            return
        try:
            rx = re.compile(pattern.encode(), re.I)
        except re.error as e:
            messagebox.showerror("Bad regex", str(e))
            return
        self.search_tree.delete(*self.search_tree.get_children())
        hits = 0
        for rec in self.analysis.packets:
            if rec.raw_payload:
                m = rx.search(rec.raw_payload)
                if m:
                    snippet = rec.raw_payload[max(0, m.start() - 20):m.end() + 30]
                    text = snippet.decode(errors="replace").replace("\r", " ").replace("\n", " ")
                    self.search_tree.insert("", "end", values=(rec.no, rec.src, rec.dst, text[:120]))
                    hits += 1
        self.status_var.set(f"Search: {hits} matches")

    # ------------------------------------------------------------ Export
    def _build_export_view(self):
        frame = tk.Frame(self.content, bg=th.BG_DARK)
        self._section_title(frame, "Export Report",
                             "Generates a Markdown report (Obsidian-ready) with dashboard stats, "
                             "top talkers, DNS, carved files, and all IOC findings — defanged.")
        tk.Button(frame, text="💾 Export Markdown Report", command=self.export_report,
                  bg=th.ACCENT, fg="#0d0f12", font=th.FONT_BOLD, relief="flat",
                  cursor="hand2", padx=12, pady=8).pack(anchor="w", padx=24, pady=(0, 8))
        tk.Button(frame, text="💾 Export IOCs as JSON", command=self.export_json,
                  bg=th.BG_PANEL, fg=th.FG_MAIN, font=th.FONT_BOLD, relief="flat",
                  cursor="hand2", padx=12, pady=8).pack(anchor="w", padx=24, pady=(0, 8))
        tk.Button(frame, text="💾 Export IOCs as CSV", command=self.export_iocs_csv,
                  bg=th.BG_PANEL, fg=th.FG_MAIN, font=th.FONT_BOLD, relief="flat",
                  cursor="hand2", padx=12, pady=8).pack(anchor="w", padx=24)
        return frame

    def export_report(self):
        if not self.analysis:
            messagebox.showwarning("No data", "Load a PCAP first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".md", filetypes=[("Markdown", "*.md")],
                                             initialfile="pcap_report.md")
        if not path:
            return
        snort_rules = self.snort_output.get("1.0", "end").strip().splitlines() if hasattr(self, "snort_output") else None
        exporter.export_markdown(self.analysis, path, snort_rules=snort_rules or None)
        messagebox.showinfo("Exported", f"Report saved to:\n{path}")

    def export_json(self):
        if not self.analysis:
            messagebox.showwarning("No data", "Load a PCAP first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")],
                                             initialfile="pcap_analysis.json")
        if not path:
            return
        exporter.export_json(self.analysis, path)
        messagebox.showinfo("Exported", f"Saved to:\n{path}")

    def export_iocs_csv(self):
        if not self.analysis:
            messagebox.showwarning("No data", "Load a PCAP first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                             initialfile="iocs.csv")
        if not path:
            return
        exporter.export_iocs_csv(self.analysis, path)
        messagebox.showinfo("Exported", f"Saved to:\n{path}")

    # ------------------------------------------------------------ session save/load
    def save_session(self):
        if not self.analysis:
            messagebox.showwarning("No data", "Load a PCAP first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("Session", "*.json")],
                                             initialfile="session.json")
        if not path:
            return
        exporter.export_json(self.analysis, path)
        messagebox.showinfo("Saved", f"Session cache saved to:\n{path}\n\n"
                                     "Note: this is a summary cache (stats/IOCs). "
                                     "Re-open the original pcap for full packet browsing.")

    def load_session(self):
        path = filedialog.askopenfilename(filetypes=[("Session/JSON", "*.json")])
        if not path:
            return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        original = data.get("path")
        if original and os.path.exists(original):
            self._begin_load(original)
        else:
            messagebox.showinfo("Summary only",
                                 "Original pcap not found on disk — showing cached summary "
                                 "(IOCs/talkers) without full packet browsing.")
            self._render_summary_only(data)

    def _render_summary_only(self, data):
        self.stat_labels["Total packets"].configure(text=str(data.get("total", "—")))
        self.stat_labels["Duration"].configure(text=f"{data.get('duration', 0):.1f}s")
        self.stat_labels["IOCs found"].configure(text=str(len(data.get("iocs", []))))
        high = sum(1 for i in data.get("iocs", []) if i["risk"] == "high")
        self.stat_labels["High-risk IOCs"].configure(text=str(high))
        self.show_view("dashboard")

    # ------------------------------------------------------------ loading
    def open_pcap(self):
        if not SCAPY_OK:
            messagebox.showerror("scapy missing", "Install scapy first:\n  pip install scapy --break-system-packages")
            return
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")])
        if not path:
            return
        self._begin_load(path)

    def _begin_load(self, path):
        self.file_label.configure(text=os.path.basename(path))
        self.status_var.set("Loading...")
        self.progress["value"] = 0
        threading.Thread(target=self._load_thread, args=(path,), daemon=True).start()

    def _load_thread(self, path):
        try:
            analysis = PcapAnalysis(path)

            def progress_cb(i, total):
                pct = int(i / max(total, 1) * 100)
                self.after(0, lambda: (self.progress.configure(value=pct),
                                       self.status_var.set(f"Parsing {i}/{total}...")))

            analysis.load(progress_cb=progress_cb)
            self.analysis = analysis
            self.after(0, self._on_loaded)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error loading PCAP", str(e)))
            self.after(0, lambda: self.status_var.set("Failed to load."))

    def _on_loaded(self):
        a = self.analysis
        self.progress["value"] = 100
        self.status_var.set(f"Loaded {a.total} packets.")

        self.stat_labels["Total packets"].configure(text=str(a.total))
        self.stat_labels["Duration"].configure(text=f"{a.duration():.1f}s")
        self.stat_labels["TCP streams"].configure(text=str(len(a.streams)))
        self.stat_labels["Files carved"].configure(text=str(len(a.carved_files)))
        self.stat_labels["IOCs found"].configure(text=str(len(a.iocs)))
        high = sum(1 for i in a.iocs if i["risk"] == "high")
        self.stat_labels["High-risk IOCs"].configure(text=str(high))

        for w in self.proto_canvas.winfo_children():
            w.destroy()
        total = max(a.total, 1)
        for proto, count in a.proto_counts.most_common():
            row = tk.Frame(self.proto_canvas, bg=th.BG_DARK)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=f"{proto:6s}", bg=th.BG_DARK, fg=th.FG_MAIN, font=th.FONT,
                     width=8, anchor="w").pack(side="left")
            bar_bg = tk.Frame(row, bg=th.BG_PANEL, height=14)
            bar_bg.pack(side="left", fill="x", expand=True, padx=8)
            pct = count / total
            tk.Frame(bar_bg, bg=th.ACCENT, height=14, width=max(2, int(pct * 500))).pack(side="left")
            tk.Label(row, text=f"{count} ({pct*100:.1f}%)", bg=th.BG_DARK, fg=th.FG_DIM,
                     font=th.FONT).pack(side="left")

        summary = []
        top_talker = a.top_talkers(1)
        if top_talker:
            (s, d), c = top_talker[0]
            summary.append(f"Top talker: {s} -> {d}  ({c} packets, {a.talker_bytes[(s,d)]:,} bytes)")
        if a.dns_stats():
            top_dns = a.dns_stats()[0]
            summary.append(f"Most-queried domain: {top_dns[0]}  ({top_dns[1]} queries)")
        if a.carved_files:
            summary.append(f"Files carved from traffic: {len(a.carved_files)}")
        summary.append(f"High-risk IOCs: {high}")
        for ioc in [i for i in a.iocs if i["risk"] == "high"][:12]:
            summary.append(f"  [!] {ioc['kind']}: {str(ioc['detail'])[:100]}  (pkt #{ioc['packet_no']})")
        self.summary_box.configure(state="normal")
        self.summary_box.delete("1.0", "end")
        self.summary_box.insert("1.0", "\n".join(summary) if summary else "No notable findings.")
        self.summary_box.configure(state="disabled")

        self.refresh_packet_view()
        self.refresh_talkers_view()
        self.refresh_dns_view()
        self.refresh_streams_view()
        self.refresh_files_view()
        self.refresh_iocs_view()
        self.show_view("dashboard")


def launch(initial_pcap=None):
    app = NetworkTinkerApp(initial_pcap=initial_pcap)
    app.mainloop()
