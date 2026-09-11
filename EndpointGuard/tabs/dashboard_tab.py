import tkinter as tk
from tkinter import ttk

from core import platform_utils, baseline

ASCII_LOGO = r"""
  _____           _             _       _    ____                     _
 | ____|_ __   __| |_ __   ___ (_)_ __ | |_ / ___|_   _  __ _ _ __ __| |
 |  _| | '_ \ / _` | '_ \ / _ \| | '_ \| __| |  _| | | |/ _` | '__/ _` |
 | |___| | | | (_| | |_) | (_) | | | | | |_| |_| | |_| | (_| | | | (_| |
 |_____|_| |_|\__,_| .__/ \___/|_|_| |_|\__|\____|\__,_|\__,_|_|  \__,_|
                    |_|
"""


class DashboardTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)

        logo = tk.Text(self, height=6, font=("Courier", 8), borderwidth=0)
        logo.insert("1.0", ASCII_LOGO)
        logo.configure(state="disabled")
        logo.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))

        info_frame = ttk.LabelFrame(self, text="System info")
        info_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
        self.info_label = ttk.Label(info_frame, text="", justify="left", font=("Courier", 10))
        self.info_label.pack(anchor="w", padx=10, pady=10)

        summary_frame = ttk.LabelFrame(self, text="Session summary")
        summary_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
        self.summary_label = ttk.Label(summary_frame, text="", justify="left")
        self.summary_label.pack(anchor="w", padx=10, pady=10)

        diff_frame = ttk.LabelFrame(self, text="Since last baseline")
        diff_frame.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 10))
        self.diff_label = ttk.Label(diff_frame, text="", justify="left", wraplength=600)
        self.diff_label.pack(anchor="w", padx=10, pady=10)

        ttk.Button(self, text="Refresh dashboard", command=self.refresh).grid(row=4, column=0, sticky="w", padx=10, pady=(0, 10))

    def refresh(self):
        info = platform_utils.get_system_summary()
        text = (
            f"OS:        {info['os']} {info['os_release']}\n"
            f"Hostname:  {info['hostname']}\n"
            f"Machine:   {info['machine']}\n"
            f"CPU:       {info['processor']} ({info['cpu_cores']} cores, {info['cpu_percent']} used)\n"
            f"RAM:       {info['ram_total_gb']} GB total, {info['ram_used_percent']} used\n"
            f"IP:        {info['ip_address']}\n"
            f"Uptime:    {info['uptime']}\n"
            f"Admin:     {'Yes' if info['admin'] else 'No'}\n"
            f"Processes: {info['process_count']}\n"
        )
        self.info_label.configure(text=text)

        counts = self.app.flag_store.count_by_severity()
        summary_text = (
            f"Total flagged items: {self.app.flag_store.count()}\n"
            f"  Critical:   {counts['Critical']}\n"
            f"  Suspicious: {counts['Suspicious']}\n"
            f"  Info:       {counts['Info']}\n"
            f"Commands run this session: {len(self.app.command_log)}"
        )
        self.summary_label.configure(text=summary_text)

        latest = baseline.latest_snapshot()
        if not latest:
            self.diff_label.configure(text="No baseline saved yet. Go to the Baseline/Compare tab to create one.")
        else:
            self.diff_label.configure(text=f"Latest baseline saved: {latest.get('created', 'unknown')}\n"
                                            f"Go to Baseline/Compare to check for changes against current state.")
