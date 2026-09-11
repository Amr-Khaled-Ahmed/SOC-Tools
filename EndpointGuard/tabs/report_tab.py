import tkinter as tk
from tkinter import ttk, messagebox

from core import report as report_core
from core.flags import SEVERITY_COLORS


class ReportTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        ttk.Button(top, text="Refresh", command=self.refresh).pack(side="left", padx=(0, 6))
        ttk.Button(top, text="Export Markdown", command=self._export_md).pack(side="left", padx=(0, 6))
        ttk.Button(top, text="Export JSON", command=self._export_json).pack(side="left", padx=(0, 6))
        ttk.Button(top, text="Export full session (.zip)", command=self._export_zip).pack(side="left", padx=(0, 6))
        ttk.Button(top, text="Clear all flags", command=self._clear_all).pack(side="left")

        text_frame = ttk.Frame(self)
        text_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)
        self.text = tk.Text(text_frame, wrap="word")
        vsb = ttk.Scrollbar(text_frame, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=vsb.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

    def refresh(self):
        items = self.app.flag_store.get_all()
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", report_core.build_markdown(items))
        self.text.configure(state="disabled")

    def _export_md(self):
        path = report_core.export_markdown(self.app.flag_store.get_all())
        messagebox.showinfo("Export", f"Saved:\n{path}")

    def _export_json(self):
        path = report_core.export_json(self.app.flag_store.get_all())
        messagebox.showinfo("Export", f"Saved:\n{path}")

    def _export_zip(self):
        path = report_core.export_full_session_zip(self.app.flag_store.get_all(), self.app.command_log)
        messagebox.showinfo("Export", f"Saved:\n{path}")

    def _clear_all(self):
        if messagebox.askyesno("Clear all flags", "Remove every flagged item across all tabs?"):
            self.app.flag_store.clear()
            self.refresh()
