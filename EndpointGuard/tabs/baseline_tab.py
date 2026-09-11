import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from core import baseline


class BaselineTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._build_ui()
        self._refresh_snapshot_list()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        ttk.Button(top, text="Save current state as baseline", command=self._save_baseline).pack(side="left", padx=(0, 6))
        ttk.Button(top, text="Compare latest vs current", command=self._compare_latest).pack(side="left")

        ttk.Label(self, text="Saved baselines:").grid(row=1, column=0, sticky="w", padx=10)
        self.listbox = tk.Listbox(self, height=6)
        self.listbox.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))

        result_frame = ttk.LabelFrame(self, text="Comparison result")
        result_frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.rowconfigure(3, weight=2)
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        self.result_text = tk.Text(result_frame, wrap="word", state="disabled")
        self.result_text.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)

    def _current_snapshot(self):
        """Builds {tab_key: [row_label, ...]} from every registered topic tab."""
        snapshot = {}
        for tab_key, tab_instance in self.app.topic_tabs.items():
            rows = tab_instance.fetch_rows()
            snapshot[tab_key] = [str(r[0]) for r in rows]
        return snapshot

    def _save_baseline(self):
        label = simpledialog.askstring("Baseline label", "Optional label (leave blank for timestamp):", parent=self)
        snapshot = self._current_snapshot()
        path = baseline.save_snapshot(snapshot, label or None)
        messagebox.showinfo("Baseline saved", f"Saved to:\n{path}")
        self._refresh_snapshot_list()

    def _refresh_snapshot_list(self):
        self.listbox.delete(0, "end")
        for name in baseline.list_snapshots():
            self.listbox.insert("end", name)

    def _compare_latest(self):
        latest = baseline.latest_snapshot()
        if not latest:
            messagebox.showwarning("Compare", "No saved baseline yet. Save one first.")
            return
        current = self._current_snapshot()
        diff = baseline.diff_snapshots(latest["data"], current)

        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        if not diff:
            self.result_text.insert("1.0", "No changes detected since the last baseline.")
        else:
            lines = [f"Comparing against baseline from: {latest.get('created')}\n"]
            for tab, changes in diff.items():
                lines.append(f"=== {tab} ===")
                for a in changes.get("added", []):
                    lines.append(f"  + NEW: {a}")
                for r in changes.get("removed", []):
                    lines.append(f"  - REMOVED: {r}")
                lines.append("")
            self.result_text.insert("1.0", "\n".join(lines))
        self.result_text.configure(state="disabled")
