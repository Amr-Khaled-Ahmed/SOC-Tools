import tkinter as tk
from tkinter import ttk


class CheatsheetTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        ttk.Label(self, text="All commands across every tab, for this OS. Select text and copy manually,\n"
                              "or use the per-tab Live Command Runner buttons directly.",
                  justify="left").grid(row=0, column=0, sticky="w", padx=10, pady=10)

        frame = ttk.Frame(self)
        frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        text = tk.Text(frame, wrap="word")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=vsb.set)
        text.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        lines = []
        for tab_key, per_os in self.app.commands.items():
            cmds = per_os.get(self.app.os_name, [])
            if not cmds:
                continue
            lines.append(f"=== {tab_key} ===")
            for c in cmds:
                lines.append(f"# {c['label']}")
                lines.append(c["cmd"])
                lines.append("")
        text.insert("1.0", "\n".join(lines) if lines else "No commands available for this OS.")
        text.configure(state="disabled")
