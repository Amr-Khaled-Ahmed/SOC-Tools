"""
BaseTab: shared layout used by every topic tab (Processes, Autoruns,
Services, Tasks/Cron, Event Logs, Sysmon, Registry, Network).

Layout (top to bottom):
  - Search box
  - Data table (Treeview) with right-click flagging
  - Live Command Runner (buttons + output box)
  - Row: [Open Native Tool] [Copy IOCs] [Help]
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time

from core import platform_utils
from core.flags import SEVERITY_LEVELS, SEVERITY_COLORS


class BaseTab(ttk.Frame):
    # Subclasses set these
    TAB_KEY = "base"          # key into commands.json / help_content.json
    COLUMNS = ("Name", "Detail")  # Treeview columns
    NATIVE_TOOL = None         # logical name for platform_utils.open_native_tool

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app  # reference to main App (holds flag_store, command_log, os_name, commands, help)
        self._all_rows = []  # list of tuples matching self.COLUMNS
        self._build_ui()
        self.refresh_data()

    # ---------- UI construction ----------

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=3)
        self.rowconfigure(3, weight=2)

        # Search bar
        search_frame = ttk.Frame(self)
        search_frame.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        ttk.Label(search_frame, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._apply_filter())
        ttk.Entry(search_frame, textvariable=self.search_var).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(search_frame, text="Refresh", command=self.refresh_data).pack(side="left")

        # Data table
        table_frame = ttk.Frame(self)
        table_frame.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(table_frame, columns=self.COLUMNS, show="headings", selectmode="browse")
        for col in self.COLUMNS:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=180, anchor="w")
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        for level, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(level, background=color, foreground="white")

        self.tree.bind("<Button-3>", self._on_right_click)   # Windows/Linux right click

        # Live Command Runner
        cmd_frame = ttk.LabelFrame(self, text="Live Command Runner")
        cmd_frame.grid(row=2, column=0, sticky="ew", padx=8, pady=4)
        self.cmd_buttons_frame = ttk.Frame(cmd_frame)
        self.cmd_buttons_frame.pack(fill="x", padx=4, pady=4)
        self._build_command_buttons()

        # Output box
        output_frame = ttk.Frame(self)
        output_frame.grid(row=3, column=0, sticky="nsew", padx=8, pady=4)
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        self.output_text = tk.Text(output_frame, height=10, wrap="none", state="disabled")
        out_vsb = ttk.Scrollbar(output_frame, orient="vertical", command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=out_vsb.set)
        self.output_text.grid(row=0, column=0, sticky="nsew")
        out_vsb.grid(row=0, column=1, sticky="ns")

        # Bottom action row
        actions = ttk.Frame(self)
        actions.grid(row=4, column=0, sticky="ew", padx=8, pady=(4, 8))
        if self.NATIVE_TOOL:
            ttk.Button(actions, text="Open Native Tool", command=self._open_native_tool).pack(side="left", padx=(0, 6))
        ttk.Button(actions, text="Copy IOCs", command=self._copy_iocs).pack(side="left", padx=(0, 6))
        ttk.Button(actions, text="Help", command=self._show_help).pack(side="left")

    def _build_command_buttons(self):
        for w in self.cmd_buttons_frame.winfo_children():
            w.destroy()
        commands = self.app.commands.get(self.TAB_KEY, {}).get(self.app.os_name, [])
        if not commands:
            ttk.Label(self.cmd_buttons_frame, text="No commands available for this OS.").pack(side="left")
            return
        for c in commands:
            ttk.Button(
                self.cmd_buttons_frame, text=c["label"],
                command=lambda cmd=c: self._run_command(cmd)
            ).pack(side="left", padx=3, pady=2)

    # ---------- Data (subclasses override fetch_rows) ----------

    def fetch_rows(self):
        """Subclasses override. Must return list of tuples matching self.COLUMNS."""
        return []

    def refresh_data(self):
        self._all_rows = self.fetch_rows()
        self._apply_filter()

    def _apply_filter(self):
        query = self.search_var.get().lower().strip()
        self.tree.delete(*self.tree.get_children())
        flagged = {f["row_label"]: f["severity"] for f in self.app.flag_store.get_for_tab(self.TAB_KEY)}
        for row in self._all_rows:
            row_text = " ".join(str(c) for c in row).lower()
            if query and query not in row_text:
                continue
            row_label = str(row[0])
            tags = (flagged[row_label],) if row_label in flagged else ()
            self.tree.insert("", "end", values=row, tags=tags)

    # ---------- Flagging ----------

    def _on_right_click(self, event):
        item_id = self.tree.identify_row(event.y)
        if not item_id:
            return
        self.tree.selection_set(item_id)
        values = self.tree.item(item_id, "values")
        row_label = str(values[0]) if values else "unknown"

        menu = tk.Menu(self, tearoff=0)
        for level in SEVERITY_LEVELS:
            menu.add_command(label=f"Flag as {level}", command=lambda lv=level, r=row_label, v=values: self._flag_row(r, lv, v))
        menu.add_separator()
        menu.add_command(label="Clear flag", command=lambda r=row_label: self._clear_flag(r))
        menu.tk_popup(event.x_root, event.y_root)

    def _flag_row(self, row_label, severity, values):
        note = tk.simpledialog.askstring("Note (optional)", f"Note for '{row_label}' [{severity}]:", parent=self) or ""
        iocs = self._extract_iocs(values)
        self.app.flag_store.remove(self.TAB_KEY, row_label)
        self.app.flag_store.add(self.TAB_KEY, row_label, severity, note, iocs)
        self._apply_filter()

    def _clear_flag(self, row_label):
        self.app.flag_store.remove(self.TAB_KEY, row_label)
        self._apply_filter()

    def _extract_iocs(self, values):
        """By default, treat every non-empty column value as a potential IOC."""
        return [str(v) for v in values if v not in (None, "", "N/A")]

    # ---------- Actions ----------

    def _open_native_tool(self):
        ok, msg = platform_utils.open_native_tool(self.NATIVE_TOOL)
        if not ok:
            messagebox.showwarning("Open Native Tool", msg)

    def _copy_iocs(self):
        iocs = self.app.flag_store.iocs_for_tab(self.TAB_KEY)
        if not iocs:
            messagebox.showinfo("Copy IOCs", "No flagged items in this tab yet.")
            return
        text = "\n".join(dict.fromkeys(iocs))  # dedupe, keep order
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copy IOCs", f"Copied {len(set(iocs))} unique IOC(s) to clipboard.")

    def _show_help(self):
        text = self.app.help_content.get(self.TAB_KEY, "No help content available for this tab.")
        top = tk.Toplevel(self)
        top.title(f"Help - {self.TAB_KEY}")
        top.geometry("520x420")
        box = tk.Text(top, wrap="word")
        box.insert("1.0", text)
        box.configure(state="disabled")
        box.pack(fill="both", expand=True, padx=10, pady=10)

    def _run_command(self, cmd_spec):
        # Warn on anything that looks like it could modify state
        risky_words = ["reg add", "reg delete", "sc create", "sc delete", "sc stop", "sc start",
                       "start-service", "stop-service", "remove-", "del ", "rm ", "export"]
        cmd_lower = cmd_spec["cmd"].lower()
        if any(w in cmd_lower for w in risky_words):
            if not messagebox.askyesno(
                "Confirm command",
                f"This command may change system state:\n\n{cmd_spec['cmd']}\n\nRun it anyway?"
            ):
                return

        self._append_output(f"$ {cmd_spec['cmd']}\n(running...)\n")

        def worker():
            success, output = platform_utils.run_command(cmd_spec["cmd"])
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            self.app.command_log.append({
                "tab": self.TAB_KEY, "command": cmd_spec["cmd"],
                "output": output, "timestamp": timestamp,
            })
            self.after(0, lambda: self._append_output(output + "\n" + ("-" * 60) + "\n", replace_last_running=True))

        threading.Thread(target=worker, daemon=True).start()

    def _append_output(self, text, replace_last_running=False):
        self.output_text.configure(state="normal")
        if replace_last_running:
            content = self.output_text.get("1.0", "end")
            if content.rstrip().endswith("(running...)"):
                idx = content.rfind("(running...)")
                self.output_text.delete("1.0", "end")
                self.output_text.insert("1.0", content[:idx])
        self.output_text.insert("end", text)
        self.output_text.see("end")
        self.output_text.configure(state="disabled")


# tkinter.simpledialog needs explicit import in some environments
import tkinter.simpledialog  # noqa: E402
