import json
import os
import tkinter as tk
from tkinter import ttk

from core import platform_utils
from core.flags import FlagStore

from tabs.dashboard_tab import DashboardTab
from tabs.processes_tab import ProcessesTab
from tabs.autoruns_tab import AutorunsTab
from tabs.services_tab import ServicesTab
from tabs.tasks_cron_tab import TasksCronTab
from tabs.eventlogs_tab import EventLogsTab
from tabs.sysmon_tab import SysmonTab
from tabs.registry_tab import RegistryTab
from tabs.network_tab import NetworkTab
from tabs.report_tab import ReportTab
from tabs.cheatsheet_tab import CheatsheetTab
from tabs.baseline_tab import BaselineTab

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


class EndpointGuardApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EndpointGuard - Endpoint Security Triage Tool")
        self.geometry("1000x720")

        self.os_name = platform_utils.get_os()
        self.flag_store = FlagStore()
        self.command_log = []  # list of {tab, command, output, timestamp}
        self.commands = self._load_json("commands.json")
        self.help_content = self._load_json("help_content.json")

        self.topic_tabs = {}  # tab_key -> tab instance, used by BaselineTab

        self._build_ui()

    def _load_json(self, filename):
        path = os.path.join(DATA_DIR, filename)
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _build_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)

        # Dashboard first
        self.dashboard_tab = DashboardTab(notebook, self)
        notebook.add(self.dashboard_tab, text="Dashboard")

        # Topic tabs - registered so Baseline/Compare and Cheatsheet can use them
        topic_tab_classes = [
            ("processes", "Processes", ProcessesTab, True),
            ("autoruns", "Autoruns", AutorunsTab, True),
            ("services", "Services", ServicesTab, self.os_name == "windows"),
            ("tasks_cron", "Tasks / Cron", TasksCronTab, True),
            ("eventlogs", "Event Logs", EventLogsTab, True),
            ("sysmon", "Sysmon", SysmonTab, True),
            ("registry", "Registry", RegistryTab, self.os_name == "windows"),
            ("network", "Network", NetworkTab, True),
        ]
        for key, label, cls, enabled in topic_tab_classes:
            if not enabled:
                continue
            tab = cls(notebook, self)
            notebook.add(tab, text=label)
            self.topic_tabs[key] = tab

        # Cross-cutting tabs
        self.report_tab = ReportTab(notebook, self)
        notebook.add(self.report_tab, text="Report")

        self.cheatsheet_tab = CheatsheetTab(notebook, self)
        notebook.add(self.cheatsheet_tab, text="Cheatsheet")

        self.baseline_tab = BaselineTab(notebook, self)
        notebook.add(self.baseline_tab, text="Baseline / Compare")

        # Refresh dashboard whenever a tab is selected (cheap, keeps counts current)
        notebook.bind("<<NotebookTabChanged>>", lambda e: self.dashboard_tab.refresh())
