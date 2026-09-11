from tabs.base_tab import BaseTab

try:
    import psutil
except ImportError:
    psutil = None


class ProcessesTab(BaseTab):
    TAB_KEY = "processes"
    COLUMNS = ("PID", "Name", "PPID", "Exe Path")
    NATIVE_TOOL = "task_manager"

    def fetch_rows(self):
        rows = []
        if not psutil:
            return rows
        for p in psutil.process_iter(["pid", "name", "ppid", "exe"]):
            try:
                info = p.info
                rows.append((info.get("pid"), info.get("name") or "Unknown",
                             info.get("ppid"), info.get("exe") or "N/A"))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return rows

    def _extract_iocs(self, values):
        # PID, Name, PPID, Exe Path -> IOC is name + exe path
        iocs = []
        if len(values) >= 4:
            if values[1] not in (None, "", "N/A"):
                iocs.append(str(values[1]))
            if values[3] not in (None, "", "N/A"):
                iocs.append(str(values[3]))
        return iocs
