from tabs.base_tab import BaseTab

try:
    import psutil
except ImportError:
    psutil = None


class ServicesTab(BaseTab):
    TAB_KEY = "services"
    COLUMNS = ("Name", "Status", "Start Type", "Binary Path")
    NATIVE_TOOL = "services"

    def fetch_rows(self):
        rows = []
        if psutil and hasattr(psutil, "win_service_iter"):
            try:
                for s in psutil.win_service_iter():
                    d = s.as_dict()
                    rows.append((d.get("name"), d.get("status"), d.get("start_type"), d.get("binpath") or "N/A"))
            except Exception:
                pass
        return rows

    def _extract_iocs(self, values):
        # Name, Status, Start Type, Binary Path
        iocs = []
        if len(values) >= 4:
            if values[0] not in (None, "", "N/A"):
                iocs.append(str(values[0]))
            if values[3] not in (None, "", "N/A"):
                iocs.append(str(values[3]))
        return iocs
