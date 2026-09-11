from tabs.base_tab import BaseTab

try:
    import psutil
except ImportError:
    psutil = None


class NetworkTab(BaseTab):
    TAB_KEY = "network"
    COLUMNS = ("Local Addr", "Remote Addr", "Status", "PID")
    NATIVE_TOOL = None

    def fetch_rows(self):
        rows = []
        if not psutil:
            return rows
        try:
            for c in psutil.net_connections(kind="inet"):
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A"
                rows.append((laddr, raddr, c.status, c.pid or "N/A"))
        except (psutil.AccessDenied, PermissionError):
            pass
        return rows

    def _extract_iocs(self, values):
        # remote address is the interesting IOC
        if len(values) >= 2 and values[1] not in (None, "", "N/A"):
            return [str(values[1])]
        return []
