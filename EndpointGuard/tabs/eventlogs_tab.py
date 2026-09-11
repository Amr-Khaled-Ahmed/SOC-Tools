from tabs.base_tab import BaseTab
from core import platform_utils


class EventLogsTab(BaseTab):
    TAB_KEY = "eventlogs"
    COLUMNS = ("Event/Line", "Detail")
    NATIVE_TOOL = "event_viewer"

    def fetch_rows(self):
        os_name = platform_utils.get_os()
        rows = []
        if os_name == "windows":
            success, output = platform_utils.run_command("wevtutil qe System /c:15 /rd:true /f:text")
            if success:
                current = []
                for line in output.splitlines():
                    if line.startswith("Event["):
                        if current:
                            rows.append((current[0], " | ".join(current[1:3])))
                        current = [line]
                    elif current:
                        current.append(line.strip())
                if current:
                    rows.append((current[0], " | ".join(current[1:3])))
        elif os_name == "linux":
            success, output = platform_utils.run_command("journalctl -n 15 --no-pager")
            if success:
                for line in output.splitlines():
                    if line.strip():
                        rows.append((line[:60], line))
        return rows

    def _extract_iocs(self, values):
        return [str(values[0])] if values else []
