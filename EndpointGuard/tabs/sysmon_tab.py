from tabs.base_tab import BaseTab
from core import platform_utils


class SysmonTab(BaseTab):
    TAB_KEY = "sysmon"
    COLUMNS = ("Event/Line", "Detail")
    NATIVE_TOOL = "event_viewer"

    def fetch_rows(self):
        os_name = platform_utils.get_os()
        rows = []
        if os_name == "windows":
            success, output = platform_utils.run_command(
                "wevtutil qe Microsoft-Windows-Sysmon/Operational /c:15 /rd:true /f:text")
            if success and "not found" not in output.lower() and "The specified channel" not in output:
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
            else:
                rows.append(("Sysmon log not found", "Sysmon may not be installed on this system"))
        else:
            rows.append(("N/A", "Sysmon is Windows-native; Sysmon for Linux support is limited"))
        return rows

    def _extract_iocs(self, values):
        return [str(values[0])] if values else []
