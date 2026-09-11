from tabs.base_tab import BaseTab
from core import platform_utils


class TasksCronTab(BaseTab):
    TAB_KEY = "tasks_cron"
    COLUMNS = ("Name/Line", "Detail")
    NATIVE_TOOL = "task_scheduler"

    def fetch_rows(self):
        os_name = platform_utils.get_os()
        rows = []
        if os_name == "windows":
            success, output = platform_utils.run_command("schtasks /query /fo CSV /nh")
            if success:
                for line in output.splitlines():
                    parts = [p.strip('"') for p in line.split('","')]
                    if len(parts) >= 3:
                        name = parts[0].strip('"')
                        status = parts[2].strip('"') if len(parts) > 2 else ""
                        rows.append((name, status))
        elif os_name == "linux":
            success, output = platform_utils.run_command("crontab -l 2>/dev/null")
            if success and output != "(no output)":
                for line in output.splitlines():
                    if line.strip() and not line.strip().startswith("#"):
                        rows.append((line.strip(), "user crontab"))
        return rows

    def _extract_iocs(self, values):
        return [str(values[0])] if values else []
