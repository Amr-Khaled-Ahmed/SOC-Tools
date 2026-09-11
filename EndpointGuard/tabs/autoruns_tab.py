from tabs.base_tab import BaseTab
from core import platform_utils


class AutorunsTab(BaseTab):
    TAB_KEY = "autoruns"
    COLUMNS = ("Location", "Name", "Value")
    NATIVE_TOOL = None  # Autoruns isn't a built-in OS tool; use Live Commands instead

    def fetch_rows(self):
        os_name = platform_utils.get_os()
        rows = []
        if os_name == "windows":
            rows.extend(self._parse_reg_query(
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run"))
            rows.extend(self._parse_reg_query(
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\...\\Run"))
        elif os_name == "linux":
            success, output = platform_utils.run_command("ls ~/.config/autostart/ 2>/dev/null")
            if success and output and output != "(no output)":
                for line in output.splitlines():
                    if line.strip():
                        rows.append(("~/.config/autostart", line.strip(), ""))
        return rows

    def _parse_reg_query(self, key_path, location_label):
        rows = []
        success, output = platform_utils.run_command(f'reg query "{key_path}"')
        if not success:
            return rows
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith(key_path.split("\\")[0]) or "REG_" not in line:
                continue
            parts = line.split(None, 2)
            if len(parts) >= 3:
                name, _, value = parts
                rows.append((location_label, name, value))
        return rows

    def _extract_iocs(self, values):
        # Location, Name, Value -> the Value (path) is the real IOC
        if len(values) >= 3 and values[2] not in (None, "", "N/A"):
            return [str(values[2])]
        return [str(values[0])] if values else []
