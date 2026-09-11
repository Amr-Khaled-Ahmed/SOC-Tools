from tabs.base_tab import BaseTab
from core import platform_utils


class RegistryTab(BaseTab):
    TAB_KEY = "registry"
    COLUMNS = ("Key", "Value Name", "Data")
    NATIVE_TOOL = "registry_editor"

    KEYS_OF_INTEREST = [
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ]

    def fetch_rows(self):
        rows = []
        if platform_utils.get_os() != "windows":
            return rows
        for key in self.KEYS_OF_INTEREST:
            success, output = platform_utils.run_command(f'reg query "{key}"')
            if not success:
                continue
            for line in output.splitlines():
                line = line.strip()
                if not line or "REG_" not in line:
                    continue
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    name, _, data = parts
                    rows.append((key, name, data))
        return rows

    def _extract_iocs(self, values):
        if len(values) >= 3 and values[2] not in (None, "", "N/A"):
            return [str(values[2])]
        return []
