"""
In-memory flagged-item registry shared across all tabs.
Severity levels: Info, Suspicious, Critical.
"""

SEVERITY_LEVELS = ["Info", "Suspicious", "Critical"]

SEVERITY_COLORS = {
    "Info": "#3B8BD4",       # blue
    "Suspicious": "#EF9F27", # amber
    "Critical": "#E24B4A",   # red
}


class FlagStore:
    """Singleton-style store (one instance shared via app.py)."""

    def __init__(self):
        # list of dicts: {tab, row_label, severity, note, iocs: [str, ...]}
        self._items = []

    def add(self, tab, row_label, severity, note="", iocs=None):
        if severity not in SEVERITY_LEVELS:
            severity = "Info"
        self._items.append({
            "tab": tab,
            "row_label": row_label,
            "severity": severity,
            "note": note,
            "iocs": iocs or [],
        })

    def remove(self, tab, row_label):
        self._items = [
            i for i in self._items
            if not (i["tab"] == tab and i["row_label"] == row_label)
        ]

    def get_all(self):
        return list(self._items)

    def get_for_tab(self, tab):
        return [i for i in self._items if i["tab"] == tab]

    def count(self):
        return len(self._items)

    def count_by_severity(self):
        counts = {lvl: 0 for lvl in SEVERITY_LEVELS}
        for i in self._items:
            counts[i["severity"]] += 1
        return counts

    def iocs_for_tab(self, tab):
        iocs = []
        for i in self.get_for_tab(tab):
            iocs.extend(i["iocs"])
        return iocs

    def clear(self):
        self._items = []
