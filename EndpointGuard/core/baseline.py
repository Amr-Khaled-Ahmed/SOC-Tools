"""
Baseline snapshot save / load / compare.
A snapshot is a dict: {tab_name: [list of row dicts], ...}
Stored as JSON under data/baselines/.
"""
import json
import os
import time

BASELINE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "baselines")


def _ensure_dir():
    os.makedirs(BASELINE_DIR, exist_ok=True)


def save_snapshot(snapshot: dict, label: str = None):
    _ensure_dir()
    ts = time.strftime("%Y%m%d-%H%M%S")
    label = label or ts
    path = os.path.join(BASELINE_DIR, f"{label}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"created": ts, "data": snapshot}, f, indent=2)
    return path


def list_snapshots():
    _ensure_dir()
    files = [f for f in os.listdir(BASELINE_DIR) if f.endswith(".json")]
    return sorted(files, reverse=True)


def load_snapshot(filename):
    path = os.path.join(BASELINE_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def latest_snapshot():
    snaps = list_snapshots()
    if not snaps:
        return None
    return load_snapshot(snaps[0])


def diff_snapshots(old: dict, new: dict):
    """
    Compares two snapshot 'data' dicts (tab -> list of row-strings).
    Returns {tab: {"added": [...], "removed": [...]}}
    """
    result = {}
    tabs = set(old.keys()) | set(new.keys())
    for tab in tabs:
        old_rows = set(old.get(tab, []))
        new_rows = set(new.get(tab, []))
        added = sorted(new_rows - old_rows)
        removed = sorted(old_rows - new_rows)
        if added or removed:
            result[tab] = {"added": added, "removed": removed}
    return result


def summarize_diff(diff: dict):
    """Short human string for the Dashboard, e.g. '3 new processes, 1 new autorun'."""
    if not diff:
        return "No changes since last baseline."
    parts = []
    for tab, changes in diff.items():
        n_add = len(changes.get("added", []))
        n_rem = len(changes.get("removed", []))
        if n_add:
            parts.append(f"{n_add} new in {tab}")
        if n_rem:
            parts.append(f"{n_rem} removed in {tab}")
    return ", ".join(parts) if parts else "No changes since last baseline."
