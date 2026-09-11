"""
Builds and exports the Report (flagged items) as Markdown / JSON,
or a full session zip (report + raw command outputs).
"""
import json
import os
import time
import zipfile

EXPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "exports")


def _ensure_dir():
    os.makedirs(EXPORT_DIR, exist_ok=True)


def build_markdown(flag_items):
    lines = ["# EndpointGuard Report", "", f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}", ""]
    if not flag_items:
        lines.append("No flagged items.")
        return "\n".join(lines)

    by_severity = {"Critical": [], "Suspicious": [], "Info": []}
    for item in flag_items:
        by_severity.setdefault(item["severity"], []).append(item)

    for severity in ["Critical", "Suspicious", "Info"]:
        items = by_severity.get(severity, [])
        if not items:
            continue
        lines.append(f"## {severity} ({len(items)})")
        lines.append("")
        for item in items:
            lines.append(f"- **[{item['tab']}]** {item['row_label']}")
            if item.get("note"):
                lines.append(f"  - Note: {item['note']}")
            if item.get("iocs"):
                lines.append(f"  - IOCs: {', '.join(item['iocs'])}")
        lines.append("")
    return "\n".join(lines)


def build_json(flag_items):
    return json.dumps({
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "flags": flag_items,
    }, indent=2)


def export_markdown(flag_items):
    _ensure_dir()
    path = os.path.join(EXPORT_DIR, f"report_{time.strftime('%Y%m%d-%H%M%S')}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_markdown(flag_items))
    return path


def export_json(flag_items):
    _ensure_dir()
    path = os.path.join(EXPORT_DIR, f"report_{time.strftime('%Y%m%d-%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_json(flag_items))
    return path


def export_full_session_zip(flag_items, command_log):
    """
    command_log: list of {"tab": str, "command": str, "output": str, "timestamp": str}
    """
    _ensure_dir()
    ts = time.strftime("%Y%m%d-%H%M%S")
    zip_path = os.path.join(EXPORT_DIR, f"session_{ts}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("report.md", build_markdown(flag_items))
        zf.writestr("report.json", build_json(flag_items))
        log_lines = []
        for entry in command_log:
            log_lines.append(f"=== [{entry['timestamp']}] {entry['tab']} :: {entry['command']} ===")
            log_lines.append(entry["output"])
            log_lines.append("")
        zf.writestr("command_log.txt", "\n".join(log_lines) if log_lines else "No commands were run this session.")
    return zip_path
