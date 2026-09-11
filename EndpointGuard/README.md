EndpointGuard
=============

A read-only, defensive endpoint security triage GUI tool built with Python
and Tkinter. Based on SOC101 (TCM) course notes on endpoint security:
processes, autoruns, services, scheduled tasks/cron, event logs, sysmon,
the registry, and network analysis.

WHAT IT IS
----------
EndpointGuard is a study/triage companion, not an attack or admin tool.
Every tab is read-only by default: it lists information and lets you run
"live commands" (real OS commands you'd use during an investigation), but
it never modifies your system on its own. Any command with the potential
to change system state is clearly labeled and requires you to confirm
before running it.

INSTALL
-------
1. Python 3.9+ required.
2. pip install -r requirements.txt
3. python main.py

FOLDER STRUCTURE
-----------------
main.py                 Entry point
app.py                  Main Tkinter app / notebook (tabs) setup
core/                   Shared logic (platform detection, baseline diff,
                         flags/severity, report export)
tabs/                   One file per tab, all topic tabs share BaseTab
data/                   commands.json (live command catalog),
                         help_content.json (per-tab help text),
                         baselines/ (saved snapshots)
exports/                Where Report/session exports are written

TABS
----
Dashboard        neofetch-style system overview + flagged count + last
                 baseline diff summary
Processes        Windows/Linux process analysis (tasklist, ps, wmic...)
Autoruns         Run/RunOnce keys, PSAutorun workflow
Services         Windows services (sc qc, Get-Service, WMI/CIM)
Tasks / Cron     Scheduled Tasks (Windows) / cron jobs (Linux)
Event Logs       Windows Event Log querying (wevtutil, Get-WinEvent)
Sysmon           Sysmon event correlation
Registry         Windows Registry persistence locations (Windows only)
Network          Active connections (netstat / ss, lsof)
Report           Aggregates all flagged items, export to Markdown/JSON/zip
Cheatsheet       All commands from every tab in one copyable place
Baseline/Compare Save a snapshot of current state, compare against a
                 later one to see what changed

EACH TOPIC TAB HAS
-------------------
- Data View: table of items, search box, right-click to flag a row
  (Info / Suspicious / Critical) with an optional note
- Live Command Runner: buttons that run real read-only OS commands and
  print output inline
- "Open Native Tool" button: opens the OS's own tool for that topic
  (Task Manager, services.msc, Event Viewer, etc.)
- Help panel: what this topic is, why it matters, IOCs to look for
- "Copy IOCs" button: copies IOCs from flagged rows to the clipboard

NOT INCLUDED (ON PURPOSE)
--------------------------
No payload generation, no AV evasion helpers, no exploitation features.
This tool is strictly defensive/read-only, matching the SOC/blue-team
side of the source material only.
