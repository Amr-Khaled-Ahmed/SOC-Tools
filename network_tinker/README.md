# Network Tinker

A GUI + CLI PCAP triage tool, built for TCM SOC101-style network security work.
Same dark-sidebar look as PhishTinker, but for packet captures instead of email.

## Install

```bash
cd network_tinker
pip install -r requirements.txt --break-system-packages
```

(`tkinter` ships with your Python install — on Fedora/Ultramarine, if it's
missing: `sudo dnf install python3-tkinter`.)

## Run

```bash
./run.py                       # opens the GUI
./run.py capture.pcap          # opens the GUI with a pcap pre-loaded
./run.py --cli capture.pcap    # headless terminal report (no GUI)
```

Or as a module:

```bash
python3 -m network_tinker.main capture.pcap
python3 -m network_tinker.cli capture.pcap --report out.md --grep "pass|login" --carve ./carved/
```

## What it does

| View | Purpose |
|---|---|
| **Dashboard** | Packet count, duration, stream count, files carved, protocol breakdown, auto-triage summary |
| **Packets** | Full packet table with a BPF-lite filter bar (`host X and port Y`, `tcp and not port 22`, `http`) — shows the equivalent `tcpdump` CLI command for copy/paste |
| **Top Talkers** | Src/dst pairs by packet count & bytes — double-click to jump into a filtered packet view (beaconing/C2 finder) |
| **DNS Explorer** | Every DNS query, ranked by frequency |
| **Follow Stream** | Full TCP conversation reconstruction, client vs. server, like Wireshark's Follow TCP Stream |
| **Carved Files** | Files pulled out of traffic via `Content-Disposition` or magic-byte signatures, with SHA256 hashes ready for VirusTotal, and a save-to-disk button |
| **IOC Hunter** | Auto-flags cleartext creds, HTTP Basic Auth (base64-decoded), malware-flagged User-Agents, dropped files, suspicious extensions, C2-style domains (t.me, pastebin, ngrok, duckdns...), insecure protocols (FTP/Telnet/POP3), and SYN-scan bursts — risk-colored and deduplicated |
| **Snort Rule Lab** | One-click generators for the classic SOC101 patterns (LFI, brute force, SSH key exfil, outbound FTP) plus a manual rule builder — valid Snort syntax, ready to paste into `local.rules` |
| **Search / Grep** | Regex search across every packet payload — `tcpdump -A \| grep` but instant |
| **Export Report** | Markdown (Obsidian-ready, indicators defanged), JSON, or CSV |

Session save/load caches the analysis summary (stats + IOCs) to JSON so you
don't have to re-parse a huge pcap just to glance at findings again.

## Package layout

```
network_tinker/
├── run.py                   # convenience launcher
├── requirements.txt
├── network_tinker/
│   ├── main.py               # GUI entry point
│   ├── cli.py                 # headless terminal mode
│   ├── core/
│   │   ├── models.py          # PacketRecord
│   │   ├── analysis.py        # PcapAnalysis engine: parsing, streams, carving, IOC hunting
│   │   ├── filters.py         # BPF-lite filter language
│   │   ├── indicators.py      # curated offline threat-intel lists (edit to tune)
│   │   ├── snort.py           # Snort rule generator
│   │   └── exporter.py        # Markdown/JSON/CSV report export
│   └── gui/
│       ├── theme.py           # shared colors/fonts
│       └── app.py             # the Tkinter application
```

All indicator lists live in `core/indicators.py` — tune them freely per
challenge (add a C2 domain from a specific pcap, flag a new malware UA, etc.)
without touching any GUI code.

## Notes

- Everything runs offline — no API calls, no telemetry.
- `--carve` / the Carved Files tab pulls files straight out of reconstructed
  TCP streams, matching the "what file got exfiltrated" question style from
  the SOC101 challenges.
- The IOC hunter is deliberately conservative/broad rather than "smart" —
  it's meant to point you at the right five packets out of five thousand,
  not replace reading the pcap yourself.
