# PhishTinker

*Author: Amr Eldhshan*  
*GitHub: https://github.com/Amr-Khaled-Ahmed*

A local, PhishTool-style phishing email triage tool. GUI (Tkinter) + CLI, zero
mandatory dependencies, modular package you can extend.

Built as an upgrade over a single-file `eioc.py` reference script — this project
splits concerns into a proper package, adds heuristic scoring/verdicts, actual
attachment *content* inspection (not just hashing), a non-blocking GUI, JSON
export for pipeline use, and a test suite.

## Features

- Parse `.eml` files: headers, `Received` chain, SPF/DKIM/DMARC results
- Extract & defang IOCs: IPs, URLs, domains
- Attachment hashing (MD5/SHA1/SHA256) **and** content inspection:
  - Office (.doc/.docm/.xls/.xlsm/...) — VBA macro detection + suspicious API calls (via `oletools`)
  - PDF — JavaScript, `/OpenAction`, `/Launch`, embedded files, encryption (via `pypdf`)
  - Flags raw executables/scripts, HTML credential-harvesting pages, archives
- Heuristic risk scoring (0–100) with a clear verdict: Benign / Suspicious / Malicious
- Optional online IP reputation (ipinfo.io) and VirusTotal hash lookups — **opt-in, off by default**, runs on a background thread so the GUI never freezes
- Copy all extracted IOCs with one click, and view country flags for sender/server IP geolocation in the IP tab
- Export report as `.txt` or `.json`
- CLI mode for headless/batch/SOC-pipeline use

### Modern, beginner-friendly GUI

- **Simple / Technical mode toggle** — Simple mode explains every finding in plain
  English ("The reply address doesn't match the sender... don't reply, check the
  real address") with a concrete next step. Technical mode shows the raw analyst detail.
- **Big color-coded verdict banner + risk gauge** — instantly readable, no jargon required
- **Card-based layout** instead of a raw text dump — Overview, Why?(Findings),
  Attachments, Links & IPs, and Technical Details tabs
- **Drag-and-drop** `.eml` files onto the sidebar (auto-enabled if `tkinterdnd2` is installed; falls back gracefully to the Open button otherwise)
- Color + icon + word are always paired for every severity (never color-only), and a
  dark, high-contrast sidebar keeps navigation simple for non-technical users

## Project layout

```
phishtinker/
  analyzers/
    email_analyzer.py       # .eml parsing -> EmailAnalysis
    attachment_analyzer.py  # macro/PDF content inspection
    scoring.py               # heuristic risk engine
  gui/
    app.py                   # Tkinter GUI
  utils/
    ioc.py                   # IP/URL/domain extraction + defanging
    reputation.py             # ipinfo.io / VirusTotal lookups (cached, opt-in)
  cli.py                      # headless CLI
  report.py                   # text/JSON report builders
  __main__.py
tests/
  test_analysis.py
samples/
  sample_phish.eml            # synthetic test fixture
```

## Install

```bash
cd phishtinker_project
pip install -r requirements.txt --break-system-packages   # optional, for full features
pip install -e .                                          # optional, installs `phishtinker` command
```

The app runs with **zero dependencies** using only `email`/`hashlib`/`tkinter`
from the standard library; `requests`, `oletools`, and `pypdf` unlock reputation
lookups and deep macro/PDF inspection respectively but are not required.

## Usage

GUI:
```bash
python3 -m phishtinker
```

CLI (headless, single or batch files):
```bash
python3 -m phishtinker samples/sample_phish.eml
python3 -m phishtinker *.eml --format json -o report.json
```

## Tests

```bash
python3 -m unittest discover tests -v
```

## Extending

- Add VirusTotal API key wiring in the GUI (function already exists in `utils/reputation.py`)
- Add more analyzers under `analyzers/` (e.g. QR-code phishing in image attachments, homoglyph domain detection)
- Swap the Tkinter GUI for a web UI by reusing `analyzers/` + `report.py` untouched — they have no GUI dependency

## Notes

- This tool performs **static analysis only** — attachments are never opened or executed.
- Online lookups (ipinfo.io / VirusTotal) are opt-in and disabled by default for offline/air-gapped use.
