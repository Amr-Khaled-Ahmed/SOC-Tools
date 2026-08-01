# PhishTinker

**Author**: Amr Eldhshan

**GitHub**: https://github.com/Amr-Khaled-Ahmed

PhishTinker is a local SOC-style phishing email triage tool with both a polished Tkinter GUI and a headless CLI mode. It is designed to help analysts explore suspicious `.eml` email samples, inspect headers and attachments, and export findings as text, JSON, or Markdown.

## Quick start

```bash
cd phishtinker_project
python3 -m phishtinker
```

## Features

- SOC-friendly GUI with tabbed workflow for Overview, Findings, Attachments, Links & IPs, Header Analysis, Mail View, and Content Analysis.
- Support for Markdown export with rich content summaries.
- Optional VirusTotal attachment scan via API key.
- Inline HTML preview and editable email source for deeper analysis.
- One-click Copy All IOCs and country-flag geolocation in the Links & IPs tab.
- Optional IP reputation lookup and threat enrichment.
- Headless CLI mode for batch processing and automation.

## Install

```bash
cd phishtinker_project
pip install -r requirements.txt --break-system-packages
pip install -e .
```

## Usage

GUI:

```bash
python3 -m phishtinker
```

CLI:

```bash
python3 -m phishtinker samples/sample_phish.eml --format markdown -o report.md
```

## Notes

The GUI is designed for analysts who want a polished, SOC-style investigation experience. It works locally by default and only performs online lookups when explicitly enabled.
