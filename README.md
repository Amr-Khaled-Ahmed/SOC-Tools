# SOC Tools

Welcome to the SOC Tools repository — a growing collection of analyst-focused security tools, organized by SOC domain and built to help defenders investigate, triage, and respond faster.


## Overview

This repo is designed as a central home for SOC tooling and automation. The first released project is **PhishTinker**, a phishing analysis and email triage tool that runs locally with both a polished GUI and a headless CLI mode.

The repository is planned to include tools across the following SOC categories:

- `01_Phishing_Analysis`
- `02_Network_Security`
- `03_Endpoint_Security`
- `04_SIEM`
- `05_Threat_Intelligence`
- `06_Digital_Forensics`
- `07_Incident_Response`

Each part will eventually contain purpose-built tools, scripts, and workflows for that SOC domain.

## Current Tool: PhishTinker

PhishTinker is the first publicly available tool in this repo. It helps SOC analysts rapidly inspect suspicious `.eml` email samples and clearly identify phishing indicators without relying on cloud services by default.

### PhishTinker features
![PhishTinker SOC Analyst Console](assets/PhishTinker_Screenshot.png)

- SOC-friendly, polished interface with a tabbed investigation workflow
- Email overview, sender and recipient analysis, header inspection, and content review
- Full findings panel showing why an email appears malicious
- Attachments extraction and analysis support
- Links and IPs tab for extracting indicators of compromise
- DMARC/SPF/validation and sender-verification checks
- Export reports as text, Markdown, or JSON
- Optional VirusTotal attachment lookup via API key
- One-click copy of all IOCs for threat hunting or reporting
- Headless CLI mode for batch processing and automation

## Getting Started with PhishTinker

1. Open the `Phishing Tinker Tool/phishtinker_project` directory.
2. Install dependencies and package locally if required.
3. Run the GUI or CLI as documented in `Phishing Tinker Tool/phishtinker_project/README.md`.

### Example

```bash
cd "Phishing Tinker Tool/phishtinker_project"
python3 -m phishtinker
```

or for CLI usage:

```bash
python3 -m phishtinker samples/sample_phish.eml --format markdown -o report.md
```

## Repository Structure

- `Phishing Tinker Tool/` — current phishing analysis tool and supporting files
- `assets/` — repository images and documentation assets
- future SOC domains will appear as additional directories or zipped modules

## New Tool: Network Tinker

Network Tinker is a lightweight network triage and traffic-analysis utility designed for SOC analysts. It provides an easy-to-use GUI and a headless CLI mode for inspecting pcap files, carving artifacts, extracting IOCs, and generating analyst-friendly summaries.

![Network Tinker Screenshot](assets/Network_tinker_tool.png)

Key features:

- `Open PCAP` quick-load and session saving for interactive investigation
- Protocol and stream breakdowns, top-talkers view, and DNS/HTTP explorers
- Automatic carving of files and extraction of IOCs (hashes, domains, IPs)
- Basic Snort rule lab and exportable reports for sharing findings

Quick start:

```bash
cd network_tinker
python3 run.py
```

See [network_tinker](network_tinker/README.md) for full usage and developer notes.

## New Tool: EndpointGuard

EndpointGuard is a lightweight endpoint triage and monitoring tool aimed at SOC analysts. It provides a centralized dashboard and multiple investigation tabs (Processes, Autoruns, Tasks/Cron, Event Logs, Sysmon, Network, Reports, Baseline/Compare) to help quickly assess an endpoint's state and generate analyst-friendly findings.

![Network Tinker Screenshot](assets/EndPointGuard.png)

Key features:

- Interactive dashboard with system summary and session-based findings
- Process and autorun enumeration with suspicious-flagging
- Event log and Sysmon parsing where available (Windows), plus basic Linux sysinfo collection
- Baseline & compare capability to detect configuration or state drift over time
- Export findings as JSON, Markdown, or a human-readable report for sharing
- Headless/CLI mode for automated triage and batch processing

Quick start (example):

```bash
cd EndpointGuard
python3 main.py
```

or run from the repository root:

```bash
python3 EndpointGuard/main.py
```

See [EndpointGuard/README.md](EndpointGuard/README.md) for full usage and developer notes.

## Why this repo?

This repo is for building practical SOC utilities that help analysts handle phishing, network threats, endpoints, SIEM ingestion, threat intelligence, forensics, and incident response. The goal is to keep tools lightweight, effective, and easy to use in real analyst workflows.

## Contributing

Contributions, ideas, and new tool suggestions are welcome. If you want to add a new SOC utility or expand an existing category, please open an issue or submit a pull request.

---

*Note: The exact number of tools is flexible and may grow over time. This repository is structured to evolve with new SOC tool categories as they are created.*
