"""Turns a PcapAnalysis into shareable artifacts: an Obsidian-ready
Markdown report, raw JSON, or a CSV of packets/IOCs."""

import os
import csv
import json
import datetime

from .analysis import defang


def export_markdown(analysis, path, snort_rules=None):
    a = analysis
    lines = [f"# PCAP Report — {os.path.basename(a.path)}", "",
             f"Generated: {datetime.datetime.now()}", "",
             "## Summary", "",
             f"- Total packets: {a.total}",
             f"- Duration: {a.duration():.2f}s",
             f"- Unique source IPs: {len({s for s, d in a.talkers})}",
             f"- Unique destination IPs: {len({d for s, d in a.talkers})}",
             f"- TCP streams reconstructed: {len(a.streams)}",
             f"- Files carved: {len(a.carved_files)}",
             f"- IOCs found: {len(a.iocs)} (high: {sum(1 for i in a.iocs if i['risk']=='high')})",
             "", "## Protocol breakdown", ""]
    for proto, count in a.proto_counts.most_common():
        lines.append(f"- {proto}: {count}")

    lines += ["", "## Top talkers", "", "| Src | Dst | Packets | Bytes |", "|---|---|---|---|"]
    for (src, dst), count in a.top_talkers(20):
        lines.append(f"| {defang(src)} | {defang(dst)} | {count} | {a.talker_bytes[(src,dst)]:,} |")

    if a.dns_stats():
        lines += ["", "## DNS queries (top 20)", "", "| Domain | Count |", "|---|---|"]
        for domain, count in a.dns_stats()[:20]:
            lines.append(f"| {defang(domain)} | {count} |")

    if a.carved_files:
        lines += ["", "## Carved / transferred files", "",
                  "| Name | Signature | SHA256 | Size | Stream |", "|---|---|---|---|---|"]
        for f in a.carved_files:
            lines.append(f"| {f['name']} | {f['signature']} | `{f['sha256']}` | "
                        f"{f['size']:,} | #{f['stream_id']} |")

    lines += ["", "## IOC findings", "", "| Risk | Kind | Detail | Count | Packet# |",
              "|---|---|---|---|---|"]
    for ioc in sorted(a.iocs, key=lambda x: {"high": 0, "med": 1, "low": 2}.get(x["risk"], 3)):
        detail = defang(str(ioc["detail"])).replace("|", "\\|")
        lines.append(f"| {ioc['risk'].upper()} | {ioc['kind']} | {detail} | "
                    f"{ioc.get('count',1)} | {ioc['packet_no']} |")

    if snort_rules:
        lines += ["", "## Generated Snort rules", "", "```"]
        lines += snort_rules
        lines += ["```"]

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def export_json(analysis, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(analysis.to_session_dict(), f, indent=2)
    return path


def export_packets_csv(analysis, path, packets=None):
    rows = packets if packets is not None else analysis.packets
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["no", "time", "src", "dst", "sport", "dport", "proto", "length", "flags", "info"])
        for rec in rows:
            w.writerow([rec.no, rec.time, rec.src, rec.dst, rec.sport, rec.dport,
                       rec.proto, rec.length, rec.flags, rec.info])
    return path


def export_iocs_csv(analysis, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["risk", "kind", "detail", "count", "packet_no", "src", "dst"])
        for ioc in analysis.iocs:
            w.writerow([ioc["risk"], ioc["kind"], ioc["detail"], ioc.get("count", 1),
                       ioc["packet_no"], ioc.get("src", ""), ioc.get("dst", "")])
    return path
