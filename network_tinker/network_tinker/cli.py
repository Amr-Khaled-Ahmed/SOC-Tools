"""Headless terminal mode -- for when you just want a quick triage from the
shell without spinning up the GUI (fits Amr's terminal-first workflow).

Usage:
    python -m network_tinker.cli capture.pcap
    python -m network_tinker.cli capture.pcap --report out.md
    python -m network_tinker.cli capture.pcap --json out.json
    python -m network_tinker.cli capture.pcap --grep "pass|login"
    python -m network_tinker.cli capture.pcap --carve ./carved_out/
"""

import argparse
import re
import sys

from .core.analysis import PcapAnalysis
from .core import exporter


def main(argv=None):
    parser = argparse.ArgumentParser(prog="network_tinker", description="Headless PCAP triage")
    parser.add_argument("pcap", help="Path to .pcap/.pcapng file")
    parser.add_argument("--report", metavar="FILE", help="Write Markdown report to FILE")
    parser.add_argument("--json", metavar="FILE", help="Write JSON summary to FILE")
    parser.add_argument("--grep", metavar="PATTERN", help="Regex search across all payloads")
    parser.add_argument("--carve", metavar="DIR", help="Carve transferred files into DIR")
    parser.add_argument("--quiet", action="store_true", help="Suppress the console summary")
    args = parser.parse_args(argv)

    print(f"[*] Loading {args.pcap} ...")
    analysis = PcapAnalysis(args.pcap)
    analysis.load(progress_cb=lambda i, t: print(f"\r[*] Parsing {i}/{t}", end="", flush=True))
    print()

    if not args.quiet:
        _print_summary(analysis)

    if args.grep:
        _do_grep(analysis, args.grep)

    if args.carve:
        import os
        os.makedirs(args.carve, exist_ok=True)
        for i, f in enumerate(analysis.carved_files):
            path = analysis.export_carved_file(i, args.carve)
            print(f"[+] carved: {path}  ({f['signature']}, sha256={f['sha256'][:16]}...)")

    if args.report:
        exporter.export_markdown(analysis, args.report)
        print(f"[+] Markdown report written to {args.report}")

    if args.json:
        exporter.export_json(analysis, args.json)
        print(f"[+] JSON summary written to {args.json}")


def _print_summary(analysis):
    a = analysis
    print(f"\n=== {a.path} ===")
    print(f"Total packets : {a.total}")
    print(f"Duration      : {a.duration():.2f}s")
    print(f"TCP streams   : {len(a.streams)}")
    print(f"Files carved  : {len(a.carved_files)}")
    print(f"IOCs found    : {len(a.iocs)}  "
          f"(high={sum(1 for i in a.iocs if i['risk']=='high')}, "
          f"med={sum(1 for i in a.iocs if i['risk']=='med')}, "
          f"low={sum(1 for i in a.iocs if i['risk']=='low')})")

    print("\n--- Protocol breakdown ---")
    for proto, count in a.proto_counts.most_common():
        print(f"  {proto:6s} {count}")

    print("\n--- Top 10 talkers ---")
    for (src, dst), count in a.top_talkers(10):
        print(f"  {src:16s} -> {dst:16s}  {count} pkts  {a.talker_bytes[(src,dst)]:,} bytes")

    if a.dns_stats():
        print("\n--- Top 10 DNS queries ---")
        for domain, count in a.dns_stats()[:10]:
            print(f"  {domain:40s} {count}")

    high_iocs = [i for i in a.iocs if i["risk"] == "high"]
    if high_iocs:
        print(f"\n--- HIGH RISK IOCs ({len(high_iocs)}) ---")
        for ioc in high_iocs:
            print(f"  [!] {ioc['kind']}: {str(ioc['detail'])[:100]}  (pkt #{ioc['packet_no']})")


def _do_grep(analysis, pattern):
    try:
        rx = re.compile(pattern.encode(), re.I)
    except re.error as e:
        print(f"[!] bad regex: {e}", file=sys.stderr)
        return
    print(f"\n--- grep '{pattern}' ---")
    hits = 0
    for rec in analysis.packets:
        if rec.raw_payload and rx.search(rec.raw_payload):
            m = rx.search(rec.raw_payload)
            snippet = rec.raw_payload[max(0, m.start() - 20):m.end() + 30]
            text = snippet.decode(errors="replace").replace("\r", " ").replace("\n", " ")
            print(f"  #{rec.no:<6} {rec.src:16s} -> {rec.dst:16s}  {text[:100]}")
            hits += 1
    print(f"  ({hits} matches)")


if __name__ == "__main__":
    main()
