"""
Headless CLI: analyze one or more .eml files without launching the GUI.
Useful for SOC pipelines / batch triage / CI.
"""
import argparse
import sys

from .analyzers import EmailAnalysis, analyze_attachment, ScoreEngine
from .report import build_text_report, build_json_report, build_markdown_report


def analyze_file(path, defang=True, fmt="text"):
    analysis = EmailAnalysis(path)
    attachment_results = [analyze_attachment(att) for att in analysis.attachments]
    score_engine = ScoreEngine(analysis, attachment_results)
    if fmt == "json":
        return build_json_report(analysis, score_engine)
    if fmt == "markdown":
        return build_markdown_report(analysis, score_engine, defang=defang)
    return build_text_report(analysis, score_engine, defang=defang)


def main():
    parser = argparse.ArgumentParser(description="PhishTinker CLI — headless .eml triage")
    parser.add_argument("files", nargs="+", help="One or more .eml files to analyze")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    parser.add_argument("--no-defang", action="store_true", help="Do not defang IOCs in output")
    parser.add_argument("-o", "--output", help="Write output to file instead of stdout (single file only)")
    args = parser.parse_args()

    outputs = []
    for path in args.files:
        try:
            outputs.append(analyze_file(path, defang=not args.no_defang, fmt=args.format))
        except Exception as e:
            print(f"[!] Failed to analyze {path}: {e}", file=sys.stderr)

    joined = "\n\n".join(outputs)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(joined)
    else:
        print(joined)


if __name__ == "__main__":
    main()
