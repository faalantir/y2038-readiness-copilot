from __future__ import annotations

import argparse
from pathlib import Path

from .reporter import write_ai_prompt, write_json, write_markdown
from .sarif import write_sarif
from .scanner import scan_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="y2038-scan",
        description="Scan a path for potential Year 2038 / timestamp-width risks.",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--out", default="reports/scan", help="Output directory for report.md/findings.json/results.sarif/ai_triage_prompt.md")
    parser.add_argument("--repo-name", default=None, help="Friendly repository/project name for the report")
    parser.add_argument("--max-findings", type=int, default=None, help="Stop after this many findings")
    parser.add_argument("--max-detail-findings", type=int, default=80, help="Number of detailed findings to include in Markdown")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    target = Path(args.path)
    out_dir = Path(args.out)
    findings = scan_path(target, repo_name=args.repo_name, max_findings=args.max_findings)

    write_json(findings, out_dir / "findings.json", repo_name=args.repo_name)
    write_markdown(findings, out_dir / "report.md", repo_name=args.repo_name, max_details=args.max_detail_findings)
    write_sarif(findings, out_dir / "results.sarif")
    write_ai_prompt(findings, out_dir / "ai_triage_prompt.md", repo_name=args.repo_name)

    high = sum(1 for f in findings if f.severity == "HIGH")
    med = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")
    info = sum(1 for f in findings if f.severity == "INFO")
    print(f"Scanned: {target}")
    print(f"Findings: {len(findings)}  HIGH={high} MEDIUM={med} LOW={low} INFO={info}")
    print(f"Report: {out_dir / 'report.md'}")
    print(f"JSON:   {out_dir / 'findings.json'}")
    print(f"SARIF:  {out_dir / 'results.sarif'}")
    print(f"Prompt: {out_dir / 'ai_triage_prompt.md'}")


if __name__ == "__main__":
    main()
