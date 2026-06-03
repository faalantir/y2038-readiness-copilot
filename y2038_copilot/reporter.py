from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, List

from .models import Finding

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def sort_findings(findings: Iterable[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.confidence, f.path, f.line))


def write_json(findings: List[Finding], output_path: Path, repo_name: str | None = None) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "tool": "Y2038 Readiness Copilot",
        "repo_name": repo_name,
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_markdown(findings: List[Finding], output_path: Path, repo_name: str | None = None, max_details: int = 80) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sort_findings(findings)
    severity_counts = Counter(f.severity for f in ordered)
    category_counts = Counter(f.category for f in ordered)

    title = f"Y2038 Readiness Scan Report: {repo_name}" if repo_name else "Y2038 Readiness Scan Report"
    lines: list[str] = []
    lines.append(f"# {title}\n")
    lines.append("> This report lists **potential timestamp-width risks** identified by static rules. Findings require human review before treating them as confirmed vulnerabilities.\n")
    lines.append("## Executive summary\n")
    lines.append(f"- Total findings: **{len(ordered)}**")
    for sev in ["HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"- {sev.title()}: **{severity_counts.get(sev, 0)}**")
    lines.append("")

    if ordered:
        lines.append("## Top categories\n")
        for category, count in category_counts.most_common(8):
            lines.append(f"- {category}: **{count}**")
        lines.append("")

        lines.append("## Top findings\n")
        lines.append("| Severity | Confidence | File | Line | Rule | Message |")
        lines.append("|---|---:|---|---:|---|---|")
        for f in ordered[:30]:
            safe_msg = f.message.replace("|", "\\|")
            lines.append(f"| {f.severity} | {f.confidence:.2f} | `{f.path}` | {f.line} | `{f.rule_id}` | {safe_msg} |")
        lines.append("")

        lines.append("## Detailed review queue\n")
        for i, f in enumerate(ordered[:max_details], start=1):
            lines.append(f"### {i}. {f.severity} / {f.confidence:.2f} — `{f.rule_id}`")
            lines.append(f"- Location: `{f.path}:{f.line}`")
            lines.append(f"- Evidence: `{f.evidence}`")
            lines.append(f"- Message: {f.message}")
            lines.append(f"- Why it matters: {f.rationale}")
            lines.append(f"- Suggested fix: {f.suggested_fix}")
            lines.append(f"- Test idea: {f.test_idea}")
            lines.append("")
    else:
        lines.append("No findings were detected with the current rule set. This does not prove the project is Y2038-safe; it only means no matching patterns were found.\n")

    lines.append("## Review notes\n")
    lines.append("This report is an input to engineering review. It does not confirm vulnerabilities by itself. Use the findings to decide where dataflow checks, platform validation, compatibility review, and future-date tests are needed.\n")
    output_path.write_text("\n".join(lines), encoding="utf-8")


def write_ai_prompt(findings: List[Finding], output_path: Path, repo_name: str | None = None, limit: int = 12) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sort_findings(findings)[:limit]
    compact = [
        {
            "rule_id": f.rule_id,
            "severity": f.severity,
            "confidence": f.confidence,
            "category": f.category,
            "location": f"{f.path}:{f.line}",
            "evidence": f.evidence,
            "message": f.message,
        }
        for f in ordered
    ]
    prompt = f"""You are a cautious application-security and embedded-systems reviewer.

Review these potential Year 2038 / timestamp-width findings from the repository: {repo_name or "unknown"}.

Important behaviour:
- Do not claim a finding is a confirmed vulnerability unless the evidence proves it.
- Classify each item as: likely real risk, needs context, likely false positive, or positive control.
- Explain why in plain English.
- Suggest exactly one next validation step and one remediation path for each likely/needs-context item.
- Produce a short engineering summary at the end.

Findings JSON:
```json
{json.dumps(compact, indent=2)}
```
"""
    output_path.write_text(prompt, encoding="utf-8")


def write_summary_from_json(json_paths: list[Path], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    combined_findings = []
    for path in json_paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        findings = data.get("findings", [])
        counts = Counter(f.get("severity", "UNKNOWN") for f in findings)
        rows.append({
            "repo": data.get("repo_name") or path.parent.name,
            "total": len(findings),
            "high": counts.get("HIGH", 0),
            "medium": counts.get("MEDIUM", 0),
            "low": counts.get("LOW", 0),
            "info": counts.get("INFO", 0),
        })
        for f in findings:
            f["repo"] = data.get("repo_name") or path.parent.name
            combined_findings.append(f)

    lines = ["# Public Repo Scan Summary — Y2038 Timestamp-Risk Experiment\n"]
    lines.append("> These are potential findings generated by static rules and require human review before being treated as confirmed issues.\n")
    lines.append("| Repo | Total | High | Medium | Low | Info |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for row in rows:
        lines.append(f"| `{row['repo']}` | {row['total']} | {row['high']} | {row['medium']} | {row['low']} | {row['info']} |")
    lines.append("")

    by_category = Counter(f.get("category", "unknown") for f in combined_findings)
    lines.append("## Finding categories across scanned repos\n")
    for category, count in by_category.most_common(10):
        lines.append(f"- {category}: **{count}**")
    lines.append("")

    top = sorted(combined_findings, key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "LOW"), 99), -float(f.get("confidence", 0))))[:20]
    lines.append("## Top cross-repo review queue\n")
    lines.append("| Severity | Confidence | Repo | Location | Message |")
    lines.append("|---|---:|---|---|---|")
    for f in top:
        location = f"{f.get('path')}:{f.get('line')}"
        msg = str(f.get("message", "")).replace("|", "\\|")
        lines.append(f"| {f.get('severity')} | {float(f.get('confidence', 0)):.2f} | `{f.get('repo')}` | `{location}` | {msg} |")
    lines.append("")
    lines.append("## Review notes\n")
    lines.append("> This summary lists potential Year 2038 timestamp-width review items from open-source repositories. Findings should be validated with dataflow, platform, and runtime context before being treated as confirmed issues.\n")
    output_path.write_text("\n".join(lines), encoding="utf-8")
