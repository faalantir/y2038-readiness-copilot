#!/usr/bin/env python3
"""Render a screenshot-friendly, curated Y2038 public-repo scan view.

This is a presentation layer over existing reports/*/findings.json files.
It intentionally avoids claiming vulnerabilities. It separates:
  - raw static-analysis matches
  - curated review examples
  - needs-context candidates
  - test/fixture hits
  - likely naming noise
  - platform/control context

The goal is a clean one-screenshot view for an engineering scan summary.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

ABSOLUTE_TIME_TERMS = re.compile(
    r"(?:epoch|unix|timestamp|time_t|expires|expiry|expiration|expire|last_seen|lastseen|"
    r"boot_time|event_time|created_at|updated_at|deleted_at|not_after|valid_until|"
    r"certificate_expiry|session_expiry|expires_at|expiry_at|start_time|end_time|"
    r"time\.msg|\bsec\b)",
    re.I,
)

DURATION_OR_COUNTER_TERMS = re.compile(
    r"(?:_ms\b|\bms\b|millis|millisecond|duration|interval|delay|elapsed|sleep|poll|"
    r"timeout|timer_cancel|counter|_count\b|count_|update_count|repeat|self_check|"
    r"protect_time|trigger_.*_time_ms|timezone|offset)",
    re.I,
)

GENERIC_NOISE_TERMS = re.compile(
    r"(?:\bupdate\b|_update\b|update_|\bvalidate\b|_validate\b|validate_|"
    r"utf8|base64|cipher|mac_|_mac|hash|zip_|\bcheck\b|check_|_check|"
    r"_cb\b|callback|aux)",
    re.I,
)

TEST_PATH_RE = re.compile(r"(^|/)(test|tests|fixture|fixtures|examples?)(/|$)", re.I)

CONTROL_RULES = {
    "BUILD-TIME64-FLAG-PRESENT",
    "BUILD-FILE-OFFSET64-FLAG-PRESENT",
    "BUILD-32BIT-TARGET-CONTEXT",
    "C-LIKE-TIME-T-CONTEXT-CHECK",
}

CURATED_RULES = {
    "MSG-IDL-32BIT-TIME-FIELD",
    "C-LIKE-TIME-TO-32BIT-ASSIGNMENT",
    "C-LIKE-EXPLICIT-TIME-CAST",
    "C-LIKE-SERIALIZED-TIME-T-SIZEOF",
    "SQL-INT-TIMESTAMP-COLUMN",
    "PROTO-32BIT-TIME-FIELD",
    "JSON-YAML-32BIT-TIME-SCHEMA",
    "MANIFEST-32BIT-LONG-LIVED-DEVICE",
}

SIGNAL_LABELS = {
    "MSG-IDL-32BIT-TIME-FIELD": "public message/interface",
    "PROTO-32BIT-TIME-FIELD": "API/wire schema",
    "JSON-YAML-32BIT-TIME-SCHEMA": "API/schema contract",
    "SQL-INT-TIMESTAMP-COLUMN": "database timestamp field",
    "C-LIKE-TIME-TO-32BIT-ASSIGNMENT": "time_t narrowing assignment",
    "C-LIKE-EXPLICIT-TIME-CAST": "explicit time cast",
    "C-LIKE-SERIALIZED-TIME-T-SIZEOF": "binary time_t persistence",
    "MANIFEST-32BIT-LONG-LIVED-DEVICE": "long-lived 32-bit target",
    "BUILD-TIME64-FLAG-PRESENT": "time64 build control",
    "BUILD-FILE-OFFSET64-FLAG-PRESENT": "file-offset64 build control",
    "BUILD-32BIT-TARGET-CONTEXT": "32-bit target context",
    "C-LIKE-TIME-T-CONTEXT-CHECK": "platform time_t context",
    "C-LIKE-32BIT-TIME-NAMED-FIELD": "named 32-bit time field",
}

WHY_REVIEW = {
    "MSG-IDL-32BIT-TIME-FIELD": "public contract width",
    "PROTO-32BIT-TIME-FIELD": "wire-format compatibility",
    "JSON-YAML-32BIT-TIME-SCHEMA": "API clients may inherit width limit",
    "SQL-INT-TIMESTAMP-COLUMN": "storage range / sort / expiry logic",
    "C-LIKE-TIME-TO-32BIT-ASSIGNMENT": "possible truncation of time_t",
    "C-LIKE-EXPLICIT-TIME-CAST": "possible narrowing cast",
    "C-LIKE-SERIALIZED-TIME-T-SIZEOF": "on-disk/on-wire width may change",
    "MANIFEST-32BIT-LONG-LIVED-DEVICE": "platform lifecycle context",
    "C-LIKE-32BIT-TIME-NAMED-FIELD": "name suggests epoch/expiry time",
}


def load_findings(reports_dir: Path, include_sample: bool = False) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for json_path in sorted(reports_dir.glob("*/findings.json")):
        repo = json_path.parent.name
        if repo == "sample" and not include_sample:
            continue
        try:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"Skipping {json_path}: {exc}")
            continue
        repo_name = payload.get("repo_name") or repo
        for item in payload.get("findings", []):
            f = dict(item)
            f["repo"] = repo_name
            findings.append(f)
    return findings


def blob(f: Dict[str, Any]) -> str:
    return " ".join(str(f.get(k, "")) for k in ("repo", "path", "evidence", "message", "rule_id", "category")).lower()


def identifier(f: Dict[str, Any]) -> str:
    msg = str(f.get("message", ""))
    m = re.search(r"`([^`]+)`", msg)
    return m.group(1).lower() if m else ""


def path_is_test(path: str) -> bool:
    return bool(TEST_PATH_RE.search(path.replace("\\", "/")))


def classify(f: Dict[str, Any], include_tests_as_examples: bool = False) -> Tuple[str, str]:
    """Return bucket and reason.

    Buckets:
      curated: high-signal example suitable for screenshot
      context: platform/control context
      triage: needs dataflow/manual review
      noise: likely name collision or duration/counter
      test: inside test/fixture/example path
    """
    rule = str(f.get("rule_id", ""))
    path = str(f.get("path", ""))
    text = blob(f)
    name = identifier(f)

    if rule in CONTROL_RULES or str(f.get("severity", "")) == "INFO":
        return "context", "platform/control context"

    if path_is_test(path) and not include_tests_as_examples:
        return "test", "test/fixture/example path"

    if rule == "C-LIKE-32BIT-TIME-NAMED-FIELD":
        # This rule is useful but noisy; only promote clear absolute timestamp-like names.
        if DURATION_OR_COUNTER_TERMS.search(name) or (GENERIC_NOISE_TERMS.search(name) and not ABSOLUTE_TIME_TERMS.search(name)):
            return "noise", "likely naming collision or duration/counter"
        if ABSOLUTE_TIME_TERMS.search(name):
            # Function names still need dataflow unless the name is very explicit.
            if "function return/name" in text and not re.search(r"(?:epoch|timestamp|expiry|expires|expire|session_expiry|certificate_expiry|last_seen|get_time)", name, re.I):
                return "triage", "function-name context needed"
            return "curated", "absolute timestamp-like name"
        if "time" in name:
            return "triage", "generic time-like name"
        return "noise", "weak timestamp signal"

    if rule in {"MSG-IDL-32BIT-TIME-FIELD", "C-LIKE-TIME-TO-32BIT-ASSIGNMENT", "C-LIKE-SERIALIZED-TIME-T-SIZEOF", "MANIFEST-32BIT-LONG-LIVED-DEVICE"}:
        return "curated", "concrete timestamp-width pattern"

    if rule == "C-LIKE-EXPLICIT-TIME-CAST":
        return "curated", "explicit cast involving time-like expression"

    if rule in {"PROTO-32BIT-TIME-FIELD", "JSON-YAML-32BIT-TIME-SCHEMA", "SQL-INT-TIMESTAMP-COLUMN"}:
        if ABSOLUTE_TIME_TERMS.search(text):
            return "curated", "schema/storage field has timestamp-like semantics"
        return "triage", "schema context needed"

    if rule in CURATED_RULES:
        return "triage", "rule matched but context needed"

    if DURATION_OR_COUNTER_TERMS.search(text) or (GENERIC_NOISE_TERMS.search(text) and not ABSOLUTE_TIME_TERMS.search(text)):
        return "noise", "likely naming collision or duration/counter"
    return "triage", "context needed"


def signal_label(f: Dict[str, Any]) -> str:
    return SIGNAL_LABELS.get(str(f.get("rule_id", "")), str(f.get("category", "unknown")))


def why_review(f: Dict[str, Any]) -> str:
    return WHY_REVIEW.get(str(f.get("rule_id", "")), "needs dataflow/platform validation")


def rank_key(f: Dict[str, Any]) -> Tuple[int, int, float, str, str]:
    # Prefer public contracts, narrowing, persistence, storage/schema, then named-field examples.
    rule_priority = {
        "MSG-IDL-32BIT-TIME-FIELD": 0,
        "C-LIKE-TIME-TO-32BIT-ASSIGNMENT": 1,
        "C-LIKE-EXPLICIT-TIME-CAST": 2,
        "C-LIKE-SERIALIZED-TIME-T-SIZEOF": 3,
        "SQL-INT-TIMESTAMP-COLUMN": 4,
        "PROTO-32BIT-TIME-FIELD": 5,
        "JSON-YAML-32BIT-TIME-SCHEMA": 6,
        "MANIFEST-32BIT-LONG-LIVED-DEVICE": 7,
        "C-LIKE-32BIT-TIME-NAMED-FIELD": 8,
    }.get(str(f.get("rule_id", "")), 20)
    return (rule_priority, SEV_ORDER.get(str(f.get("severity", "LOW")), 99), -float(f.get("confidence", 0)), str(f.get("repo", "")), str(f.get("path", "")))


def clean_location(path: str, line: Any, max_len: int) -> str:
    loc = f"{path}:{line}"
    if len(loc) <= max_len:
        return loc
    return "…" + loc[-(max_len - 1):]


def table(headers: List[str], rows: List[List[Any]], max_width: int = 120) -> str:
    rows_s = [[str(c) for c in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in rows_s:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    total = sum(widths) + 3 * (len(widths) - 1) + 4
    if total > max_width and widths:
        overflow = total - max_width
        widths[-1] = max(18, widths[-1] - overflow)
    def trunc(s: str, w: int) -> str:
        return s if len(s) <= w else s[: max(0, w - 1)] + "…"
    def fmt(row: List[str]) -> str:
        return "| " + " | ".join(trunc(row[i], widths[i]).ljust(widths[i]) for i in range(len(widths))) + " |"
    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    out = [sep, fmt(headers), sep]
    for row in rows_s:
        out.append(fmt(row))
    out.append(sep)
    return "\n".join(out)


def select_examples(items: List[Dict[str, Any]], max_items: int) -> List[Dict[str, Any]]:
    # Keep the screenshot diverse: at most two per repo and two per signal.
    selected: List[Dict[str, Any]] = []
    by_repo: Counter[str] = Counter()
    by_signal: Counter[str] = Counter()
    for f in sorted(items, key=rank_key):
        sig = signal_label(f)
        repo = str(f.get("repo", ""))
        if by_repo[repo] >= 3:
            continue
        if by_signal[sig] >= 2:
            continue
        selected.append(f)
        by_repo[repo] += 1
        by_signal[sig] += 1
        if len(selected) >= max_items:
            break
    # If diversity rules were too strict, fill remaining slots.
    if len(selected) < max_items:
        seen = {(str(f.get("repo")), str(f.get("path")), str(f.get("line")), str(f.get("rule_id"))) for f in selected}
        for f in sorted(items, key=rank_key):
            key = (str(f.get("repo")), str(f.get("path")), str(f.get("line")), str(f.get("rule_id")))
            if key not in seen:
                selected.append(f)
                seen.add(key)
                if len(selected) >= max_items:
                    break
    return selected


def render(findings: List[Dict[str, Any]], max_items: int, width: int, include_tests_as_examples: bool = False) -> str:
    classified: List[Dict[str, Any]] = []
    for item in findings:
        bucket, reason = classify(item, include_tests_as_examples=include_tests_as_examples)
        f = dict(item)
        f["bucket"] = bucket
        f["bucket_reason"] = reason
        f["signal"] = signal_label(f)
        f["why"] = why_review(f)
        classified.append(f)

    repos = sorted({str(f["repo"]) for f in classified})
    counts = Counter(f["bucket"] for f in classified)
    curated = [f for f in classified if f["bucket"] == "curated"]
    triage = [f for f in classified if f["bucket"] == "triage"]

    lines: List[str] = []
    lines.append("Y2038 Readiness Copilot — Public Repo Scan, Curated View")
    lines.append("=" * 64)
    lines.append("Static-analysis candidates only. No vulnerabilities are claimed from this view.")
    lines.append("")
    lines.append(
        f"Repos: {len(repos)}  |  Raw matches: {len(classified)}  |  Curated review examples: {len(curated)}  |  "
        f"Needs context: {len(triage)}  |  Test/fixture hits: {counts.get('test', 0)}  |  "
        f"Likely naming noise: {counts.get('noise', 0)}  |  Controls/context: {counts.get('context', 0)}"
    )
    lines.append("")

    by_repo: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for f in classified:
        by_repo[str(f["repo"])].append(f)

    repo_rows: List[List[Any]] = []
    for repo in repos:
        items = by_repo[repo]
        rc = Counter(f["bucket"] for f in items)
        sigs = Counter(f["signal"] for f in items if f["bucket"] == "curated")
        main = sigs.most_common(1)[0][0] if sigs else "—"
        repo_rows.append([repo, len(items), rc.get("curated", 0), rc.get("triage", 0), rc.get("noise", 0), rc.get("test", 0), main])
    lines.append(table(["Repo", "Raw", "Curated", "Triage", "Noise", "Test", "Main curated signal"], repo_rows, max_width=width))
    lines.append("")

    examples = select_examples(curated, max_items=max_items)
    ex_rows: List[List[Any]] = []
    loc_width = max(38, width - 92)
    for idx, f in enumerate(examples, start=1):
        ex_rows.append([
            idx,
            f.get("repo", ""),
            f.get("signal", ""),
            clean_location(str(f.get("path", "")), f.get("line", ""), max_len=loc_width),
            f.get("why", ""),
        ])
    lines.append("Curated review examples")
    if ex_rows:
        lines.append(table(["#", "Repo", "Signal", "Location", "Why review"], ex_rows, max_width=width))
    else:
        lines.append("No curated examples selected. Re-check scanner inputs or include --include-sample.")
    lines.append("")

    sig_counts = Counter(f["signal"] for f in curated)
    sig_rows = [[sig, count] for sig, count in sig_counts.most_common(8)]
    lines.append("Curated signal mix")
    lines.append(table(["Signal", "Count"], sig_rows, max_width=min(width, 84)))
    lines.append("")

    lines.append("Interpretation: this is an engineering review queue, not a vulnerability list.")
    lines.append("Next validation: inspect dataflow, confirm target time_t width, then run post-2038 tests.")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports", default="reports", help="reports directory containing */findings.json")
    parser.add_argument("--max-items", type=int, default=8)
    parser.add_argument("--width", type=int, default=120)
    parser.add_argument("--include-sample", action="store_true", help="include reports/sample/findings.json")
    parser.add_argument("--include-tests", action="store_true", help="allow test/fixture/example paths in curated examples")
    parser.add_argument("--out", help="optional output text file")
    args = parser.parse_args()

    width = args.width or shutil.get_terminal_size((120, 30)).columns
    findings = load_findings(Path(args.reports), include_sample=args.include_sample)
    text = render(findings, max_items=args.max_items, width=width, include_tests_as_examples=args.include_tests)
    print(text)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
