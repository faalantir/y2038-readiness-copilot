from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .models import Finding
from .reporter import sort_findings

LEVEL_MAP = {
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}


def write_sarif(findings: List[Finding], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sort_findings(findings)
    rules = {}
    for f in ordered:
        rules.setdefault(
            f.rule_id,
            {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.category},
                "fullDescription": {"text": f.rationale},
                "help": {"text": f.suggested_fix},
                "properties": {"category": f.category},
            },
        )

    results = []
    for f in ordered:
        results.append(
            {
                "ruleId": f.rule_id,
                "level": LEVEL_MAP.get(f.severity, "warning"),
                "message": {"text": f"{f.message} Evidence: {f.evidence}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path.replace("\\", "/")},
                            "region": {"startLine": max(1, int(f.line))},
                        }
                    }
                ],
                "properties": {
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "category": f.category,
                    "test_idea": f.test_idea,
                    "suggested_fix": f.suggested_fix,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Y2038 Readiness Copilot",
                        "semanticVersion": "0.1.0",
                        "informationUri": "https://github.com/your-username/y2038-readiness-copilot",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
