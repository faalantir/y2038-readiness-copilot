from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, Any


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    confidence: float
    category: str
    path: str
    line: int
    evidence: str
    message: str
    rationale: str
    suggested_fix: str
    test_idea: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
