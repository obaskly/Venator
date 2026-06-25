"""Non-destructive vulnerability detection modules.

Every check is detection/fingerprinting only — no exploitation, no data
modification. Findings flag candidates with a suggested *manual* next step.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Optional

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2,
                  "low": 3, "info": 4}


@dataclass
class Finding:
    title: str
    severity: str               # critical|high|medium|low|info
    category: str               # headers|tls|misconfig|cors|reflection|cve|nuclei|secret|takeover|exploit-intel
    target: str                 # url or host the finding applies to
    evidence: str               # what was observed
    recommendation: str         # suggested manual next step (NOT auto-exploit)
    confidence: str = "tentative"   # confirmed|firm|tentative
    # --- populated by the validation + scoring passes ---
    validated: Optional[bool] = None   # True=re-confirmed, False=looked like FP, None=not checked
    fp_note: str = ""                  # why it may be a false positive / how it was validated
    priority: int = 0                  # bounty-hunt priority score (higher = hunt first)
    poc: str = ""                      # copy-paste reproduction (e.g. a curl command)

    def to_dict(self) -> dict:
        return asdict(self)


def sort_findings(findings: List[Finding]) -> List[Finding]:
    # Highest priority first; ties broken by severity, then category/target.
    return sorted(findings,
                  key=lambda f: (-f.priority, SEVERITY_ORDER.get(f.severity, 9),
                                 f.category, f.target))
