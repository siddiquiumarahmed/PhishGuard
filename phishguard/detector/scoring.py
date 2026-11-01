"""Heuristic risk index.

The index is a bounded, rule-weighted sum of finding severities. It is **not**
a probability and has not been calibrated against real-world outcomes. It is
shown to help users compare scans; the verdict itself is decided by the
explicit precedence rules in :mod:`phishguard.detector.verdict_engine`.

    info = 0, low = 5, medium = 15, high = 35, critical = 60   (capped at 100)

Weights were chosen so that one critical or two high findings exceed 60, while
any number of low findings cannot exceed ~30 unless there are many of them.
"""

from __future__ import annotations

from collections.abc import Iterable

from phishguard.detector.rule_engine import Finding, Severity

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 35,
    Severity.CRITICAL: 60,
}

INDEX_LABEL = "Heuristic risk index"
INDEX_DISCLAIMER = (
    "A 0–100 indicator computed from rule severities. It is not a probability and has not been calibrated."
)


def heuristic_index(findings: Iterable[Finding]) -> int:
    total = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    return max(0, min(100, total))


def index_band(index: int) -> str:
    if index >= 60:
        return "high"
    if index >= 30:
        return "elevated"
    if index >= 10:
        return "low"
    return "minimal"
