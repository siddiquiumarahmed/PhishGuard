"""Combines rule findings, reputation lookups and the ML estimate into a verdict.

Verdict precedence (first matching step wins)
---------------------------------------------
1. **Confirmed malicious** - at least one reputation provider returned a
   verified match.
2. **High risk** - a critical finding; or two or more high findings; or one
   high finding corroborated by a medium finding, an ML estimate above
   threshold, or an unverified reputation listing.
3. **Suspicious** - one high finding; or two or more medium findings; or an
   unverified reputation listing; or an ML estimate above threshold. The ML
   model on its own can never raise a verdict above Suspicious, and an ML
   "legitimate" estimate never lowers a rule-based verdict.
4. **Inconclusive** - nothing above applies, but a necessary method did not
   complete: the rule engine failed (fully or partially), a *configured*
   reputation provider failed, or ``require_reputation`` is enabled and no
   provider completed a lookup.
5. **No threat detected** - otherwise. The coverage actually achieved is
   always reported alongside it.

A provider ``NO_MATCH`` never lowers a verdict: not being listed is not
evidence of safety.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from phishguard.detector.explanations import GENERAL_LIMITATIONS, RECOMMENDATIONS, VERDICT_INFO, Verdict
from phishguard.detector.rule_engine import RuleEngineResult, Severity
from phishguard.detector.scoring import heuristic_index, index_band
from phishguard.intelligence.base import LookupStatus, ProviderResult
from phishguard.ml.predict import MLResult, MLStatus


@dataclass
class VerdictResult:
    verdict: Verdict
    label: str
    summary: str
    reasons: list[str]
    heuristic_index: int
    index_band: str
    decisive_methods: list[str]
    components: dict[str, object]
    limitations: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict.value,
            "label": self.label,
            "summary": self.summary,
            "reasons": self.reasons,
            "heuristic_index": self.heuristic_index,
            "index_band": self.index_band,
            "decisive_methods": self.decisive_methods,
            "components": self.components,
            "limitations": self.limitations,
            "recommendations": self.recommendations,
        }


def _reputation_component(results: list[ProviderResult]) -> dict[str, object]:
    configured = [r for r in results if r.status != LookupStatus.NOT_CONFIGURED]
    completed = [r for r in configured if r.status.completed]
    failed = [r for r in configured if r.status.failed]
    if not configured:
        status = "not_configured"
    elif failed and completed:
        status = "partial"
    elif failed:
        status = "failed"
    else:
        status = "ok"
    return {
        "status": status,
        "configured": len(configured),
        "completed": len(completed),
        "failed": len(failed),
        "providers": [r.to_dict() for r in results],
    }


def decide(
    rule_result: RuleEngineResult,
    provider_results: list[ProviderResult],
    ml_result: MLResult | None,
    *,
    require_reputation: bool = False,
) -> VerdictResult:
    findings = rule_result.findings
    n_crit = rule_result.count(Severity.CRITICAL)
    n_high = rule_result.count(Severity.HIGH)
    n_med = rule_result.count(Severity.MEDIUM)

    matches = [r for r in provider_results if r.status == LookupStatus.MATCH]
    unverified = [r for r in provider_results if r.status == LookupStatus.UNVERIFIED_LISTING]
    configured = [r for r in provider_results if r.status != LookupStatus.NOT_CONFIGURED]
    failed = [r for r in configured if r.status.failed]
    completed = [r for r in configured if r.status.completed]

    ml_ok = ml_result is not None and ml_result.status == MLStatus.OK
    ml_flag = bool(ml_ok and ml_result and ml_result.flagged)

    reasons: list[str] = []
    decisive: list[str] = []
    significant = [f for f in findings if f.severity.rank >= Severity.MEDIUM.rank]

    def add_rule_reasons() -> None:
        for f in significant[:6]:
            reasons.append(f"{f.title} ({f.severity.value})")
        if significant:
            decisive.append("rules")

    if matches:
        verdict = Verdict.CONFIRMED_MALICIOUS
        for r in matches:
            types = ", ".join(t.replace("_", " ").lower() for t in r.threat_types) or "malicious"
            reasons.append(f"{r.display_name} lists this URL ({types}).")
        decisive.append("threat_intelligence")
        add_rule_reasons()
    elif n_crit or n_high >= 2 or (n_high >= 1 and (n_med >= 1 or ml_flag or unverified)):
        verdict = Verdict.HIGH_RISK
        add_rule_reasons()
    elif n_high >= 1 or n_med >= 2 or unverified or ml_flag:
        verdict = Verdict.SUSPICIOUS
        add_rule_reasons()
    elif rule_result.status != "ok":
        verdict = Verdict.INCONCLUSIVE
        reasons.append("Some detection rules could not be evaluated, so the analysis is incomplete.")
    elif failed:
        verdict = Verdict.INCONCLUSIVE
        names = ", ".join(r.display_name for r in failed)
        reasons.append(f"Configured reputation check(s) could not be completed: {names}.")
    elif require_reputation and not completed:
        verdict = Verdict.INCONCLUSIVE
        reasons.append(
            "This installation requires a reputation check before reporting "
            "'no threat detected', and none was completed."
        )
    else:
        verdict = Verdict.NO_THREAT_DETECTED
        coverage = ["address-structure rules"]
        if completed:
            coverage.append(f"{len(completed)} reputation service(s)")
        if ml_ok:
            coverage.append("the machine-learning model")
        reasons.append(f"No significant indicators found by {', '.join(coverage)}.")
        minor = [f for f in findings if f.severity == Severity.LOW]
        if minor:
            reasons.append(f"{len(minor)} minor observation(s) were noted; none is significant on its own.")
        decisive.append("rules")

    if unverified and verdict != Verdict.CONFIRMED_MALICIOUS:
        for r in unverified:
            reasons.append(f"{r.display_name} has an unverified report for this URL.")
        decisive.append("threat_intelligence")
    if ml_flag and ml_result is not None and ml_result.score is not None:
        reasons.append(
            f"The machine-learning model's score ({ml_result.score:.2f}) is above its decision threshold "
            f"({ml_result.threshold:.2f}). This is an uncalibrated estimate, not proof."
        )
        decisive.append("machine_learning")
    if ml_ok and ml_result and not ml_result.flagged and verdict in (Verdict.SUSPICIOUS, Verdict.HIGH_RISK):
        reasons.append("The machine-learning model did not flag this URL; rule findings take precedence.")

    # Limitations specific to this scan.
    limitations = list(GENERAL_LIMITATIONS)
    if not configured:
        limitations.insert(
            0, "No threat-intelligence service is configured, so this URL was not checked against any blocklist."
        )
    elif not completed:
        limitations.insert(
            0, "The configured threat-intelligence lookups failed for this scan; their results are unknown, not clean."
        )
    elif failed:
        limitations.insert(0, "Some threat-intelligence lookups failed; their results are unknown, not clean.")
    if ml_result is None or ml_result.status != MLStatus.OK:
        limitations.append(
            "The machine-learning model was not used for this scan "
            f"({(ml_result.detail if ml_result else 'not configured')})."
        )

    index = heuristic_index(findings)
    info = VERDICT_INFO[verdict]
    components = {
        "rules": {
            "status": rule_result.status,
            "rules_evaluated": rule_result.rules_evaluated,
            "rule_errors": rule_result.rule_errors,
            "findings": len(findings),
        },
        "reputation": _reputation_component(provider_results),
        "ml": ml_result.to_dict() if ml_result else {"status": MLStatus.UNAVAILABLE.value, "detail": "not configured"},
    }
    return VerdictResult(
        verdict=verdict,
        label=info["label"],
        summary=info["summary"],
        reasons=reasons,
        heuristic_index=index,
        index_band=index_band(index),
        decisive_methods=sorted(set(decisive)),
        components=components,
        limitations=limitations,
        recommendations=list(RECOMMENDATIONS[verdict]),
    )
