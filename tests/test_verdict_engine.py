import pytest

from phishguard.detector.explanations import Verdict
from phishguard.detector.rule_engine import Finding, RuleEngineResult, Severity, evaluate
from phishguard.detector.scoring import heuristic_index, index_band
from phishguard.detector.url_features import extract_features
from phishguard.detector.url_parser import parse_url
from phishguard.detector.verdict_engine import decide
from phishguard.intelligence.base import LookupStatus, ProviderResult
from phishguard.ml.predict import MLResult, MLStatus
from tests.fixtures_urls import BENIGN_URLS, MALICIOUS_URLS, at_least

NO_ML = MLResult(MLStatus.UNAVAILABLE, detail="no trained model found")


def findings(*severities):
    return RuleEngineResult(
        findings=[Finding(f"PG-T-{i}", f"t{i}", s, "e") for i, s in enumerate(severities)],
        rules_evaluated=10,
    )


def provider(status, types=None, name="Test Provider"):
    return ProviderResult("test", name, status, types or [])


def ml(score, threshold=0.5):
    return MLResult(MLStatus.OK, score=score, threshold=threshold, flagged=score >= threshold, model_version="m1")


class TestPrecedence:
    def test_verified_match_is_confirmed_even_without_findings(self):
        v = decide(findings(), [provider(LookupStatus.MATCH, ["SOCIAL_ENGINEERING"])], NO_ML)
        assert v.verdict == Verdict.CONFIRMED_MALICIOUS
        assert "threat_intelligence" in v.decisive_methods

    def test_match_beats_ml_saying_legitimate(self):
        v = decide(findings(), [provider(LookupStatus.MATCH, ["MALWARE"])], ml(0.01))
        assert v.verdict == Verdict.CONFIRMED_MALICIOUS

    @pytest.mark.parametrize(
        ("sev", "expected"),
        [
            ((Severity.CRITICAL,), Verdict.HIGH_RISK),
            ((Severity.HIGH, Severity.HIGH), Verdict.HIGH_RISK),
            ((Severity.HIGH, Severity.MEDIUM), Verdict.HIGH_RISK),
            ((Severity.HIGH,), Verdict.SUSPICIOUS),
            ((Severity.HIGH, Severity.LOW, Severity.LOW), Verdict.SUSPICIOUS),
            ((Severity.MEDIUM, Severity.MEDIUM), Verdict.SUSPICIOUS),
            ((Severity.MEDIUM,), Verdict.NO_THREAT_DETECTED),
            ((Severity.LOW, Severity.LOW, Severity.LOW), Verdict.NO_THREAT_DETECTED),
            ((), Verdict.NO_THREAT_DETECTED),
        ],
    )
    def test_rule_thresholds(self, sev, expected):
        assert decide(findings(*sev), [], NO_ML).verdict == expected

    def test_ml_alone_can_only_reach_suspicious(self):
        assert decide(findings(), [], ml(0.99)).verdict == Verdict.SUSPICIOUS

    def test_ml_corroborates_high_finding(self):
        assert decide(findings(Severity.HIGH), [], ml(0.9)).verdict == Verdict.HIGH_RISK

    def test_ml_legitimate_never_downgrades_rules(self):
        v = decide(findings(Severity.CRITICAL), [], ml(0.01))
        assert v.verdict == Verdict.HIGH_RISK
        assert any("did not flag" in r for r in v.reasons)

    def test_unverified_listing_is_suspicious_not_confirmed(self):
        v = decide(findings(), [provider(LookupStatus.UNVERIFIED_LISTING, ["PHISHING"])], NO_ML)
        assert v.verdict == Verdict.SUSPICIOUS
        v2 = decide(findings(Severity.HIGH), [provider(LookupStatus.UNVERIFIED_LISTING)], NO_ML)
        assert v2.verdict == Verdict.HIGH_RISK


class TestMissingDataIsNotNegative:
    @pytest.mark.parametrize(
        "status",
        [
            LookupStatus.TIMEOUT,
            LookupStatus.ERROR,
            LookupStatus.QUOTA_EXCEEDED,
            LookupStatus.AUTH_ERROR,
            LookupStatus.MALFORMED_RESPONSE,
        ],
    )
    def test_failed_configured_provider_makes_clean_result_inconclusive(self, status):
        v = decide(findings(), [provider(status)], NO_ML)
        assert v.verdict == Verdict.INCONCLUSIVE
        assert v.components["reputation"]["status"] == "failed"

    def test_failed_provider_does_not_hide_rule_findings(self):
        v = decide(findings(Severity.HIGH), [provider(LookupStatus.TIMEOUT)], NO_ML)
        assert v.verdict == Verdict.SUSPICIOUS
        assert any("failed" in lim for lim in v.limitations)

    def test_not_configured_is_not_a_failure(self):
        v = decide(findings(), [provider(LookupStatus.NOT_CONFIGURED)], NO_ML)
        assert v.verdict == Verdict.NO_THREAT_DETECTED
        assert v.components["reputation"]["status"] == "not_configured"
        assert any("No threat-intelligence service is configured" in lim for lim in v.limitations)

    def test_require_reputation_option(self):
        v = decide(findings(), [provider(LookupStatus.NOT_CONFIGURED)], NO_ML, require_reputation=True)
        assert v.verdict == Verdict.INCONCLUSIVE
        v2 = decide(findings(), [provider(LookupStatus.NO_MATCH)], NO_ML, require_reputation=True)
        assert v2.verdict == Verdict.NO_THREAT_DETECTED

    def test_partial_rule_failure_is_inconclusive(self):
        partial = RuleEngineResult(findings=[], rules_evaluated=10, rule_errors=["PG-X"])
        assert decide(partial, [], NO_ML).verdict == Verdict.INCONCLUSIVE

    def test_one_failed_one_clean_provider(self):
        v = decide(findings(), [provider(LookupStatus.NO_MATCH), provider(LookupStatus.TIMEOUT, name="B")], NO_ML)
        assert v.verdict == Verdict.INCONCLUSIVE
        assert v.components["reputation"]["status"] == "partial"

    def test_no_match_is_never_called_safe(self):
        v = decide(findings(), [provider(LookupStatus.NO_MATCH)], NO_ML)
        assert v.verdict == Verdict.NO_THREAT_DETECTED
        assert "not a guarantee" in v.summary


def test_components_record_each_method():
    v = decide(findings(), [provider(LookupStatus.NO_MATCH)], NO_ML)
    assert set(v.components) == {"rules", "reputation", "ml"}
    assert v.components["ml"]["status"] == "unavailable"
    assert any("machine-learning model was not used" in lim for lim in v.limitations)


def test_scoring_is_bounded_and_labelled():
    many = [Finding("x", "x", Severity.CRITICAL, "e")] * 5
    assert heuristic_index(many) == 100
    assert heuristic_index([]) == 0
    assert index_band(0) == "minimal" and index_band(65) == "high"


# --- End-to-end regression set (rules only, no ML, no providers) -------------


def analyse(url):
    parsed = parse_url(url)
    return decide(evaluate(parsed, extract_features(parsed)), [], NO_ML)


@pytest.mark.parametrize("url", BENIGN_URLS)
def test_regression_benign(url):
    assert analyse(url).verdict == Verdict.NO_THREAT_DETECTED


@pytest.mark.parametrize(("url", "minimum"), MALICIOUS_URLS)
def test_regression_malicious(url, minimum):
    verdict = analyse(url).verdict.value
    assert at_least(verdict, minimum), verdict
