import pytest

from phishguard.detector.rule_engine import RULES, Finding, Rule, Severity, evaluate, rule_catalogue
from phishguard.detector.url_features import extract_features
from phishguard.detector.url_parser import parse_url
from tests.fixtures_urls import BENIGN_URLS


def run(url):
    parsed = parse_url(url)
    return evaluate(parsed, extract_features(parsed))


def rule_ids(result):
    return {f.rule_id for f in result.findings}


def test_every_finding_has_required_fields():
    result = run("http://paypal.com@203.0.113.7/login")
    assert result.findings
    for f in result.findings:
        d = f.to_dict()
        assert d["rule_id"].startswith("PG-")
        assert d["title"] and d["explanation"]
        assert d["severity"] in {s.value for s in Severity}
        assert isinstance(d["evidence"], list)


def test_rule_catalogue_documents_every_rule():
    catalogue = rule_catalogue()
    assert len(catalogue) == len(RULES)
    for entry in catalogue:
        assert entry["rationale"] and entry["limitations"]


@pytest.mark.parametrize(
    ("url", "rule_id", "severity"),
    [
        ("http://user:pw@example.com/", "PG-URL-001", Severity.MEDIUM),
        ("http://www.paypal.com@203.0.113.7/", "PG-URL-002", Severity.CRITICAL),
        ("http://docs.example.org@203.0.113.7/", "PG-URL-002", Severity.HIGH),
        ("http://203.0.113.7/login", "PG-HOST-001", Severity.MEDIUM),
        ("http://3232235777/", "PG-HOST-002", Severity.HIGH),
        ("http://%65vil.example/", "PG-HOST-003", Severity.HIGH),
        ("https://xn--pypal-4ve.example/", "PG-HOST-004", Severity.HIGH),
        ("https://bücher.example/", "PG-HOST-005", Severity.LOW),
        ("https://a.b.c.d.e.f.example.com/", "PG-HOST-007", Severity.MEDIUM),
        ("https://a.b.c.d.example.com/", "PG-HOST-007", Severity.LOW),
        ("https://my-very-long-hyphen-name.example/", "PG-HOST-008", Severity.LOW),
        ("https://shop.example.top/", "PG-HOST-009", Severity.LOW),
        ("https://project.github.io/", "PG-HOST-010", Severity.LOW),
        ("https://x.github.io/office365-login", "PG-HOST-010", Severity.MEDIUM),
        ("https://bit.ly/abc", "PG-HOST-011", Severity.LOW),
        ("http://192.168.1.1/", "PG-HOST-012", Severity.INFO),
        ("https://example.com:8443/", "PG-HOST-013", Severity.LOW),
        ("https://paypal.com.verify.example.net/", "PG-BRAND-001", Severity.CRITICAL),
        ("https://paypal-help.verify.example.net/", "PG-BRAND-001", Severity.HIGH),
        ("https://secure-paypal-login.example/", "PG-BRAND-002", Severity.HIGH),
        ("https://paypal.example/", "PG-BRAND-002", Severity.MEDIUM),
        ("https://xn--pypal-4ve.example/", "PG-BRAND-003", Severity.CRITICAL),
        ("https://paypa1.example/", "PG-BRAND-003", Severity.CRITICAL),
        ("https://paypa1-help.example/", "PG-BRAND-003", Severity.HIGH),
        ("https://netflx.example/", "PG-BRAND-003", Severity.MEDIUM),
        ("https://evil.example/www.paypal.com/", "PG-BRAND-004", Severity.MEDIUM),
        ("https://evil.example/www.paypal.com/signin", "PG-BRAND-004", Severity.HIGH),
        ("https://news.example/apple-results", "PG-BRAND-004", Severity.LOW),
        ("https://verify-account.example/", "PG-KW-001", Severity.MEDIUM),
        ("https://shop.example/login", "PG-KW-002", Severity.LOW),
        ("http://example.com/", "PG-TLS-001", Severity.INFO),
        ("http://verify.example.com/", "PG-TLS-001", Severity.MEDIUM),
        ("https://e.example/a?x=%2541", "PG-PATH-001", Severity.MEDIUM),
        ("https://e.example/r?url=https://evil.example/", "PG-PATH-002", Severity.LOW),
        ("https://e.example/setup.exe", "PG-PATH-003", Severity.MEDIUM),
        ("https://e.example/files.zip", "PG-PATH-003", Severity.LOW),
        ("https://e.example/a/../b", "PG-PATH-004", Severity.LOW),
        ("https://e.example/" + "a" * 220, "PG-LEN-001", Severity.LOW),
    ],
)
def test_rule_triggers(url, rule_id, severity):
    result = run(url)
    matching = [f for f in result.findings if f.rule_id == rule_id]
    assert matching, f"{rule_id} not triggered; got {rule_ids(result)}"
    assert matching[0].severity == severity


@pytest.mark.parametrize("url", BENIGN_URLS)
def test_benign_urls_have_no_high_or_critical_findings(url):
    result = run(url)
    assert not [f for f in result.findings if f.severity.rank >= Severity.HIGH.rank], result.findings


def test_official_domains_do_not_trigger_brand_rules():
    for url in ("https://www.paypal.com/signin", "https://login.microsoftonline.com/", "https://www.amazon.co.uk/"):
        assert not {i for i in rule_ids(run(url)) if i.startswith("PG-BRAND")}


def test_findings_sorted_by_severity():
    result = run("https://paypal.com.account-verify.example.top/signin")
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_faulty_rule_is_isolated():
    def broken(parsed, features):
        raise RuntimeError("boom")

    def fine(parsed, features):
        return [Finding("PG-T-1", "ok", Severity.LOW, "x")]

    parsed = parse_url("https://example.com/")
    result = evaluate(
        parsed,
        extract_features(parsed),
        rules=[
            Rule("PG-T-0", "broken", "test", "r", "l", broken),
            Rule("PG-T-1", "fine", "test", "r", "l", fine),
        ],
    )
    assert result.status == "partial"
    assert result.rule_errors == ["PG-T-0"]
    assert [f.rule_id for f in result.findings] == ["PG-T-1"]


def test_all_rules_failing_marks_failed():
    def broken(parsed, features):
        raise ValueError

    parsed = parse_url("https://example.com/")
    result = evaluate(parsed, extract_features(parsed), rules=[Rule("PG-T-0", "b", "t", "r", "l", broken)])
    assert result.status == "failed"


def test_evidence_never_contains_password():
    result = run("http://www.paypal.com:s3cretpass@203.0.113.7/")
    for f in result.findings:
        assert "s3cretpass" not in str(f.to_dict())
