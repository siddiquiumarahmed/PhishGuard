"""Threat-intelligence adapters. All network calls are mocked; nothing is sent anywhere."""

from __future__ import annotations

import pytest
import requests

from phishguard.intelligence.base import LookupStatus
from phishguard.intelligence.cache import TTLCache, cache_key
from phishguard.intelligence.google_provider import (
    SAFE_BROWSING_ENDPOINT,
    GoogleSafeBrowsingProvider,
    GoogleWebRiskProvider,
)
from phishguard.intelligence.phishtank_provider import PhishTankProvider
from phishguard.intelligence.service import ReputationService, build_service

URL = "https://phish.example/login"
KEY = "test-api-key-SECRET"


class FakeResponse:
    def __init__(self, status_code=200, payload=None, json_error=False):
        self.status_code = status_code
        self._payload = payload
        self._json_error = json_error

    def json(self):
        if self._json_error:
            raise ValueError("not json")
        return self._payload


class FakeSession:
    def __init__(self, responses=None, exc=None):
        self.responses = list(responses or [])
        self.exc = exc
        self.calls = []

    def _respond(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if self.exc:
            raise self.exc
        return self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]

    def post(self, url, **kwargs):
        return self._respond("POST", url, **kwargs)

    def get(self, url, **kwargs):
        return self._respond("GET", url, **kwargs)


def gsb(session):
    return GoogleSafeBrowsingProvider(KEY, session=session)


# --- Missing credentials ------------------------------------------------------


@pytest.mark.parametrize(
    "provider",
    [
        GoogleSafeBrowsingProvider(None),
        GoogleSafeBrowsingProvider("  "),
        GoogleWebRiskProvider(""),
        PhishTankProvider(enabled=False),
    ],
)
def test_unconfigured_providers_do_not_call_network(provider):
    provider.session = FakeSession(exc=AssertionError("network must not be used"))
    result = provider.lookup(URL)
    assert result.status == LookupStatus.NOT_CONFIGURED
    assert not result.status.completed and not result.status.failed


# --- Google Safe Browsing -------------------------------------------------------


def test_gsb_no_match():
    session = FakeSession([FakeResponse(200, {})])
    result = gsb(session).lookup(URL)
    assert result.status == LookupStatus.NO_MATCH
    _method, url, kwargs = session.calls[0]
    assert url == SAFE_BROWSING_ENDPOINT
    assert kwargs["headers"]["X-Goog-Api-Key"] == KEY
    assert KEY not in url  # key travels in a header, not the URL
    assert kwargs["json"]["threatInfo"]["threatEntries"] == [{"url": URL}]
    assert kwargs["timeout"]


def test_gsb_match():
    payload = {"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": URL}}]}
    result = gsb(FakeSession([FakeResponse(200, payload)])).lookup(URL)
    assert result.status == LookupStatus.MATCH
    assert result.threat_types == ["SOCIAL_ENGINEERING"]


@pytest.mark.parametrize(
    ("response", "status"),
    [
        (FakeResponse(401, {}), LookupStatus.AUTH_ERROR),
        (FakeResponse(403, {"error": {"message": f"key {KEY} invalid"}}), LookupStatus.AUTH_ERROR),
        (FakeResponse(429, {}), LookupStatus.QUOTA_EXCEEDED),
        (FakeResponse(500, {}), LookupStatus.ERROR),
        (FakeResponse(400, {}), LookupStatus.ERROR),
        (FakeResponse(200, json_error=True), LookupStatus.MALFORMED_RESPONSE),
        (FakeResponse(200, ["not", "an", "object"]), LookupStatus.MALFORMED_RESPONSE),
        (FakeResponse(200, {"matches": "nope"}), LookupStatus.MALFORMED_RESPONSE),
        (FakeResponse(200, {"matches": [{"no_type": 1}]}), LookupStatus.MALFORMED_RESPONSE),
    ],
)
def test_gsb_failures_are_reported_never_clean(response, status):
    result = gsb(FakeSession([response])).lookup(URL)
    assert result.status == status
    assert result.status.failed
    assert KEY not in result.detail


@pytest.mark.parametrize("exc", [requests.Timeout(), requests.ConnectionError(), requests.TooManyRedirects()])
def test_gsb_network_exceptions(exc):
    result = gsb(FakeSession(exc=exc)).lookup(URL)
    assert result.status == (LookupStatus.TIMEOUT if isinstance(exc, requests.Timeout) else LookupStatus.ERROR)


def test_quota_error_triggers_cooldown():
    session = FakeSession([FakeResponse(429, {}), FakeResponse(200, {})])
    provider = gsb(session)
    assert provider.lookup(URL).status == LookupStatus.QUOTA_EXCEEDED
    second = provider.lookup(URL)
    assert second.status == LookupStatus.QUOTA_EXCEEDED
    assert "Skipped" in second.detail
    assert len(session.calls) == 1


# --- Google Web Risk ------------------------------------------------------------


def test_web_risk_no_match_and_match():
    session = FakeSession([FakeResponse(200, {})])
    provider = GoogleWebRiskProvider(KEY, session=session)
    assert provider.lookup(URL).status == LookupStatus.NO_MATCH
    params = dict(session.calls[0][2]["params"][:1])
    assert params["uri"] == URL
    provider.session = FakeSession([FakeResponse(200, {"threat": {"threatTypes": ["MALWARE"], "expireTime": "x"}})])
    result = provider.lookup(URL)
    assert result.status == LookupStatus.MATCH and result.threat_types == ["MALWARE"]


@pytest.mark.parametrize("payload", [{"threat": "x"}, {"threat": {"threatTypes": []}}, {"threat": {}}])
def test_web_risk_malformed(payload):
    provider = GoogleWebRiskProvider(KEY, session=FakeSession([FakeResponse(200, payload)]))
    assert provider.lookup(URL).status == LookupStatus.MALFORMED_RESPONSE


# --- PhishTank ------------------------------------------------------------------


def phishtank(payload, status=200):
    session = FakeSession([FakeResponse(status, payload)])
    return PhishTankProvider(enabled=True, app_key="k", username="tester", session=session), session


@pytest.mark.parametrize(
    ("results", "status"),
    [
        ({"in_database": False}, LookupStatus.NO_MATCH),
        ({"in_database": True, "verified": True, "valid": True}, LookupStatus.MATCH),
        ({"in_database": "y", "verified": "y", "valid": "y"}, LookupStatus.MATCH),
        ({"in_database": True, "verified": False, "valid": False}, LookupStatus.UNVERIFIED_LISTING),
        ({"in_database": True, "verified": True, "valid": False}, LookupStatus.NO_MATCH),
    ],
)
def test_phishtank_interpretation(results, status):
    provider, session = phishtank({"meta": {}, "results": {"url": URL, **results}})
    assert provider.lookup(URL).status == status
    assert session.calls[0][2]["headers"]["User-Agent"] == "phishtank/tester"
    assert session.calls[0][2]["data"]["format"] == "json"


@pytest.mark.parametrize(
    ("payload", "http", "status"),
    [
        ({"meta": {}}, 200, LookupStatus.MALFORMED_RESPONSE),
        ({"results": {"url": URL}}, 200, LookupStatus.MALFORMED_RESPONSE),
        ({"errortext": "bad"}, 200, LookupStatus.ERROR),
        ({}, 509, LookupStatus.QUOTA_EXCEEDED),
    ],
)
def test_phishtank_failures(payload, http, status):
    provider, _ = phishtank(payload, http)
    assert provider.lookup(URL).status == status


# --- Service and cache ------------------------------------------------------------


def test_service_caches_completed_results_only():
    ok_session = FakeSession([FakeResponse(200, {})])
    bad_session = FakeSession(exc=requests.Timeout())
    ok = GoogleSafeBrowsingProvider(KEY, session=ok_session)
    bad = GoogleWebRiskProvider(KEY, session=bad_session)
    service = ReputationService([ok, bad, PhishTankProvider(enabled=False)])

    first = service.check(URL)
    assert [r.provider for r in first] == ["google_safe_browsing", "google_web_risk", "phishtank"]
    assert [r.status for r in first] == [LookupStatus.NO_MATCH, LookupStatus.TIMEOUT, LookupStatus.NOT_CONFIGURED]

    second = service.check(URL)
    assert second[0].cached is True and len(ok_session.calls) == 1
    assert second[1].cached is False and len(bad_session.calls) == 2  # failures retried


def test_cache_keys_do_not_contain_url_and_expire():
    key = cache_key("p", URL)
    assert URL not in key and len(key) == 64
    cache: TTLCache[str] = TTLCache(ttl_seconds=0.0)
    cache.set(key, "x")
    assert cache.get(key) is None
    lru: TTLCache[int] = TTLCache(ttl_seconds=60, max_entries=2)
    for i in range(3):
        lru.set(str(i), i)
    assert len(lru) == 2 and lru.get("0") is None


def test_build_service_without_credentials():
    service = build_service({})
    results = service.check(URL)
    assert results and all(r.status == LookupStatus.NOT_CONFIGURED for r in results)
    assert all(not d["configured"] for d in service.describe())
