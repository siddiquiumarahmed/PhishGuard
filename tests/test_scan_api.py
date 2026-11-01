"""REST API and application start-up."""

from __future__ import annotations

import uuid

import pytest

from phishguard.intelligence.base import LookupStatus, ProviderResult, ReputationProvider
from tests.conftest import api_scan, api_token, make_app, set_providers


class StubProvider(ReputationProvider):
    def __init__(self, status, threat_types=None, pid="stub", name="Stub Intel"):
        super().__init__()
        self._status = status
        self._types = threat_types or []
        self.provider_id = pid
        self.display_name = name
        self.calls = 0

    def is_configured(self):
        return self._status != LookupStatus.NOT_CONFIGURED

    def _query(self, url):
        self.calls += 1
        return ProviderResult(self.provider_id, self.display_name, self._status, self._types)


# --- Start-up -------------------------------------------------------------------


def test_app_starts_and_registers_routes(app):
    endpoints = {rule.endpoint for rule in app.url_map.iter_rules()}
    for expected in (
        "main.index",
        "scan.submit",
        "scan.result",
        "history.index",
        "dashboard.index",
        "api.create_scan",
        "api.list_scan_records",
        "api.get_scan",
        "health.health",
        "health.status",
    ):
        assert expected in endpoints


def test_health(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.get_json() == {"ok": True, "data": {"status": "ok", "database": "ok"}}


def test_status_reports_components_without_secrets():
    secret = "AIza-super-secret-test-key"
    app = make_app(GOOGLE_SAFE_BROWSING_API_KEY=secret)
    app.extensions["phishguard"]["reputation"].providers[0].api_key = secret
    response = app.test_client().get("/api/v1/status")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert secret not in body
    data = response.get_json()["data"]
    assert data["fetches_submitted_urls"] is False
    assert data["machine_learning"]["status"] == "unavailable"
    assert any(p["configured"] for p in data["threat_intelligence"])


# --- Scanning -------------------------------------------------------------------


def test_scan_success_shape(client):
    response = api_scan(client, "https://paypal.com.account-verify.example.net/signin?token=abc123")
    assert response.status_code == 201
    payload = response.get_json()
    assert payload["ok"] is True
    data = payload["data"]
    assert data["verdict"] == "high_risk"
    assert response.headers["Location"].endswith(data["id"])
    assert data["findings"] and {"rule_id", "severity", "explanation", "evidence"} <= set(data["findings"][0])
    assert data["components"]["rules"]["status"] == "ok"
    assert data["machine_learning"]["status"] == "unavailable"
    assert "abc123" not in str(data)  # query values are not stored or returned
    assert data["detector_version"].startswith("detector-")


def test_benign_scan_without_credentials_or_model(client):
    data = api_scan(client, "https://www.example.com/").get_json()["data"]
    assert data["verdict"] == "no_threat_detected"
    assert data["components"]["reputation"]["status"] == "not_configured"
    assert any("not checked against any blocklist" in limit for limit in data["limitations"])


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("example.com", "invalid_url.missing_scheme"),
        ("javascript:alert(1)", "invalid_url.unsupported_scheme"),
        ("http://999.1.1.1/", "invalid_url.invalid_ip"),
        ("https://" + "a" * 3000 + ".com/", "invalid_url.too_long"),
    ],
)
def test_invalid_urls_rejected(client, url, code):
    response = api_scan(client, url)
    assert response.status_code == 422
    error = response.get_json()["error"]
    assert error["code"] == code and error["field"] == "url" and error["message"]


def test_malformed_requests(client):
    token = api_token(client)
    headers = {"X-CSRFToken": token}
    r = client.post(
        "/api/v1/scan",
        data="url=https://example.com",
        headers=headers,
        content_type="application/x-www-form-urlencoded",
    )
    assert r.status_code == 415
    r = client.post("/api/v1/scan", data="{not json", headers=headers, content_type="application/json")
    assert r.status_code == 400 and r.get_json()["error"]["code"] == "invalid_json"
    for body, code in [
        ([], "invalid_body"),
        ({}, "missing_field"),
        ({"url": 5}, "invalid_type"),
        ({"url": "https://example.com", "admin": True}, "invalid_body"),
    ]:
        r = client.post("/api/v1/scan", json=body, headers=headers)
        assert r.status_code == 400 and r.get_json()["error"]["code"] == code, body


def test_oversized_body_rejected(client):
    token = api_token(client)
    r = client.post(
        "/api/v1/scan",
        data='{"url": "' + "a" * 20000 + '"}',
        headers={"X-CSRFToken": token},
        content_type="application/json",
    )
    assert r.status_code == 413
    assert r.get_json()["error"]["code"] == "payload_too_large"


def test_list_get_delete(client):
    token = api_token(client)
    ids = [api_scan(client, f"https://site{i}.example/", token).get_json()["data"]["id"] for i in range(3)]
    api_scan(client, "http://paypal.com@203.0.113.7/login", token)

    listing = client.get("/api/v1/scans?per_page=2").get_json()
    assert listing["meta"]["total"] == 4 and listing["meta"]["pages"] == 2 and len(listing["data"]) == 2
    filtered = client.get("/api/v1/scans?verdict=high_risk").get_json()
    assert [s["verdict"] for s in filtered["data"]] == ["high_risk"]
    searched = client.get("/api/v1/scans?q=site1").get_json()
    assert searched["meta"]["total"] == 1

    detail = client.get(f"/api/v1/scans/{ids[0]}")
    assert detail.status_code == 200 and detail.get_json()["data"]["id"] == ids[0]

    deleted = client.delete(f"/api/v1/scans/{ids[0]}", headers={"X-CSRFToken": token})
    assert deleted.status_code == 200
    assert client.get(f"/api/v1/scans/{ids[0]}").status_code == 404


@pytest.mark.parametrize("query", ["page=0", "page=abc", "per_page=-1", "verdict=evil", "q=" + "x" * 101])
def test_list_parameter_validation(client, query):
    api_token(client)
    response = client.get(f"/api/v1/scans?{query}")
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "invalid_parameter"


def test_per_page_is_capped(client):
    api_scan(client, "https://example.com/")
    assert client.get("/api/v1/scans?per_page=5000").get_json()["meta"]["per_page"] == 100


@pytest.mark.parametrize("scan_id", [str(uuid.uuid4()), "not-a-uuid", "1%27%20OR%20%271%27%3D%271"])
def test_unknown_ids_are_404(client, scan_id):
    api_token(client)
    response = client.get(f"/api/v1/scans/{scan_id}")
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "not_found"


def test_unknown_api_route_and_method_return_json(client):
    assert client.get("/api/v1/nope").get_json()["error"]["code"] == "not_found"
    r = client.put("/api/v1/scans")
    assert r.status_code == 405 and r.get_json()["error"]["code"] == "method_not_allowed"


# --- Threat intelligence integration (mocked) --------------------------------------


def test_provider_match_confirms(app, client):
    set_providers(app, [StubProvider(LookupStatus.MATCH, ["SOCIAL_ENGINEERING"])])
    data = api_scan(client, "https://www.example.com/").get_json()["data"]
    assert data["verdict"] == "confirmed_malicious"
    assert data["threat_intelligence"][0]["status"] == "match"


def test_provider_timeout_makes_clean_url_inconclusive(app, client):
    set_providers(app, [StubProvider(LookupStatus.TIMEOUT)])
    data = api_scan(client, "https://www.example.com/").get_json()["data"]
    assert data["verdict"] == "inconclusive"
    assert data["threat_intelligence"][0]["status_label"].endswith("not checked")


def test_provider_no_match_is_not_called_safe(app, client):
    set_providers(app, [StubProvider(LookupStatus.NO_MATCH)])
    data = api_scan(client, "https://www.example.com/").get_json()["data"]
    assert data["verdict"] == "no_threat_detected"
    assert "not a guarantee" in data["summary"]


# --- Rate limiting and errors -----------------------------------------------------------


def test_rate_limit_applies_to_scans():
    app = make_app(RATELIMIT_ENABLED=True, SCAN_RATE_LIMIT="2 per minute")
    client = app.test_client()
    token = api_token(client)
    assert api_scan(client, "https://a.example/", token).status_code == 201
    assert api_scan(client, "https://b.example/", token).status_code == 201
    limited = api_scan(client, "https://c.example/", token)
    assert limited.status_code == 429
    assert limited.get_json()["error"]["code"] == "rate_limited"


def test_unexpected_errors_do_not_leak_details(app, client, monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError("internal secret detail /srv/path")

    monkeypatch.setattr(app.extensions["phishguard"]["scan_service"], "analyze", explode)
    response = api_scan(client, "https://example.com/")
    assert response.status_code == 500
    text = response.get_data(as_text=True)
    assert "internal secret detail" not in text and "Traceback" not in text
    assert response.get_json()["error"]["code"] == "internal_error"
