"""Application security: XSS, CSRF, authorisation boundaries, headers, privacy, SSRF."""

from __future__ import annotations

import logging

import pytest
import requests

from phishguard.extensions import db
from phishguard.models.scan_record import ScanRecord
from phishguard.security.privacy import RedactQueryStringFilter
from tests.conftest import api_scan, api_token, form_scan, form_token

XSS = "<script>alert(1)</script>"


# --- XSS ---------------------------------------------------------------------------


def test_xss_in_url_path_is_escaped_on_result_and_history(client):
    response = form_scan(client, f"https://example.com/{XSS}")
    location = response.headers["Location"]
    for page in (client.get(location), client.get("/history")):
        html = page.get_data(as_text=True)
        assert XSS not in html
        assert "&lt;script&gt;" in html


def test_xss_in_query_parameter_names_is_escaped(client):
    payload = "<svg/onload=alert(1)>"
    response = form_scan(client, f"https://example.com/?{payload}=1")
    html = client.get(response.headers["Location"]).get_data(as_text=True)
    assert "<svg/onload" not in html
    assert "&lt;svg/onload" in html


def test_rejected_input_is_escaped_when_echoed(client):
    payload = f'javascript:"><img src=x onerror=alert(1)>{XSS}'
    response = form_scan(client, payload)
    html = response.get_data(as_text=True)
    assert response.status_code == 400
    assert XSS not in html and "<img src=x" not in html


def test_search_term_is_escaped(client):
    api_token(client)
    html = client.get("/history?q=%3Cscript%3Ealert(1)%3C/script%3E").get_data(as_text=True)
    assert XSS not in html


def test_api_returns_json_content_type(client):
    response = api_scan(client, f"https://example.com/{XSS}")
    assert response.mimetype == "application/json"


# --- Security headers ----------------------------------------------------------------


@pytest.mark.parametrize("path", ["/", "/history", "/api/v1/health", "/does-not-exist"])
def test_security_headers(client, path):
    headers = client.get(path).headers
    csp = headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp and "script-src 'self'" in csp and "unsafe-inline" not in csp
    assert "frame-ancestors 'none'" in csp
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"


def test_scan_pages_not_cached(client):
    response = form_scan(client, "https://example.com/")
    assert client.get(response.headers["Location"]).headers["Cache-Control"] == "no-store"
    assert client.get("/history").headers["Cache-Control"] == "no-store"
    assert client.get("/api/v1/scans").headers["Cache-Control"] == "no-store"


def test_session_cookie_flags(client):
    response = client.get("/api/v1/session")
    cookie = next(c for c in response.headers.getlist("Set-Cookie") if c.startswith("phishguard_session="))
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


# --- CSRF ------------------------------------------------------------------------------


def test_form_scan_requires_csrf(client):
    assert client.post("/scan", data={"url": "https://example.com/"}).status_code == 400
    assert client.post("/scan", data={"url": "https://example.com/", "csrf_token": "forged"}).status_code == 400


def test_api_scan_requires_csrf_header(client):
    api_token(client)
    response = client.post("/api/v1/scan", json={"url": "https://example.com/"})
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "csrf_failed"


def test_token_from_one_session_is_rejected_in_another(client, other_client):
    token = api_token(client)
    api_token(other_client)
    response = other_client.post("/api/v1/scan", json={"url": "https://example.com/"}, headers={"X-CSRFToken": token})
    assert response.status_code == 400


@pytest.mark.parametrize("path", ["/history/clear", "/dashboard/demo", "/dashboard/demo/clear"])
def test_state_changing_forms_require_csrf(client, path):
    assert client.post(path).status_code == 400


# --- Authorisation boundaries -------------------------------------------------------------


def test_other_sessions_cannot_read_or_delete_records(app, client, other_client):
    scan_id = api_scan(client, "https://private.example/").get_json()["data"]["id"]
    other_token = api_token(other_client)

    assert other_client.get(f"/api/v1/scans/{scan_id}").status_code == 404
    assert other_client.get(f"/scans/{scan_id}").status_code == 404
    assert other_client.get("/api/v1/scans").get_json()["meta"]["total"] == 0
    assert "private.example" not in other_client.get("/history").get_data(as_text=True)
    assert "private.example" not in other_client.get("/dashboard").get_data(as_text=True)
    assert other_client.delete(f"/api/v1/scans/{scan_id}", headers={"X-CSRFToken": other_token}).status_code == 404
    other_form = form_token(other_client)
    other_client.post(f"/history/{scan_id}/delete", data={"csrf_token": other_form})
    other_client.post("/history/clear", data={"csrf_token": other_form})

    assert client.get(f"/api/v1/scans/{scan_id}").status_code == 200
    with app.app_context():
        assert db.session.get(ScanRecord, scan_id) is not None


def test_client_without_session_sees_nothing(app, client):
    scan_id = api_scan(client, "https://example.com/").get_json()["data"]["id"]
    fresh = app.test_client()
    assert fresh.get(f"/api/v1/scans/{scan_id}").status_code == 404
    assert fresh.get("/api/v1/scans").get_json()["data"] == []


# --- Input limits ----------------------------------------------------------------------------


def test_oversized_url_rejected_in_form(client):
    response = form_scan(client, "https://example.com/" + "a" * 5000)
    assert response.status_code == 400
    assert "character limit" in response.get_data(as_text=True)


def test_oversized_form_body_rejected(client):
    token = form_token(client)
    response = client.post("/scan", data={"url": "https://example.com/" + "a" * 20000, "csrf_token": token})
    assert response.status_code == 413


# --- Privacy and SSRF ----------------------------------------------------------------------


def test_scanned_urls_never_logged(client, caplog):
    caplog.set_level(logging.DEBUG)
    api_scan(client, "https://example.com/reset?token=TOPSECRET-TOKEN")
    assert "TOPSECRET-TOKEN" not in caplog.text
    assert "example.com/reset" not in caplog.text


def test_request_log_filter_redacts_query_strings():
    record = logging.LogRecord(
        "werkzeug",
        logging.INFO,
        __file__,
        1,
        '%s - - "%s" %s %s',
        ("127.0.0.1", "GET /history?q=secret.example HTTP/1.1", "200", "-"),
        None,
    )
    RedactQueryStringFilter().filter(record)
    assert "secret.example" not in record.getMessage()
    assert "/history?[redacted]" in record.getMessage()


def test_scanning_makes_no_outbound_requests(client, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("PhishGuard must not fetch submitted URLs")

    monkeypatch.setattr(requests.Session, "request", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    response = api_scan(client, "http://203.0.113.7/login")
    assert response.status_code == 201
