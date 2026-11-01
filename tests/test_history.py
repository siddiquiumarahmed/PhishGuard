"""Persistence, retention, history UI, dashboard and informational pages."""

from __future__ import annotations

import re
from datetime import timedelta

from phishguard.extensions import db
from phishguard.models.scan_record import ScanRecord, utcnow
from phishguard.services.history_service import purge_expired
from tests.conftest import api_scan, api_token, form_scan, form_token, make_app

SCAN_PATH = re.compile(r"/scans/([0-9a-f-]{36})$")


def only_record(app) -> ScanRecord:
    with app.app_context():
        records = db.session.scalars(db.select(ScanRecord)).all()
        assert len(records) == 1
        db.session.expunge_all()
        return records[0]


def test_form_scan_redirects_to_result_page(client):
    response = form_scan(client, "https://paypal.com.account-verify.example.net/signin")
    assert response.status_code == 303
    match = SCAN_PATH.search(response.headers["Location"])
    assert match
    page = client.get(response.headers["Location"])
    html = page.get_data(as_text=True)
    assert page.status_code == 200
    assert "High risk" in html and "PG-BRAND-001" in html and "example.net" in html


def test_form_validation_error_is_shown(client):
    response = form_scan(client, "example.com")
    assert response.status_code == 400
    assert "Include the scheme" in response.get_data(as_text=True)


def test_record_is_privacy_conscious_by_default(app, client):
    api_scan(client, "https://user:p4ssw0rd@shop.example.net/reset?token=SECRET123&email=a%40b.example#FRAGSECRET")
    record = only_record(app)
    stored = " ".join(
        str(v)
        for v in (
            record.display_url,
            record.findings,
            record.result,
            record.provider_results,
            record.component_status,
            record.host,
            record.normalized_url,
        )
    )
    for secret in ("p4ssw0rd", "SECRET123", "a%40b", "FRAGSECRET", "user:"):
        assert secret not in stored
    assert record.display_url == "https://shop.example.net/reset?token=…&email=…"
    assert re.fullmatch(r"[0-9a-f]{64}", record.url_fingerprint)
    assert record.normalized_url is None
    assert len(record.owner_hash) == 64


def test_normalized_url_stored_only_when_enabled():
    app = make_app(STORE_NORMALIZED_URL=True)
    client = app.test_client()
    api_scan(client, "https://user:pw@shop.example.net/a?x=1#f")
    assert only_record(app).normalized_url == "https://shop.example.net/a?x=1"


def test_retention_expiry_and_purge(app, client):
    scan_id = api_scan(client, "https://example.com/").get_json()["data"]["id"]
    record = only_record(app)
    assert record.expires_at - record.created_at == timedelta(days=app.config["SCAN_RETENTION_DAYS"])
    with app.app_context():
        db.session.get(ScanRecord, scan_id).expires_at = utcnow() - timedelta(seconds=1)
        db.session.commit()
    assert client.get(f"/api/v1/scans/{scan_id}").status_code == 404
    assert client.get("/api/v1/scans").get_json()["meta"]["total"] == 0
    with app.app_context():
        assert purge_expired() == 1
        assert db.session.scalar(db.select(db.func.count()).select_from(ScanRecord)) == 0


def test_purge_cli_command(app, client):
    api_scan(client, "https://example.com/")
    with app.app_context():
        for r in db.session.scalars(db.select(ScanRecord)):
            r.expires_at = utcnow() - timedelta(days=1)
        db.session.commit()
    result = app.test_cli_runner().invoke(args=["purge-expired"])
    assert "Deleted 1 expired record" in result.output


def test_history_page_search_filter_and_pagination(client):
    token = api_token(client)
    for i in range(22):
        api_scan(client, f"https://site{i}.example/", token)
    api_scan(client, "http://paypal.com@203.0.113.7/login", token)

    page1 = client.get("/history").get_data(as_text=True)
    assert "23 records" in page1 and "page 1 of 2" in page1 and 'rel="next"' in page1
    page2 = client.get("/history?page=2").get_data(as_text=True)
    assert "page 2 of 2" in page2

    searched = client.get("/history?q=site21").get_data(as_text=True)
    assert "site21.example" in searched and "site3.example" not in searched
    filtered = client.get("/history?verdict=high_risk").get_data(as_text=True)
    assert "203.0.113.7" in filtered and "site1.example" not in filtered
    # Invalid filters fall back to defaults on HTML pages instead of erroring.
    assert client.get("/history?page=abc&verdict=nope").status_code == 200


def test_history_empty_state(client):
    html = client.get("/history").get_data(as_text=True)
    assert "No scans yet" in html


def test_clear_and_delete(app, client):
    token = api_token(client)
    first = api_scan(client, "https://a.example/", token).get_json()["data"]["id"]
    api_scan(client, "https://b.example/", token)

    form = form_token(client)
    r = client.post(f"/history/{first}/delete", data={"csrf_token": form})
    assert r.status_code == 303
    assert client.get("/api/v1/scans").get_json()["meta"]["total"] == 1

    r = client.post("/history/clear", data={"csrf_token": form})
    assert r.status_code == 303
    assert client.get("/api/v1/scans").get_json()["meta"]["total"] == 0


def test_dashboard_and_demo_data(app, client):
    assert client.get("/dashboard").status_code == 200
    token = form_token(client)
    r = client.post("/dashboard/demo", data={"csrf_token": token})
    assert r.status_code == 303
    html = client.get("/dashboard").get_data(as_text=True)
    assert "demonstration data" in html
    with app.app_context():
        demo = db.session.scalars(db.select(ScanRecord).where(ScanRecord.is_demo.is_(True))).all()
        assert demo and all(r.is_demo for r in demo)
        assert {r.verdict for r in demo} >= {"no_threat_detected", "high_risk"}
    assert "Demo" in client.get("/history").get_data(as_text=True)
    client.post("/dashboard/demo/clear", data={"csrf_token": token})
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count()).select_from(ScanRecord)) == 0


def test_information_pages_render(client):
    for path, text in [
        ("/", "Check a link"),
        ("/methodology", "PG-BRAND-003"),
        ("/privacy", "What is stored"),
        ("/api-docs", "/api/v1/scan"),
    ]:
        response = client.get(path)
        assert response.status_code == 200, path
        assert text in response.get_data(as_text=True), path


def test_custom_404_page(client):
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    assert "Not found" in response.get_data(as_text=True)
