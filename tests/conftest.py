"""Shared fixtures.

Flask and its extensions are imported inside fixtures, so the detector,
intelligence and ML tests can run without the web stack installed.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import pytest

CSRF_INPUT = re.compile(r'name="csrf_token" value="([^"]+)"')


def make_app(**overrides: Any):
    from phishguard import create_app
    from phishguard.extensions import db

    app = create_app("testing", overrides=overrides or None)
    with app.app_context():
        db.create_all()
    return app


@pytest.fixture()
def app() -> Iterator[Any]:
    from phishguard.extensions import db

    application = make_app()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def other_client(app):
    """A second, independent browser session."""
    return app.test_client()


def api_token(client) -> str:
    response = client.get("/api/v1/session")
    assert response.status_code == 200
    return response.get_json()["data"]["csrf_token"]


def form_token(client) -> str:
    html = client.get("/").get_data(as_text=True)
    match = CSRF_INPUT.search(html)
    assert match, "CSRF token not found in form"
    return match.group(1)


def api_scan(client, url: str, token: str | None = None):
    token = token or api_token(client)
    return client.post("/api/v1/scan", json={"url": url}, headers={"X-CSRFToken": token})


def form_scan(client, url: str, token: str | None = None):
    token = token or form_token(client)
    return client.post("/scan", data={"url": url, "csrf_token": token})


def set_providers(app, providers) -> None:
    """Replace the reputation providers (used with mocked providers)."""
    from phishguard.intelligence.service import ReputationService

    service = ReputationService(providers)
    state = app.extensions["phishguard"]
    state["reputation"] = service
    state["scan_service"].reputation = service
