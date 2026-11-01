"""Versioned JSON API (``/api/v1``).

Authentication model: anonymous, cookie-based. The first request receives a
signed session cookie that identifies the caller's own records. Because the
session is cookie-based, state-changing requests (POST/DELETE) must send the
CSRF token from ``GET /api/v1/session`` in the ``X-CSRFToken`` header.
"""

from __future__ import annotations

from flask import Blueprint, request
from flask.typing import ResponseReturnValue
from flask_wtf.csrf import generate_csrf

from phishguard.detector.url_parser import URLValidationError
from phishguard.extensions import limiter
from phishguard.schemas.common import api_error, api_success
from phishguard.schemas.scan import scan_detail, scan_summary
from phishguard.security.privacy import current_owner
from phishguard.security.rate_limits import scan_limit
from phishguard.security.validation import RequestValidationError, extract_url_from_json, parse_history_query
from phishguard.services.history_service import delete_scan, list_scans, maybe_purge_expired
from phishguard.services.history_service import get_scan as fetch_scan
from phishguard.services.scan_service import get_scan_service

bp = Blueprint("api", __name__, url_prefix="/api/v1")

NOT_FOUND_MESSAGE = "No scan with this ID exists for your session."


@bp.get("/session")
def session_info() -> ResponseReturnValue:
    """Start (or resume) an anonymous session and return a CSRF token."""
    current_owner(create=True)
    return api_success({"csrf_token": generate_csrf(), "csrf_header": "X-CSRFToken"})


@bp.post("/scan")
@limiter.limit(scan_limit)
def create_scan() -> ResponseReturnValue:
    if not request.is_json:
        return api_error(
            "unsupported_media_type", "Send the request body as JSON with 'Content-Type: application/json'.", 415
        )
    payload = request.get_json(silent=True)
    if payload is None:
        return api_error("invalid_json", "The request body is not valid JSON.", 400)
    try:
        url = extract_url_from_json(payload)
    except RequestValidationError as exc:
        return api_error(exc.code, exc.message, 400, exc.field)

    owner = current_owner(create=True)
    if owner is None:  # pragma: no cover
        return api_error("session_error", "Could not establish a session.", 500)
    try:
        record = get_scan_service().scan_and_store(url, owner)
    except URLValidationError as exc:
        return api_error(f"invalid_url.{exc.code}", exc.message, 422, "url")
    maybe_purge_expired()
    response, status = api_success(scan_detail(record), 201)
    response.headers["Location"] = scan_detail(record)["links"]["self"]
    return response, status


@bp.get("/scans")
def list_scan_records() -> ResponseReturnValue:
    try:
        query = parse_history_query(request.args, strict=True)
    except RequestValidationError as exc:
        return api_error(exc.code, exc.message, 400, exc.field)
    owner = current_owner(create=False)
    if owner is None:
        return api_success(
            [],
            meta={"page": 1, "per_page": query.per_page, "total": 0, "pages": 1, "has_next": False, "has_prev": False},
        )
    page = list_scans(owner, query)
    return api_success([scan_summary(r) for r in page.items], meta=page.meta())


@bp.get("/scans/<scan_id>")
def get_scan(scan_id: str) -> ResponseReturnValue:
    owner = current_owner(create=False)
    record = fetch_scan(owner, scan_id) if owner else None
    if record is None:
        return api_error("not_found", NOT_FOUND_MESSAGE, 404)
    return api_success(scan_detail(record))


@bp.delete("/scans/<scan_id>")
def remove_scan(scan_id: str) -> ResponseReturnValue:
    owner = current_owner(create=False)
    if not owner or not delete_scan(owner, scan_id):
        return api_error("not_found", NOT_FOUND_MESSAGE, 404)
    return api_success({"deleted": scan_id})
