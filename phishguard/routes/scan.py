"""HTML scan submission and result pages."""

from __future__ import annotations

from flask import Blueprint, abort, current_app, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue

from phishguard.detector.url_parser import URLValidationError
from phishguard.extensions import limiter
from phishguard.routes.main import EXAMPLE_URLS, _intel_configured
from phishguard.security.privacy import current_owner
from phishguard.security.rate_limits import scan_limit
from phishguard.services.history_service import get_scan, maybe_purge_expired
from phishguard.services.scan_service import get_scan_service

bp = Blueprint("scan", __name__)


@bp.post("/scan")
@limiter.limit(scan_limit)
def submit() -> ResponseReturnValue:
    raw = request.form.get("url", "")
    owner = current_owner(create=True)
    if owner is None:  # pragma: no cover - create=True always returns an owner
        abort(500)
    try:
        record = get_scan_service().scan_and_store(raw, owner)
    except URLValidationError as exc:
        return render_template(
            "index.html",
            examples=EXAMPLE_URLS,
            intel_configured=_intel_configured(),
            max_url_length=current_app.config["MAX_URL_LENGTH"],
            error=exc.message,
            # Echoed back into the input (autoescaped) so the user can correct it.
            submitted=raw[: current_app.config["MAX_URL_LENGTH"] + 64] if isinstance(raw, str) else "",
        ), 400
    maybe_purge_expired()
    return redirect(url_for("scan.result", scan_id=record.id), code=303)


@bp.get("/scans/<scan_id>")
def result(scan_id: str) -> ResponseReturnValue:
    owner = current_owner(create=False)
    record = get_scan(owner, scan_id) if owner else None
    if record is None:
        abort(404)
    return render_template("results.html", scan=record.to_detail(), record=record)
