"""Scan history: list, search, filter, paginate and delete (own records only)."""

from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue

from phishguard.detector.explanations import VERDICT_INFO, Verdict
from phishguard.security.privacy import current_owner
from phishguard.security.validation import parse_history_query
from phishguard.services.history_service import Page, clear_history, delete_scan, list_scans, maybe_purge_expired

bp = Blueprint("history", __name__)


@bp.get("/history")
def index() -> ResponseReturnValue:
    maybe_purge_expired()
    query = parse_history_query(request.args, strict=False)
    owner = current_owner(create=False)
    page = list_scans(owner, query) if owner else Page(items=[], page=1, per_page=query.per_page, total=0)
    return render_template(
        "history.html",
        page=page,
        query=query,
        verdict_options=[(v.value, VERDICT_INFO[v]["label"]) for v in Verdict],
    )


@bp.post("/history/clear")
def clear() -> ResponseReturnValue:
    owner = current_owner(create=False)
    removed = clear_history(owner) if owner else 0
    flash(f"Deleted {removed} scan record(s) from this browser's history.", "success")
    return redirect(url_for("history.index"), code=303)


@bp.post("/history/<scan_id>/delete")
def delete(scan_id: str) -> ResponseReturnValue:
    owner = current_owner(create=False)
    if owner and delete_scan(owner, scan_id):
        flash("Scan record deleted.", "success")
    else:
        flash("That scan record was not found.", "error")
    return redirect(url_for("history.index"), code=303)
