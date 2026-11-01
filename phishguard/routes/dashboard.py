"""Local analytics dashboard and clearly-labelled demonstration data."""

from __future__ import annotations

from flask import Blueprint, abort, current_app, flash, redirect, render_template, url_for
from flask.typing import ResponseReturnValue

from phishguard.detector import DETECTOR_VERSION
from phishguard.detector.rule_engine import RULES
from phishguard.extensions import limiter
from phishguard.security.privacy import current_owner
from phishguard.services.analytics_service import dashboard_stats
from phishguard.services.history_service import clear_history, maybe_purge_expired
from phishguard.services.scan_service import DEMO_URLS, get_scan_service

bp = Blueprint("dashboard", __name__)


def _component_status() -> dict[str, object]:
    state = current_app.extensions["phishguard"]
    return {
        "detector_version": DETECTOR_VERSION,
        "rule_count": len(RULES),
        "providers": state["reputation"].describe(),
        "ml": state["predictor"].status().to_dict(),
    }


@bp.get("/dashboard")
def index() -> ResponseReturnValue:
    maybe_purge_expired()
    owner = current_owner(create=False)
    stats = dashboard_stats(owner) if owner else dashboard_stats("")
    return render_template("dashboard.html", stats=stats, components=_component_status())


@bp.post("/dashboard/demo")
@limiter.limit("5 per minute")
def load_demo() -> ResponseReturnValue:
    owner = current_owner(create=True)
    if owner is None:  # pragma: no cover
        abort(500)
    service = get_scan_service()
    for url in DEMO_URLS:
        service.scan_and_store(url, owner, is_demo=True)
    flash(
        f"Scanned {len(DEMO_URLS)} synthetic demonstration URLs. They are marked 'Demo' "
        "everywhere and can be removed at any time.",
        "success",
    )
    return redirect(url_for("dashboard.index"), code=303)


@bp.post("/dashboard/demo/clear")
def clear_demo() -> ResponseReturnValue:
    owner = current_owner(create=False)
    removed = clear_history(owner, demo_only=True) if owner else 0
    flash(f"Removed {removed} demonstration record(s).", "success")
    return redirect(url_for("dashboard.index"), code=303)
