"""Health and status endpoints. They never expose secrets or configuration values
beyond whether optional components are available."""

from __future__ import annotations

import logging

from flask import Blueprint, current_app
from flask.typing import ResponseReturnValue
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from phishguard import __version__
from phishguard.detector import DETECTOR_VERSION
from phishguard.detector.rule_engine import RULES
from phishguard.extensions import db, limiter
from phishguard.schemas.common import api_success

bp = Blueprint("health", __name__, url_prefix="/api/v1")
logger = logging.getLogger(__name__)


@bp.get("/health")
@limiter.exempt
def health() -> ResponseReturnValue:
    try:
        db.session.execute(text("SELECT 1"))
        database = "ok"
    except SQLAlchemyError:
        db.session.rollback()
        logger.exception("Database health check failed")
        database = "unavailable"
    status = 200 if database == "ok" else 503
    return api_success({"status": "ok" if status == 200 else "degraded", "database": database}, status)


@bp.get("/status")
def status() -> ResponseReturnValue:
    state = current_app.extensions["phishguard"]
    ml = state["predictor"].status().to_dict()
    return api_success(
        {
            "application_version": __version__,
            "detector_version": DETECTOR_VERSION,
            "rule_count": len(RULES),
            "threat_intelligence": state["reputation"].describe(),
            "machine_learning": {k: ml[k] for k in ("status", "model_version", "threshold", "detail")},
            "privacy": {
                "retention_days": current_app.config["SCAN_RETENTION_DAYS"],
                "stores_normalized_url": bool(current_app.config["STORE_NORMALIZED_URL"]),
            },
            "require_reputation_for_clean": bool(current_app.config["REQUIRE_REPUTATION_FOR_CLEAN"]),
            "fetches_submitted_urls": False,
        }
    )
