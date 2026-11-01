"""PhishGuard - offline-first phishing URL analysis.

The Flask application factory imports the web stack lazily so the
``phishguard.detector``, ``phishguard.intelligence`` and ``phishguard.ml``
packages remain usable (and testable) without Flask extensions - for example
from the model-training scripts.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__version__ = "1.0.0"

if TYPE_CHECKING:  # pragma: no cover
    from flask import Flask


def create_app(config_name: str | None = None, overrides: dict[str, Any] | None = None) -> Flask:
    import logging
    from pathlib import Path

    from flask import Flask

    from config import BASE_DIR, INSTANCE_DIR, get_config
    from phishguard.cli import init_database, register_cli
    from phishguard.detector.explanations import verdict_label
    from phishguard.extensions import csrf, db, limiter, migrate
    from phishguard.intelligence.service import build_service
    from phishguard.ml.predict import ModelPredictor
    from phishguard.routes import register_blueprints, register_error_handlers
    from phishguard.security.headers import init_security_headers
    from phishguard.security.privacy import RedactQueryStringFilter
    from phishguard.services.scan_service import ScanService

    app = Flask(__name__, instance_path=str(INSTANCE_DIR), instance_relative_config=False)
    app.config.from_object(get_config(config_name))
    if overrides:
        app.config.update(overrides)
    app.config.setdefault("AUTO_INIT_DB", not app.config.get("TESTING", False))

    # --- Logging (never logs submitted URLs or query strings) ---
    level = getattr(logging, str(app.config.get("LOG_LEVEL", "INFO")), logging.INFO)
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
    logging.getLogger().setLevel(level)
    app.logger.setLevel(level)
    werkzeug_logger = logging.getLogger("werkzeug")
    if not any(isinstance(f, RedactQueryStringFilter) for f in werkzeug_logger.filters):
        werkzeug_logger.addFilter(RedactQueryStringFilter())

    # --- Extensions ---
    db.init_app(app)
    migrate.init_app(app, db, directory=str(Path(BASE_DIR) / "migrations"), render_as_batch=True)
    csrf.init_app(app)
    limiter.init_app(app)
    init_security_headers(app)

    # --- Services ---
    reputation = build_service(app.config)
    predictor = ModelPredictor(app.config.get("ML_MODEL_PATH"), enabled=bool(app.config.get("ML_ENABLED", True)))
    app.extensions["phishguard"] = {
        "reputation": reputation,
        "predictor": predictor,
        "scan_service": ScanService(reputation, predictor, app.config),
        "last_purge": 0.0,
    }

    # --- Web layer ---
    register_blueprints(app)
    register_error_handlers(app)
    register_cli(app)

    @app.template_filter("verdict_label")
    def _verdict_label(value: str) -> str:
        return verdict_label(value)

    @app.template_filter("utc")
    def _utc(value: Any) -> str:
        return value.strftime("%Y-%m-%d %H:%M UTC") if value is not None else ""

    @app.context_processor
    def _inject_globals() -> dict[str, Any]:
        return {"app_version": __version__}

    if app.config.get("AUTO_INIT_DB"):
        with app.app_context():
            init_database(quiet=True)

    return app
