"""Blueprint registration and error handling."""

from __future__ import annotations

import logging

from flask import Flask, render_template, request
from flask.typing import ResponseReturnValue
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException

from phishguard.schemas.common import api_error

logger = logging.getLogger(__name__)

ERROR_COPY: dict[int, tuple[str, str]] = {
    400: ("Bad request", "The request could not be understood. Check the information you submitted."),
    403: ("Forbidden", "You do not have permission to perform this action."),
    404: (
        "Not found",
        "The page or scan you asked for does not exist, has expired, or belongs to a different browser session.",
    ),
    405: ("Method not allowed", "This address does not accept that kind of request."),
    413: ("Request too large", "The submitted data is larger than PhishGuard accepts."),
    415: ("Unsupported content type", "Send the request body as JSON."),
    429: ("Too many requests", "You have reached the rate limit. Wait a little and try again."),
    500: (
        "Something went wrong",
        "PhishGuard hit an unexpected error. No details are shown for security reasons; check the server log.",
    ),
}

ERROR_CODES = {
    400: "bad_request",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    413: "payload_too_large",
    415: "unsupported_media_type",
    429: "rate_limited",
    500: "internal_error",
}


def _wants_json() -> bool:
    return request.path.startswith("/api/")


def _render_error(
    status: int, title: str | None = None, message: str | None = None, code: str | None = None
) -> ResponseReturnValue:
    default_title, default_message = ERROR_COPY.get(status, ERROR_COPY[500])
    title = title or default_title
    message = message or default_message
    if _wants_json():
        return api_error(code or ERROR_CODES.get(status, "error"), message, status)
    return render_template("errors/error.html", status=status, title=title, message=message), status


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(CSRFError)
    def handle_csrf(exc: CSRFError) -> ResponseReturnValue:
        return _render_error(
            400,
            "Security check failed",
            "The form's security token was missing or expired. Reload the page and try again. "
            "API clients must send the token from GET /api/v1/session in the X-CSRFToken header.",
            "csrf_failed",
        )

    @app.errorhandler(HTTPException)
    def handle_http(exc: HTTPException) -> ResponseReturnValue:
        status = exc.code or 500
        if status >= 500:
            logger.error("HTTP %s on %s %s", status, request.method, request.path)
        return _render_error(status)

    @app.errorhandler(Exception)
    def handle_unexpected(exc: Exception) -> ResponseReturnValue:
        # Full traceback goes to the server log only; the client gets a generic message.
        logger.exception("Unhandled error on %s %s", request.method, request.path)
        from phishguard.extensions import db

        db.session.rollback()
        return _render_error(500)


def register_blueprints(app: Flask) -> None:
    from phishguard.routes import api, dashboard, health, history, main, scan

    for module in (main, scan, history, dashboard, api, health):
        app.register_blueprint(module.bp)
