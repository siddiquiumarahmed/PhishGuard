"""Consistent JSON envelope for every API response.

Success: ``{"ok": true, "data": ..., "meta": {...}}``
Error:   ``{"ok": false, "error": {"code": "...", "message": "...", "field": ...}}``

Error messages are written for end users and never include stack traces,
secrets or internal paths.
"""

from __future__ import annotations

from typing import Any

from flask import Response, jsonify


def api_success(data: Any, status: int = 200, meta: dict[str, Any] | None = None) -> tuple[Response, int]:
    body: dict[str, Any] = {"ok": True, "data": data}
    if meta is not None:
        body["meta"] = meta
    return jsonify(body), status


def api_error(code: str, message: str, status: int, field: str | None = None) -> tuple[Response, int]:
    error: dict[str, Any] = {"code": code, "message": message}
    if field:
        error["field"] = field
    return jsonify({"ok": False, "error": error}), status
