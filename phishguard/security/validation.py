"""Validation of request parameters (everything except the URL itself, which
is validated by :mod:`phishguard.detector.url_parser`)."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from phishguard.detector.explanations import Verdict

MAX_SEARCH_LENGTH = 100
MAX_PER_PAGE = 100
DEFAULT_PER_PAGE = 20
VALID_VERDICTS = frozenset(v.value for v in Verdict)


class RequestValidationError(ValueError):
    def __init__(self, code: str, message: str, field: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.field = field


def is_valid_scan_id(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 36:
        return False
    try:
        return str(uuid.UUID(value, version=4)) == value
    except ValueError:
        return False


def parse_positive_int(value: object, field: str, default: int, maximum: int) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise RequestValidationError("invalid_parameter", f"'{field}' must be a positive integer.", field)
    try:
        number = int(str(value), 10)
    except ValueError as exc:
        raise RequestValidationError("invalid_parameter", f"'{field}' must be a positive integer.", field) from exc
    if number < 1:
        raise RequestValidationError("invalid_parameter", f"'{field}' must be a positive integer.", field)
    return min(number, maximum)


@dataclass(frozen=True)
class HistoryQuery:
    search: str
    verdict: str | None
    page: int
    per_page: int


def parse_history_query(args: Mapping[str, Any], strict: bool) -> HistoryQuery:
    """Validate history filters. ``strict`` raises on bad input (API); otherwise
    invalid values fall back to defaults (HTML pages)."""
    get = args.get

    search = (get("q") or "").strip()
    if len(search) > MAX_SEARCH_LENGTH:
        if strict:
            raise RequestValidationError(
                "invalid_parameter", f"'q' must be at most {MAX_SEARCH_LENGTH} characters.", "q"
            )
        search = search[:MAX_SEARCH_LENGTH]

    verdict = (get("verdict") or "").strip() or None
    if verdict is not None and verdict not in VALID_VERDICTS:
        if strict:
            raise RequestValidationError(
                "invalid_parameter", f"'verdict' must be one of: {', '.join(sorted(VALID_VERDICTS))}.", "verdict"
            )
        verdict = None

    try:
        page = parse_positive_int(get("page"), "page", 1, 10_000)
        per_page = parse_positive_int(get("per_page"), "per_page", DEFAULT_PER_PAGE, MAX_PER_PAGE)
    except RequestValidationError:
        if strict:
            raise
        page, per_page = 1, DEFAULT_PER_PAGE
    return HistoryQuery(search=search, verdict=verdict, page=page, per_page=per_page)


def extract_url_from_json(payload: object) -> str:
    if not isinstance(payload, dict):
        raise RequestValidationError("invalid_body", "The request body must be a JSON object.")
    unknown = set(payload) - {"url"}
    if unknown:
        raise RequestValidationError("invalid_body", "Unexpected field(s): " + ", ".join(sorted(map(str, unknown))[:5]))
    url = payload.get("url")
    if url is None:
        raise RequestValidationError("missing_field", "The 'url' field is required.", "url")
    if not isinstance(url, str):
        raise RequestValidationError("invalid_type", "The 'url' field must be a string.", "url")
    return url
