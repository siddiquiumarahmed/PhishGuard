"""Privacy helpers: anonymous ownership, URL fingerprints, redaction and log filtering.

* Each browser gets a random anonymous ``client_id`` stored in the signed
  session cookie. Records store only an HMAC of it (``owner_hash``), so the
  database alone cannot be linked back to a cookie.
* Full URLs are not stored by default. A keyed fingerprint (HMAC-SHA256 of the
  normalised URL) allows de-duplication without keeping the URL, and a
  redacted ``display_url`` (no credentials, query *values* or fragment) is
  kept for the history page.
* A logging filter strips query strings from request log lines.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from urllib.parse import parse_qsl

from flask import current_app, session

from phishguard.detector.url_parser import ParsedURL

SESSION_CLIENT_KEY = "pg_client_id"
DISPLAY_PATH_LIMIT = 96
DISPLAY_URL_LIMIT = 480


def _key(purpose: str) -> bytes:
    secret = current_app.config["SECRET_KEY"]
    return hashlib.sha256(f"{purpose}:{secret}".encode()).digest()


def get_client_id(create: bool = True) -> str | None:
    client_id = session.get(SESSION_CLIENT_KEY)
    if isinstance(client_id, str) and 16 <= len(client_id) <= 64:
        return client_id
    if not create:
        return None
    client_id = secrets.token_urlsafe(24)
    session[SESSION_CLIENT_KEY] = client_id
    session.permanent = True
    return client_id


def owner_hash(client_id: str) -> str:
    return hmac.new(_key("owner"), client_id.encode(), hashlib.sha256).hexdigest()


def current_owner(create: bool = True) -> str | None:
    client_id = get_client_id(create=create)
    return owner_hash(client_id) if client_id else None


def url_fingerprint(normalized_url: str) -> str:
    return hmac.new(_key("url"), normalized_url.encode(), hashlib.sha256).hexdigest()


def redact_url(parsed: ParsedURL) -> str:
    """Human-readable URL with credentials removed and query values hidden.

    ``https://user:pw@example.com/a/b?token=abc#x`` -> ``https://example.com/a/b?token=…``
    """
    host = parsed.host_unicode if parsed.host_type == "domain" else parsed.host_ascii
    netloc = host if not parsed.nonstandard_port else f"{host}:{parsed.port}"
    path = parsed.path
    if len(path) > DISPLAY_PATH_LIMIT:
        path = path[:DISPLAY_PATH_LIMIT] + "…"
    shown = f"{parsed.scheme}://{netloc}{path}"
    if parsed.query:
        try:
            keys = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)][:8]
        except ValueError:
            keys = []
        shown += "?" + ("&".join(f"{k[:24]}=…" for k in keys) if keys else "…")
    return shown[:DISPLAY_URL_LIMIT]


# Matches the request line werkzeug logs, e.g. 'GET /history?q=x HTTP/1.1'
# (possibly wrapped in ANSI colour codes).
def url_anatomy(parsed: ParsedURL) -> dict[str, object]:
    """Break a URL into display segments (for the results page) without secrets.

    The registered domain is singled out because it is the only part that
    identifies who controls the site. Credentials are reduced to a flag.
    """
    query_keys: list[str] = []
    if parsed.query:
        try:
            query_keys = [k[:24] for k, _ in parse_qsl(parsed.query, keep_blank_values=True)][:8]
        except ValueError:
            query_keys = []
    if parsed.host_type == "domain":
        labels = parsed.host_unicode.split(".")
        size = len(parsed.registrable_domain.split(".")) if parsed.registrable_domain else len(labels)
        subdomain = ".".join(labels[:-size]) if len(labels) > size else ""
        registered = ".".join(labels[-size:])
    else:
        subdomain, registered = "", parsed.host_ascii
    path = parsed.path if len(parsed.path) <= DISPLAY_PATH_LIMIT else parsed.path[:DISPLAY_PATH_LIMIT] + "…"
    return {
        "scheme": parsed.scheme,
        "credentials": parsed.has_credentials,
        "subdomain": subdomain,
        "registered": registered,
        "is_ip": parsed.is_ip,
        "port": parsed.port if parsed.nonstandard_port else None,
        "path": path,
        "query_keys": query_keys,
        "has_query": bool(parsed.query),
        "punycode": parsed.host_ascii if parsed.is_idn else None,
    }


_QUERY_IN_REQUEST_LINE = re.compile(r"\b((?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) [^ ?\"]*)\?[^ \"]*")


class RedactQueryStringFilter(logging.Filter):
    """Remove query strings from werkzeug request log lines."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(
                _QUERY_IN_REQUEST_LINE.sub(r"\1?[redacted]", a) if isinstance(a, str) else a for a in record.args
            )
        elif isinstance(record.msg, str):
            record.msg = _QUERY_IN_REQUEST_LINE.sub(r"\1?[redacted]", record.msg)
        return True
