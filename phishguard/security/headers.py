"""HTTP security headers applied to every response.

The Content-Security-Policy forbids inline scripts and styles and any
third-party origin; all JavaScript and CSS is served from ``/static``. This
is the second line of defence against XSS after Jinja2 autoescaping and the
use of ``textContent`` in client-side code.
"""

from __future__ import annotations

from flask import Flask, Response, request

CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

# Pages showing scan data must not be cached by the browser or intermediaries.
NO_STORE_PREFIXES = ("/scans", "/history", "/dashboard", "/api/")


def apply_security_headers(response: Response) -> Response:
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if request.path.startswith(NO_STORE_PREFIXES) or request.method == "POST":
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    # Do not advertise the server software/version.
    response.headers.pop("Server", None)
    return response


def init_security_headers(app: Flask) -> None:
    app.after_request(apply_security_headers)
