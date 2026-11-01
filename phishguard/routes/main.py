"""Static information pages: home, methodology, privacy and API documentation."""

from __future__ import annotations

from flask import Blueprint, current_app, render_template
from flask.typing import ResponseReturnValue

from phishguard.detector.explanations import VERDICT_INFO, Verdict
from phishguard.detector.rule_engine import rule_catalogue
from phishguard.detector.scoring import SEVERITY_WEIGHTS

bp = Blueprint("main", __name__)

# Synthetic examples on reserved domains (.example / .test / RFC 5737 IPs).
# PhishGuard never visits them; they only demonstrate the detector.
EXAMPLE_URLS: list[dict[str, str]] = [
    {"url": "https://www.example.com/products?id=42", "hint": "Ordinary address"},
    {"url": "https://paypal.com.account-verify.example.net/signin", "hint": "Brand in subdomain"},
    {"url": "http://paypal.com@203.0.113.7/login", "hint": "'@' disguise + IP"},
    {"url": "https://xn--pypal-4ve.example/login", "hint": "Homoglyph (Cyrillic 'а')"},
    {"url": "https://paypa1.example/signin", "hint": "Typosquat"},
    {"url": "http://3232235777/admin", "hint": "Obfuscated IP"},
    {"url": "https://free-site.github.io/office365-login/", "hint": "Login page on free hosting"},
    {"url": "https://bit.ly/3example", "hint": "Link shortener"},
]


def _intel_configured() -> int:
    service = current_app.extensions["phishguard"]["reputation"]
    return sum(1 for p in service.providers if p.is_configured())


@bp.get("/")
def index() -> ResponseReturnValue:
    return render_template(
        "index.html",
        examples=EXAMPLE_URLS,
        intel_configured=_intel_configured(),
        max_url_length=current_app.config["MAX_URL_LENGTH"],
        error=None,
        submitted="",
    )


@bp.get("/methodology")
def methodology() -> ResponseReturnValue:
    return render_template(
        "methodology.html",
        rules=rule_catalogue(),
        verdicts=[(v.value, VERDICT_INFO[v]) for v in Verdict],
        weights=[(s.value, w) for s, w in SEVERITY_WEIGHTS.items()],
    )


@bp.get("/privacy")
def privacy() -> ResponseReturnValue:
    return render_template(
        "privacy.html",
        retention_days=current_app.config["SCAN_RETENTION_DAYS"],
        store_normalized=current_app.config["STORE_NORMALIZED_URL"],
        intel_configured=_intel_configured(),
    )


@bp.get("/api-docs")
def api_docs() -> ResponseReturnValue:
    return render_template("api_docs.html", max_url_length=current_app.config["MAX_URL_LENGTH"])
