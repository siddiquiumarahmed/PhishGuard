"""Scan orchestration: validation → features → rules → reputation → ML → verdict → storage.

Business logic lives here, not in the HTTP routes, so the web UI, the API and
tests share exactly the same code path.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from flask import current_app

from phishguard.detector import DETECTOR_VERSION
from phishguard.detector.rule_engine import RULES, RuleEngineResult, evaluate
from phishguard.detector.url_features import URLFeatures, extract_features
from phishguard.detector.url_parser import ParsedURL, parse_url
from phishguard.detector.verdict_engine import VerdictResult, decide
from phishguard.extensions import db
from phishguard.intelligence.base import ProviderResult
from phishguard.intelligence.service import ReputationService
from phishguard.ml.predict import MLResult, ModelPredictor
from phishguard.models.scan_record import ScanRecord, utcnow
from phishguard.security.privacy import redact_url, url_anatomy, url_fingerprint

logger = logging.getLogger(__name__)

#: Synthetic URLs on reserved domains (RFC 2606 / RFC 6761 / RFC 5737) used to
#: populate clearly-labelled demonstration data. They are analysed for real,
#: never visited, and stored with ``is_demo=True``.
DEMO_URLS: tuple[str, ...] = (
    "https://www.example.com/",
    "https://docs.example.org/guide/getting-started",
    "https://shop.example.net/cart?item=1234&qty=2",
    "https://news.example.com/2026/10/apple-announces-results",
    "https://paypal.com.account-verify.example.net/signin",
    "http://paypal.com@203.0.113.7/login",
    "https://xn--pypal-4ve.example/login",
    "https://paypa1.example/webscr?cmd=_login-submit",
    "https://secure-microsoft-login.example.top/office365/verify",
    "https://free-site.github.io/office365-login/",
    "http://198.51.100.23:8080/secure/bankofamerica/login.html",
    "https://bit.ly/3example",
)


@dataclass
class Analysis:
    parsed: ParsedURL
    features: URLFeatures | None
    rules: RuleEngineResult
    providers: list[ProviderResult]
    ml: MLResult
    verdict: VerdictResult


class ScanService:
    def __init__(self, reputation: ReputationService, predictor: ModelPredictor, config: Mapping[str, Any]) -> None:
        self.reputation = reputation
        self.predictor = predictor
        self.config = config

    # -- analysis (no persistence) ----------------------------------------
    def analyze(self, raw_url: object) -> Analysis:
        """Analyse a URL. Raises URLValidationError for unacceptable input."""
        parsed = parse_url(raw_url, max_length=int(self.config.get("MAX_URL_LENGTH", 2048)))

        features: URLFeatures | None
        try:
            features = extract_features(parsed)
            rule_result = evaluate(parsed, features)
        except Exception:
            logger.exception("Feature extraction failed")
            features = None
            rule_result = RuleEngineResult(
                findings=[], rules_evaluated=len(RULES), rule_errors=[r.rule_id for r in RULES]
            )

        providers = self.reputation.check(parsed.normalized)

        if features is not None:
            ml = self.predictor.predict(features)
        else:
            ml = MLResult(self.predictor.status().status, detail="skipped: features unavailable")

        verdict = decide(
            rule_result,
            providers,
            ml,
            require_reputation=bool(self.config.get("REQUIRE_REPUTATION_FOR_CLEAN", False)),
        )
        return Analysis(parsed, features, rule_result, providers, ml, verdict)

    # -- analysis + storage -------------------------------------------------
    def scan_and_store(self, raw_url: object, owner: str, *, is_demo: bool = False) -> ScanRecord:
        analysis = self.analyze(raw_url)
        parsed, verdict = analysis.parsed, analysis.verdict
        now = utcnow()
        retention_days = int(self.config.get("SCAN_RETENTION_DAYS", 7))

        result_payload = verdict.to_dict()
        result_payload["parser_notes"] = list(parsed.notes)
        result_payload["anatomy"] = url_anatomy(parsed)
        result_payload.pop("components", None)

        record = ScanRecord(
            created_at=now,
            expires_at=now + timedelta(days=retention_days),
            owner_hash=owner,
            url_fingerprint=url_fingerprint(parsed.normalized),
            display_url=redact_url(parsed),
            host=(parsed.host_unicode if parsed.host_type == "domain" else parsed.host_ascii)[:255],
            normalized_url=parsed.normalized if self.config.get("STORE_NORMALIZED_URL") else None,
            verdict=verdict.verdict.value,
            heuristic_index=verdict.heuristic_index,
            status="completed",
            detector_version=DETECTOR_VERSION,
            model_version=analysis.ml.model_version,
            is_demo=is_demo,
            findings=[f.to_dict() for f in analysis.rules.findings],
            provider_results=[p.to_dict() for p in analysis.providers],
            ml_result=analysis.ml.to_dict(),
            component_status=verdict.components,
            result=result_payload,
        )
        db.session.add(record)
        db.session.commit()
        # Log the scan without the URL (it may contain tokens).
        logger.info("Scan %s completed: verdict=%s index=%s", record.id, record.verdict, record.heuristic_index)
        return record


def get_scan_service() -> ScanService:
    service: ScanService = current_app.extensions["phishguard"]["scan_service"]
    return service
