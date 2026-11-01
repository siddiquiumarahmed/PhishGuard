"""Scan record model.

Privacy by default:
* the submitted URL is **not** stored; ``display_url`` is redacted (no
  credentials, query values or fragment) and ``url_fingerprint`` is a keyed
  hash of the normalised URL;
* ``normalized_url`` is only populated when ``STORE_NORMALIZED_URL=true``;
* every record has ``expires_at`` and is deleted after ``SCAN_RETENTION_DAYS``;
* ``owner_hash`` (HMAC of an anonymous browser ID) scopes every query, so one
  browser can never read another browser's records.

All timestamps are naive UTC (SQLite has no time-zone type).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from phishguard.extensions import db


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def new_scan_id() -> str:
    return str(uuid.uuid4())


class ScanRecord(db.Model):  # type: ignore[name-defined]
    __tablename__ = "scan_records"

    id = db.Column(db.String(36), primary_key=True, default=new_scan_id)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    owner_hash = db.Column(db.String(64), nullable=False, index=True)
    url_fingerprint = db.Column(db.String(64), nullable=False, index=True)
    display_url = db.Column(db.String(512), nullable=False)
    host = db.Column(db.String(255), nullable=False, index=True)
    normalized_url = db.Column(db.Text, nullable=True)
    verdict = db.Column(db.String(32), nullable=False, index=True)
    heuristic_index = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(16), nullable=False, default="completed")
    detector_version = db.Column(db.String(32), nullable=False)
    model_version = db.Column(db.String(64), nullable=True)
    is_demo = db.Column(db.Boolean, nullable=False, default=False, index=True)
    findings = db.Column(db.JSON, nullable=False, default=list)
    provider_results = db.Column(db.JSON, nullable=False, default=list)
    ml_result = db.Column(db.JSON, nullable=True)
    component_status = db.Column(db.JSON, nullable=False, default=dict)
    result = db.Column(db.JSON, nullable=False, default=dict)

    __table_args__ = (db.Index("ix_scan_records_owner_created", "owner_hash", "created_at"),)

    def to_summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat(timespec="seconds") + "Z",
            "expires_at": self.expires_at.isoformat(timespec="seconds") + "Z",
            "display_url": self.display_url,
            "host": self.host,
            "verdict": self.verdict,
            "heuristic_index": self.heuristic_index,
            "is_demo": self.is_demo,
        }

    def to_detail(self) -> dict[str, Any]:
        data = self.to_summary()
        result = dict(self.result or {})
        data.update(
            {
                "status": self.status,
                "label": result.get("label"),
                "summary": result.get("summary"),
                "reasons": result.get("reasons", []),
                "index_band": result.get("index_band"),
                "decisive_methods": result.get("decisive_methods", []),
                "findings": self.findings or [],
                "threat_intelligence": self.provider_results or [],
                "machine_learning": self.ml_result,
                "components": self.component_status or {},
                "limitations": result.get("limitations", []),
                "recommendations": result.get("recommendations", []),
                "parser_notes": result.get("parser_notes", []),
                "anatomy": result.get("anatomy", {}),
                "detector_version": self.detector_version,
                "model_version": self.model_version,
                "normalized_url": self.normalized_url,
            }
        )
        return data
