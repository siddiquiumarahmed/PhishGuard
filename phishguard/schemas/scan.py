"""Serialisation of scan records for the API and for templates."""

from __future__ import annotations

from typing import Any

from flask import url_for

from phishguard.models.scan_record import ScanRecord


def scan_summary(record: ScanRecord) -> dict[str, Any]:
    data = record.to_summary()
    data["links"] = {
        "self": url_for("api.get_scan", scan_id=record.id),
        "report": url_for("scan.result", scan_id=record.id),
    }
    return data


def scan_detail(record: ScanRecord) -> dict[str, Any]:
    data = record.to_detail()
    data["links"] = {
        "self": url_for("api.get_scan", scan_id=record.id),
        "report": url_for("scan.result", scan_id=record.id),
    }
    return data
