"""Dashboard statistics for the current browser's own scans.

Statistics are computed only from records owned by the requesting browser on
this local installation. They describe local usage and say nothing about
phishing activity in general.
"""

from __future__ import annotations

from collections import Counter
from datetime import timedelta
from typing import Any

from sqlalchemy import select

from phishguard.detector.explanations import VERDICT_INFO, Verdict
from phishguard.extensions import db
from phishguard.models.scan_record import ScanRecord, utcnow

ACTIVITY_DAYS = 14
ELEVATED = {Verdict.CONFIRMED_MALICIOUS.value, Verdict.HIGH_RISK.value, Verdict.SUSPICIOUS.value}


def dashboard_stats(owner: str) -> dict[str, Any]:
    now = utcnow()
    records = list(
        db.session.scalars(
            select(ScanRecord)
            .where(ScanRecord.owner_hash == owner, ScanRecord.expires_at > now)
            .order_by(ScanRecord.created_at.desc())
        )
    )

    verdicts = Counter(r.verdict for r in records)
    distribution = [
        {"verdict": v.value, "label": VERDICT_INFO[v]["label"], "count": verdicts.get(v.value, 0)} for v in Verdict
    ]

    today = now.date()
    days = [today - timedelta(days=i) for i in range(ACTIVITY_DAYS - 1, -1, -1)]
    per_day = Counter(r.created_at.date() for r in records)
    elevated_per_day = Counter(r.created_at.date() for r in records if r.verdict in ELEVATED)
    activity = [
        {
            "date": d.isoformat(),
            "label": d.strftime("%d %b"),
            "total": per_day.get(d, 0),
            "elevated": elevated_per_day.get(d, 0),
        }
        for d in days
    ]

    provider_errors: Counter[str] = Counter()
    provider_checks: Counter[str] = Counter()
    ml_used = 0
    for r in records:
        for p in r.provider_results or []:
            status = p.get("status")
            name = p.get("display_name", p.get("provider", "unknown"))
            if status in {"match", "unverified_listing", "no_match"}:
                provider_checks[name] += 1
            elif status not in {"not_configured", None}:
                provider_errors[name] += 1
        if (r.ml_result or {}).get("status") == "ok":
            ml_used += 1

    return {
        "total": len(records),
        "demo_count": sum(1 for r in records if r.is_demo),
        "elevated": sum(1 for r in records if r.verdict in ELEVATED),
        "distribution": distribution,
        "max_distribution": max([d["count"] for d in distribution] + [1]),
        "activity": activity,
        "max_activity": max([a["total"] for a in activity] + [1]),
        "recent": records[:8],
        "provider_checks": dict(provider_checks),
        "provider_errors": dict(provider_errors),
        "ml_used": ml_used,
    }
