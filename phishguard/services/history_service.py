"""Owner-scoped access to scan records and retention enforcement.

Every query in this module filters on ``owner_hash`` *and* excludes expired
records. Routes never query :class:`ScanRecord` directly, which keeps the
authorisation boundary in one place.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from flask import current_app
from sqlalchemy import ColumnElement, delete, func, or_, select

from phishguard.extensions import db
from phishguard.models.scan_record import ScanRecord, utcnow
from phishguard.security.validation import HistoryQuery, is_valid_scan_id

PURGE_INTERVAL_SECONDS = 300


@dataclass
class Page:
    items: list[ScanRecord]
    page: int
    per_page: int
    total: int

    @property
    def pages(self) -> int:
        return max(1, (self.total + self.per_page - 1) // self.per_page)

    @property
    def has_next(self) -> bool:
        return self.page < self.pages

    @property
    def has_prev(self) -> bool:
        return self.page > 1

    def meta(self) -> dict[str, int | bool]:
        return {
            "page": self.page,
            "per_page": self.per_page,
            "total": self.total,
            "pages": self.pages,
            "has_next": self.has_next,
            "has_prev": self.has_prev,
        }


def _owned(owner: str) -> ColumnElement[bool]:
    return (ScanRecord.owner_hash == owner) & (ScanRecord.expires_at > utcnow())


def list_scans(owner: str, query: HistoryQuery) -> Page:
    conditions = [_owned(owner)]
    if query.verdict:
        conditions.append(ScanRecord.verdict == query.verdict)
    if query.search:
        term = query.search.lower()
        conditions.append(
            or_(
                func.lower(ScanRecord.host).contains(term, autoescape=True),
                func.lower(ScanRecord.display_url).contains(term, autoescape=True),
            )
        )
    total = db.session.scalar(select(func.count()).select_from(ScanRecord).where(*conditions)) or 0
    pages = max(1, (total + query.per_page - 1) // query.per_page)
    page = min(query.page, pages)
    items = list(
        db.session.scalars(
            select(ScanRecord)
            .where(*conditions)
            .order_by(ScanRecord.created_at.desc(), ScanRecord.id)
            .offset((page - 1) * query.per_page)
            .limit(query.per_page)
        )
    )
    return Page(items=items, page=page, per_page=query.per_page, total=int(total))


def get_scan(owner: str, scan_id: str) -> ScanRecord | None:
    """Return the record only if it belongs to ``owner`` and has not expired.

    A record owned by someone else is indistinguishable from a missing one.
    """
    if not is_valid_scan_id(scan_id):
        return None
    return db.session.scalar(select(ScanRecord).where(ScanRecord.id == scan_id, _owned(owner)))


def delete_scan(owner: str, scan_id: str) -> bool:
    if not is_valid_scan_id(scan_id):
        return False
    result = db.session.execute(delete(ScanRecord).where(ScanRecord.id == scan_id, ScanRecord.owner_hash == owner))
    db.session.commit()
    return bool(result.rowcount)


def clear_history(owner: str, demo_only: bool = False) -> int:
    stmt = delete(ScanRecord).where(ScanRecord.owner_hash == owner)
    if demo_only:
        stmt = stmt.where(ScanRecord.is_demo.is_(True))
    result = db.session.execute(stmt)
    db.session.commit()
    return int(result.rowcount or 0)


def purge_expired() -> int:
    result = db.session.execute(delete(ScanRecord).where(ScanRecord.expires_at <= utcnow()))
    db.session.commit()
    return int(result.rowcount or 0)


def maybe_purge_expired() -> None:
    """Purge expired records at most once every few minutes (called on requests)."""
    state = current_app.extensions["phishguard"]
    now = time.monotonic()
    if now - state.get("last_purge", 0.0) >= PURGE_INTERVAL_SECONDS:
        state["last_purge"] = now
        purge_expired()
