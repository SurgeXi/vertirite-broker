# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Coverage-over-time (Wave A #2).

Periodic snapshots of the Coverage Map metrics per tenant, so the console can
render exposure SHRINKING as governance grows — the renewal story ("you were at
11% ungoverned-AI in March; you're at 2% now"). Additive + read-mostly; nothing
customer-facing changes until the console reads the trend. A scheduler (or the
existing self-healing timer) calls ``capture_coverage_snapshot`` on a cadence;
``get_coverage_trend`` feeds the chart.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import DateTime, Float, Integer, String, select
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base, session_scope
from .coverage import coverage_map


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CoverageSnapshotTable(Base):
    __tablename__ = "coverage_snapshots"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    coverage_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    witnessed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    governed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ungoverned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ungoverned_ai: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ungoverned_suspicious: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


def build_snapshot_record(coverage: Dict[str, Any], tenant_id: str,
                          captured_at: Optional[datetime] = None) -> Dict[str, Any]:
    """Map a ``coverage_map()`` result to the snapshot columns. Pure + testable
    (no DB): the whole risk surface of this feature is this mapping."""
    c = (coverage or {}).get("counts", {}) or {}
    return {
        "id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "captured_at": captured_at or _utc_now(),
        "coverage_pct": float((coverage or {}).get("coverage_pct", 0.0) or 0.0),
        "witnessed": int(c.get("witnessed", 0) or 0),
        "governed": int(c.get("governed", 0) or 0),
        "ungoverned": int(c.get("ungoverned", 0) or 0),
        "ungoverned_ai": int(c.get("ungoverned_ai_services", 0) or 0),
        "ungoverned_suspicious": int(c.get("ungoverned_suspicious", 0) or 0),
    }


def _row_to_dict(r: "CoverageSnapshotTable") -> Dict[str, Any]:
    return {
        "tenant_id": r.tenant_id,
        "captured_at": r.captured_at.isoformat() if r.captured_at else None,
        "coverage_pct": r.coverage_pct,
        "witnessed": r.witnessed,
        "governed": r.governed,
        "ungoverned": r.ungoverned,
        "ungoverned_ai": r.ungoverned_ai,
        "ungoverned_suspicious": r.ungoverned_suspicious,
    }


def capture_coverage_snapshot(tenant_id: str) -> Dict[str, Any]:
    """Compute the current coverage for ``tenant_id`` and persist ONE snapshot row."""
    rec = build_snapshot_record(coverage_map(tenant_id), tenant_id)
    with session_scope() as db:
        db.add(CoverageSnapshotTable(**rec))
        db.flush()
    out = dict(rec)
    out["captured_at"] = out["captured_at"].isoformat()
    return out


def get_coverage_trend(tenant_id: str, limit: int = 90) -> List[Dict[str, Any]]:
    """The tenant's snapshots, OLDEST->NEWEST, for the trend chart (capped)."""
    limit = max(1, min(int(limit or 90), 1000))
    with session_scope() as db:
        rows = db.execute(
            select(CoverageSnapshotTable)
            .where(CoverageSnapshotTable.tenant_id == tenant_id)
            .order_by(CoverageSnapshotTable.captured_at.desc())
            .limit(limit)
        ).scalars().all()
    return [_row_to_dict(r) for r in reversed(rows)]
