# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""report_runs — record of each generated Inventory Report PDF, with
chain pointers for tamper-evident verification.

Each row is one report generation. The fingerprint is SHA-256 of the
JSON body that was rendered to PDF (NOT the PDF bytes — auditors should
be able to regenerate from the JSON snapshot if needed, but for v1 we
just keep the hash). The chain pointer links this report to the
previous one for the same tenant scope, so an auditor can verify the
sequence of attestations.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base, session_scope

logger = logging.getLogger("vertirite.reports.runs")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ReportRunTable(Base):
    __tablename__ = "report_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    report_type: Mapped[str] = mapped_column(String(64), nullable=False, default="inventory")
    tenant_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    previous_fingerprint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    generated_by: Mapped[str] = mapped_column(String(128), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")  # short blurb

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


def _row_to_dict(row: ReportRunTable) -> Dict[str, Any]:
    return {
        "id": row.id,
        "report_type": row.report_type,
        "tenant_id": row.tenant_id,
        "period_start": row.period_start.isoformat() if row.period_start else None,
        "period_end": row.period_end.isoformat() if row.period_end else None,
        "fingerprint": row.fingerprint,
        "previous_fingerprint": row.previous_fingerprint,
        "generated_by": row.generated_by,
        "summary": row.summary,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def get_previous_fingerprint(
    report_type: str = "inventory",
    tenant_id: Optional[str] = None,
) -> Optional[str]:
    """Return the most recent report's fingerprint for chain linking."""
    with session_scope() as db:
        stmt = (
            select(ReportRunTable)
            .where(ReportRunTable.report_type == report_type)
        )
        if tenant_id is not None:
            stmt = stmt.where(ReportRunTable.tenant_id == tenant_id)
        else:
            stmt = stmt.where(ReportRunTable.tenant_id.is_(None))
        stmt = stmt.order_by(ReportRunTable.created_at.desc()).limit(1)
        row = db.execute(stmt).scalars().first()
        return row.fingerprint if row else None


def record_report_run(
    report_type: str,
    tenant_id: Optional[str],
    period_start: datetime,
    period_end: datetime,
    fingerprint: str,
    previous_fingerprint: Optional[str],
    generated_by: str,
    summary: str = "",
) -> Dict[str, Any]:
    run_id = str(uuid.uuid4())
    with session_scope() as db:
        row = ReportRunTable(
            id=run_id,
            report_type=report_type,
            tenant_id=tenant_id,
            period_start=period_start,
            period_end=period_end,
            fingerprint=fingerprint,
            previous_fingerprint=previous_fingerprint,
            generated_by=generated_by,
            summary=summary,
        )
        db.add(row)
        db.flush()
        return _row_to_dict(row)


def list_report_runs(
    report_type: Optional[str] = None,
    tenant_id: Optional[str] = None,
    limit: int = 100,
) -> list[Dict[str, Any]]:
    with session_scope() as db:
        stmt = select(ReportRunTable)
        if report_type is not None:
            stmt = stmt.where(ReportRunTable.report_type == report_type)
        if tenant_id is not None:
            stmt = stmt.where(ReportRunTable.tenant_id == tenant_id)
        stmt = stmt.order_by(ReportRunTable.created_at.desc()).limit(limit)
        rows = db.execute(stmt).scalars().all()
        return [_row_to_dict(r) for r in rows]
