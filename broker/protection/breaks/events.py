# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""break_events — the persisted record of detected agent breaks.

One row per open (tenant, actor, reason, target) break; re-detections while a
break is still open bump ``occurrence_count`` rather than spawning duplicates
(same de-dup discipline as discovery/findings.py). Lifecycle:

    open ─ acknowledge ─▶ acknowledged   (expected/benign — folded into baseline)
        ├ dismiss ──────▶ dismissed      (false positive — also folded, stops re-firing)
        └ confirm ──────▶ confirmed      (real — NOT folded; P3 would contain)
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import DateTime, Integer, String, Text, and_, select
from sqlalchemy.orm import Mapped, mapped_column

from ...db import Base, session_scope
from . import baseline as _baseline
from .detector import Break

logger = logging.getLogger("vertirite.breaks.events")

STATUS_VALUES = ("open", "acknowledged", "dismissed", "confirmed")
_OPEN = ("open", "acknowledged")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class BreakEventTable(Base):
    __tablename__ = "break_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    reason: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    chokepoints: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open", index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    resolved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolve_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


def _row_to_dict(row: BreakEventTable) -> Dict[str, Any]:
    def _j(raw, default):
        try:
            return json.loads(raw) if raw else default
        except Exception:
            return default
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "actor_id": row.actor_id,
        "reason": row.reason,
        "severity": row.severity,
        "title": row.title,
        "target": row.target,
        "chokepoints": _j(row.chokepoints, []),
        "evidence": _j(row.evidence, {}),
        "status": row.status,
        "occurrence_count": row.occurrence_count,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "resolved_by": row.resolved_by,
        "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
        "resolve_note": row.resolve_note,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def report_break(tenant_id: str, actor_id: str, brk: Break) -> Dict[str, Any]:
    """Upsert a break. If an open row with the same (tenant, actor, reason,
    target) exists, bump occurrence_count + last_seen; else insert."""
    with session_scope() as db:
        existing = db.scalar(
            select(BreakEventTable).where(
                and_(
                    BreakEventTable.tenant_id == tenant_id,
                    BreakEventTable.actor_id == actor_id,
                    BreakEventTable.reason == brk.reason,
                    BreakEventTable.target == brk.target,
                    BreakEventTable.status.in_(_OPEN),
                )
            )
        )
        if existing is not None:
            existing.occurrence_count += 1
            existing.last_seen_at = _utc_now()
            db.flush()
            return _row_to_dict(existing)

        row = BreakEventTable(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            actor_id=actor_id,
            reason=brk.reason,
            severity=brk.severity,
            title=brk.title,
            target=brk.target,
            chokepoints=json.dumps(sorted(brk.chokepoints or [])),
            evidence=json.dumps(brk.evidence or {}),
            status="open",
        )
        db.add(row)
        db.flush()
        return _row_to_dict(row)


def list_breaks(tenant_id: Optional[str] = None, status_filter: Optional[List[str]] = None,
                severity: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
    with session_scope() as db:
        stmt = select(BreakEventTable)
        if tenant_id is not None:
            stmt = stmt.where(BreakEventTable.tenant_id == tenant_id)
        if status_filter:
            stmt = stmt.where(BreakEventTable.status.in_(status_filter))
        if severity:
            stmt = stmt.where(BreakEventTable.severity == severity)
        stmt = stmt.order_by(BreakEventTable.last_seen_at.desc()).limit(limit)
        return [_row_to_dict(r) for r in db.execute(stmt).scalars().all()]


def get_break(break_id: str) -> Optional[Dict[str, Any]]:
    with session_scope() as db:
        row = db.get(BreakEventTable, break_id)
        return _row_to_dict(row) if row else None


def summary(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    with session_scope() as db:
        stmt = select(BreakEventTable.status, BreakEventTable.severity)
        if tenant_id is not None:
            stmt = stmt.where(BreakEventTable.tenant_id == tenant_id)
        rows = db.execute(stmt).all()
    by_status = {s: 0 for s in STATUS_VALUES}
    open_by_sev: Dict[str, int] = {}
    for status, severity in rows:
        by_status[status] = by_status.get(status, 0) + 1
        if status in _OPEN:
            open_by_sev[severity] = open_by_sev.get(severity, 0) + 1
    return {"total": len(rows), "by_status": by_status, "open_by_severity": open_by_sev}


def _fold_into_baseline(reason: str, tenant_id: str, actor_id: str, target: str) -> None:
    """Teach the baseline that this behavior is expected, so it stops re-firing.
    Only for the novelty/first-time reasons; scope/denial breaks aren't grants.
    MUST run AFTER the break_events transaction has committed — it opens its own
    session, and sqlite is single-writer (a nested session would deadlock)."""
    if reason == "novel_egress":
        _baseline.learn(tenant_id, actor_id, dest=target)
    elif reason == "first_credential":
        _baseline.learn(tenant_id, actor_id, credential=True)
    elif reason == "first_irreversible":
        _baseline.learn(tenant_id, actor_id, irreversible=True)
    elif reason == "dataclass_escalation":
        _baseline.learn(tenant_id, actor_id, data_class=target)
    elif reason == "off_hours":
        try:
            _baseline.learn(tenant_id, actor_id, hour=int(target.split(":", 1)[1]))
        except Exception:
            pass
    elif reason == "rate_spike":
        try:
            _baseline.learn(tenant_id, actor_id, rate_band=int(target.split(":", 1)[1]))
        except Exception:
            pass


def _resolve(break_id: str, status: str, actor_id: str, note: str = "",
             fold: bool = False) -> Optional[Dict[str, Any]]:
    fold_args = None
    with session_scope() as db:
        row = db.get(BreakEventTable, break_id)
        if row is None:
            return None
        row.status = status
        row.resolved_by = actor_id
        row.resolved_at = _utc_now()
        if note:
            row.resolve_note = note.strip()[:1024]
        db.flush()
        result = _row_to_dict(row)
        if fold:
            fold_args = (row.reason, row.tenant_id, row.actor_id, row.target)
    # Transaction committed + connection released — now safe to open a new one.
    if fold_args:
        _fold_into_baseline(*fold_args)
    return result


def acknowledge_break(break_id: str, actor_id: str) -> Optional[Dict[str, Any]]:
    """Expected/benign — fold into the baseline (confirm-and-learn)."""
    return _resolve(break_id, "acknowledged", actor_id, fold=True)


def dismiss_break(break_id: str, actor_id: str, reason: str = "") -> Optional[Dict[str, Any]]:
    """False positive — also fold so it stops re-firing."""
    return _resolve(break_id, "dismissed", actor_id, note=reason, fold=True)


def confirm_break(break_id: str, actor_id: str, note: str = "") -> Optional[Dict[str, Any]]:
    """Real break — do NOT fold; keep it flagged (P3 would trigger containment)."""
    return _resolve(break_id, "confirmed", actor_id, note=note, fold=False)
