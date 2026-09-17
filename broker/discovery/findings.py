# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""witnessed_findings — Vertirite's record of AI activity it saw on the
fleet that does NOT route through the broker.

Each row is one (source_host, target, pattern) observation, with
occurrence_count tracking how many times that same combination has been
re-witnessed by the same agent. Findings have an opt-in remediation
workflow:

    new → acknowledged → governed
         ↘ dismissed (operator marked false-positive)

`new` rows are what the dashboard surfaces with "X findings need review."
`acknowledged` means the operator has looked at it but hasn't yet
decided. `governed` means a fleet_hosts entry was created and the
remediation is underway. `dismissed` means false positive or out of scope.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import DateTime, Integer, String, Text, and_, select
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base, session_scope
from .patterns import lookup_pattern

logger = logging.getLogger("vertirite.discovery.findings")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


SIGNAL_TYPES = ("process", "network", "container", "log")
STATUS_VALUES = ("new", "acknowledged", "governed", "dismissed")
CONFIDENCES = ("low", "medium", "high")


class WitnessedFindingTable(Base):
    __tablename__ = "witnessed_findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    source_host_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    signal_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    pattern_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    pattern_name: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")

    # JSON-encoded evidence blob (small — pid, command line, container name,
    # remote host, port, etc.). Strings only; no payload, no PII.
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    status: Mapped[str] = mapped_column(String(32), nullable=False, default="new", index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    acknowledged_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    governed_host_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    dismiss_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _row_to_dict(row: WitnessedFindingTable) -> Dict[str, Any]:
    try:
        evidence = json.loads(row.evidence) if row.evidence else {}
    except Exception:
        evidence = {"raw": row.evidence}
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "source_host_id": row.source_host_id,
        "target_hostname": row.target_hostname,
        "signal_type": row.signal_type,
        "pattern_id": row.pattern_id,
        "pattern_name": row.pattern_name,
        "confidence": row.confidence,
        "evidence": evidence,
        "status": row.status,
        "occurrence_count": row.occurrence_count,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "acknowledged_by": row.acknowledged_by,
        "acknowledged_at": row.acknowledged_at.isoformat() if row.acknowledged_at else None,
        "governed_host_id": row.governed_host_id,
        "dismiss_reason": row.dismiss_reason,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }



# ---------------------------------------------------------------------------
# Real-time alerting (Wave A #1). A genuinely NEW high-signal finding fires a
# metadata-only alert to the operator's channel. OFF by default
# (alert_webhook_enabled=False) -- nothing leaves the box until an operator
# opts in. Never blocks or breaks the finding insert.
# ---------------------------------------------------------------------------
def build_finding_alert(finding: Dict[str, Any], pattern: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The metadata-only alert payload for a new finding, or None if alerting is
    off / the finding's category is not in the alert set. Pure + fully testable."""
    from ..config import settings as _s
    if not getattr(_s, "alert_webhook_enabled", False):
        return None
    if not (getattr(_s, "alert_webhook_url", "") or ""):
        return None
    category = (pattern or {}).get("category")
    if category not in getattr(_s, "alert_categories", ("suspicious-egress",)):
        return None
    try:
        from .patterns import friendly_name
        fn = friendly_name(finding.get("pattern_id")) or {}
    except Exception:
        fn = {}
    return {
        "type": "vertirite.finding.new",
        "finding_id": finding.get("id"),
        "tenant_id": finding.get("tenant_id"),
        "pattern_id": finding.get("pattern_id"),
        "name": fn.get("name") or finding.get("pattern_name"),
        "vendor": fn.get("vendor"),
        "category": category,
        "confidence": finding.get("confidence"),
        "target_hostname": finding.get("target_hostname"),
        "source_host_id": finding.get("source_host_id"),
        "signal_type": finding.get("signal_type"),
    }


def _default_alert_sender(url: str, payload: Dict[str, Any]) -> None:
    """Fire-and-forget POST in a daemon thread so it never blocks finding insert."""
    import threading

    def _send():
        try:
            import httpx
            httpx.post(url, json=payload, timeout=5.0)
        except Exception:
            logger.warning("finding alert POST failed (non-fatal)", exc_info=True)

    threading.Thread(target=_send, daemon=True).start()


# Overridable in tests.
_alert_sender = _default_alert_sender


def _dispatch_alert(finding: Dict[str, Any], pattern: Dict[str, Any]) -> None:
    try:
        payload = build_finding_alert(finding, pattern)
        if payload is None:
            return
        from ..config import settings as _s
        _alert_sender(_s.alert_webhook_url, payload)
    except Exception:
        logger.warning("finding alert dispatch failed (non-fatal)", exc_info=True)


def report_finding(
    tenant_id: str,
    source_host_id: str,
    target_hostname: str,
    signal_type: str,
    pattern_id: str,
    evidence: Optional[Dict[str, Any]] = None,
    confidence_override: Optional[str] = None,
) -> Dict[str, Any]:
    """Agent calls this for each witnessed match.

    Upsert semantics: if a row with the same (tenant_id, source_host_id,
    target_hostname, signal_type, pattern_id) already exists and is not
    dismissed/governed, increment occurrence_count and update last_seen_at.
    Otherwise insert new.

    The agent doesn't need to know whether this is a new or repeat
    finding — the broker handles the de-dup.
    """
    if signal_type not in SIGNAL_TYPES:
        raise ValueError(f"invalid signal_type {signal_type!r}. Must be one of: {sorted(SIGNAL_TYPES)}")
    pattern = lookup_pattern(pattern_id, tenant_id)
    if pattern is None:
        raise ValueError(f"unknown pattern_id {pattern_id!r}")
    if confidence_override is not None and confidence_override not in CONFIDENCES:
        raise ValueError(f"invalid confidence {confidence_override!r}")

    confidence = confidence_override or pattern["confidence"]
    pattern_name = pattern["name"]
    evidence_json = json.dumps(evidence or {})

    with session_scope() as db:
        existing = db.scalar(
            select(WitnessedFindingTable).where(
                and_(
                    WitnessedFindingTable.tenant_id == tenant_id,
                    WitnessedFindingTable.source_host_id == source_host_id,
                    WitnessedFindingTable.target_hostname == target_hostname,
                    WitnessedFindingTable.signal_type == signal_type,
                    WitnessedFindingTable.pattern_id == pattern_id,
                    WitnessedFindingTable.status.in_(("new", "acknowledged")),
                )
            )
        )
        if existing is not None:
            existing.occurrence_count += 1
            existing.last_seen_at = _utc_now()
            existing.evidence = evidence_json  # latest evidence wins
            existing.confidence = confidence
            db.flush()
            return _row_to_dict(existing)

        row = WitnessedFindingTable(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            source_host_id=source_host_id,
            target_hostname=target_hostname,
            signal_type=signal_type,
            pattern_id=pattern_id,
            pattern_name=pattern_name,
            confidence=confidence,
            evidence=evidence_json,
            status="new",
            occurrence_count=1,
        )
        db.add(row)
        db.flush()
        _result = _row_to_dict(row)
        _dispatch_alert(_result, pattern)  # non-blocking; off by default
        return _result


def list_findings(
    tenant_id: Optional[str] = None,
    status_filter: Optional[List[str]] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    with session_scope() as db:
        stmt = select(WitnessedFindingTable)
        if tenant_id is not None:
            stmt = stmt.where(WitnessedFindingTable.tenant_id == tenant_id)
        if status_filter:
            stmt = stmt.where(WitnessedFindingTable.status.in_(status_filter))
        stmt = stmt.order_by(WitnessedFindingTable.last_seen_at.desc()).limit(limit)
        rows = db.execute(stmt).scalars().all()
        return [_row_to_dict(r) for r in rows]


def get_finding(finding_id: str) -> Optional[Dict[str, Any]]:
    with session_scope() as db:
        row = db.get(WitnessedFindingTable, finding_id)
        return _row_to_dict(row) if row else None


def acknowledge_finding(finding_id: str, actor_id: str) -> Optional[Dict[str, Any]]:
    with session_scope() as db:
        row = db.get(WitnessedFindingTable, finding_id)
        if row is None:
            return None
        if row.status not in ("new",):
            # Already acknowledged / governed / dismissed — return current state
            return _row_to_dict(row)
        row.status = "acknowledged"
        row.acknowledged_by = actor_id
        row.acknowledged_at = _utc_now()
        db.flush()
        return _row_to_dict(row)


def mark_governed(finding_id: str, governed_host_id: str) -> Optional[Dict[str, Any]]:
    """Called when the operator clicks 'Bring under governance' and a
    fleet_hosts row is created from this finding."""
    with session_scope() as db:
        row = db.get(WitnessedFindingTable, finding_id)
        if row is None:
            return None
        row.status = "governed"
        row.governed_host_id = governed_host_id
        if row.acknowledged_at is None:
            row.acknowledged_at = _utc_now()
        db.flush()
        return _row_to_dict(row)


def dismiss_finding(finding_id: str, actor_id: str, reason: str) -> Optional[Dict[str, Any]]:
    with session_scope() as db:
        row = db.get(WitnessedFindingTable, finding_id)
        if row is None:
            return None
        row.status = "dismissed"
        row.dismiss_reason = (reason or "").strip()[:1024]
        row.acknowledged_by = actor_id
        row.acknowledged_at = _utc_now()
        db.flush()
        return _row_to_dict(row)


def summary(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """Counts by status — for the dashboard header chip + stat card."""
    with session_scope() as db:
        stmt = select(WitnessedFindingTable.status, WitnessedFindingTable.id)
        if tenant_id is not None:
            stmt = stmt.where(WitnessedFindingTable.tenant_id == tenant_id)
        rows = db.execute(stmt).all()

    by_status = {"new": 0, "acknowledged": 0, "governed": 0, "dismissed": 0}
    for status, _ in rows:
        by_status[status] = by_status.get(status, 0) + 1
    return {"total": len(rows), "by_status": by_status}
