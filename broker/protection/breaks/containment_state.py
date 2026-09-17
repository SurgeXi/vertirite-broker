# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""agent_containment_state — the detect -> contain bridge (P3).

Containment (docs/CONTAINMENT.md) gates *the next action* by the chokepoint it
crosses. Break Detection (P1/P2) watches *the agent* over time. P3 joins them: an
open/confirmed break can put the agent into an elevated containment state, and the
gate then enforces that state on every subsequent action until an operator lifts it.

Modes (each only ever RAISES the floor — additive, deterministic, like containment):
  * ``none``                 — no override.
  * ``elevated_gated``       — floor every action to GATED (operator approval).
  * ``elevated_high_stakes`` — floor to HIGH_STAKES (approval + disagreement review).
  * ``quarantined``          — deny every action (fail-closed for this agent).

Safety rules:
  * OFF by default — gated by ``VERTIRITE_DETECT_CONTAIN=1`` (separate from P1's
    detection flag; containment is the riskier half and switches independently).
  * **Auto-clamp is conservative**: only a ``first_irreversible`` break auto-sets
    ``elevated_high_stakes`` (per FEATURE-break-detection.md resolved decision —
    money movement / mass deletion). Everything else is alert-only. **Never
    auto-quarantines** — quarantine is operator-only.
  * Always operator-liftable. Never lowers a floor. No model in the loop.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Optional, Tuple

from sqlalchemy import Boolean, DateTime, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column

from ...db import Base, session_scope
from ... import approval_types as caps

logger = logging.getLogger("vertirite.breaks.containment_state")

MODES = ("none", "elevated_gated", "elevated_high_stakes", "quarantined")

_FLOOR = {
    "elevated_gated": caps.ApprovalClass.GATED,
    "elevated_high_stakes": caps.ApprovalClass.HIGH_STAKES,
}
_RANK = {
    caps.ApprovalClass.SAFE: 0,
    caps.ApprovalClass.SCOPED: 1,
    caps.ApprovalClass.GATED: 2,
    caps.ApprovalClass.HIGH_STAKES: 3,
}


def enabled() -> bool:
    # Operator runtime override (interface toggle) wins over the env default.
    from . import runtime_config
    return runtime_config.effective("detect_contain")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sid(tenant_id: str, actor_id: str) -> str:
    return f"{tenant_id}::{actor_id}"


class AgentContainmentStateTable(Base):
    __tablename__ = "agent_containment_state"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)  # tenant::actor
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="none", index=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source_break_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    set_by: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    set_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    cleared_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    cleared_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


def _row_to_dict(row: AgentContainmentStateTable) -> dict:
    return {
        "tenant_id": row.tenant_id, "actor_id": row.actor_id,
        "mode": row.mode, "active": row.active, "reason": row.reason,
        "source_break_id": row.source_break_id, "set_by": row.set_by,
        "set_at": row.set_at.isoformat() if row.set_at else None,
        "cleared_by": row.cleared_by,
        "cleared_at": row.cleared_at.isoformat() if row.cleared_at else None,
    }


def set_state(tenant_id: str, actor_id: str, mode: str, reason: str, set_by: str,
              source_break_id: Optional[str] = None, *, only_raise: bool = False) -> dict:
    """Set (or raise) the agent's containment override.

    ``only_raise=True`` (used by auto-clamp) will not downgrade an already-stricter
    active state — auto-clamp never weakens an operator's stronger clamp.
    """
    if mode not in MODES:
        raise ValueError(f"invalid mode {mode!r}; must be one of {MODES}")
    with session_scope() as db:
        sid = _sid(tenant_id, actor_id)
        row = db.get(AgentContainmentStateTable, sid)
        if row is None:
            row = AgentContainmentStateTable(id=sid, tenant_id=tenant_id, actor_id=actor_id)
            db.add(row)
        if only_raise and row.active and _strictness(row.mode) >= _strictness(mode):
            return _row_to_dict(row)  # keep the stronger existing clamp
        row.mode = mode
        row.active = mode != "none"
        row.reason = (reason or "").strip()[:1024]
        row.source_break_id = source_break_id
        row.set_by = set_by
        row.set_at = _utc_now()
        row.cleared_by = None
        row.cleared_at = None
        db.flush()
        return _row_to_dict(row)


def _strictness(mode: str) -> int:
    order = {"none": 0, "elevated_gated": 1, "elevated_high_stakes": 2, "quarantined": 3}
    return order.get(mode, 0)


def clear_state(tenant_id: str, actor_id: str, cleared_by: str) -> Optional[dict]:
    with session_scope() as db:
        row = db.get(AgentContainmentStateTable, _sid(tenant_id, actor_id))
        if row is None:
            return None
        row.mode = "none"
        row.active = False
        row.cleared_by = cleared_by
        row.cleared_at = _utc_now()
        db.flush()
        return _row_to_dict(row)


def get_state(tenant_id: str, actor_id: str) -> Optional[dict]:
    with session_scope() as db:
        row = db.get(AgentContainmentStateTable, _sid(tenant_id, actor_id))
        if row is None or not row.active:
            return None
        return _row_to_dict(row)


def enforce(tenant_id: str, actor_id: str,
            eff_class: caps.ApprovalClass) -> Tuple[caps.ApprovalClass, bool, str]:
    """Consulted by the gate. Returns (possibly-elevated class, quarantined?, reason).
    Only ever raises the class. Quarantine signals the gate to deny."""
    st = get_state(tenant_id, actor_id)
    if not st:
        return eff_class, False, ""
    if st["mode"] == "quarantined":
        return eff_class, True, st["reason"] or "agent quarantined"
    floor = _FLOOR.get(st["mode"])
    if floor is not None and _RANK[floor] > _RANK[eff_class]:
        return floor, False, st["reason"]
    return eff_class, False, st["reason"]


def auto_clamp_for_break(tenant_id: str, actor_id: str, reason: str,
                         break_id: Optional[str], severity: str) -> Optional[dict]:
    """Conservative auto-clamp policy. Today: only a first_irreversible break
    auto-elevates to HIGH_STAKES (money movement / mass deletion). Never
    auto-quarantines. only_raise so it can't weaken an operator's clamp."""
    if reason == "first_irreversible":
        return set_state(
            tenant_id, actor_id, "elevated_high_stakes",
            reason=f"auto-clamp: {reason} break (severity {severity})",
            set_by="vertirite:auto", source_break_id=break_id, only_raise=True,
        )
    return None
