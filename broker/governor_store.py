# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Gate 01 — the LOCAL mode-authority store.

The broker's governance gate reads a global :class:`SurgeMode`
(AUTONOMOUS / CONTROLLED / ESCALATION_REQUIRED / LOCKDOWN). Historically the
ONLY source of that mode was an external surge-core service; with surge-core
unreachable fleet-wide the mode was pinned at a permissive default and LOCKDOWN
could not be engaged at all — the gate had no live authority.

This module is that authority, localized INTO the broker and persisted so it
survives a restart. It is a single-row store (``governor_state``). Writes are
authorized only through the governor trust domain (``auth.require_governor``),
which the agent plane can never hold — mode authority stays out-of-band.

Default when never set: LOCKDOWN when ``governor_fail_closed`` (the Vertirite
default — deny by default until a governor sets a mode), else CONTROLLED.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .config import settings
from .db import Base, session_scope
from .models import SurgeMode

# The store holds exactly one row. Its primary key is fixed so get/set always
# address the same singleton regardless of how many times it's written.
_SINGLETON_ID = 1


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class GovernorStateTable(Base):
    __tablename__ = "governor_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)  # singleton (always 1)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    updated_by: Mapped[str] = mapped_column(String(128), nullable=False, default="")


def _default_mode() -> SurgeMode:
    """Mode when the store has never been set.

    Bootstrap safety (anti-brick): fail-closed's LOCKDOWN default applies ONLY
    once a governor credential EXISTS. The set-path (POST /v1/mode) is 503-gated
    until ``governor_token`` is provisioned, so a LOCKDOWN default on an
    UN-provisioned box would be an unliftable brick on a customer's first boot —
    nothing could lift it because no one can yet authenticate as governor.

    Precedence:
      * no governor credential provisioned → CONTROLLED (governable, not bricked)
      * governor credential present + fail_closed → LOCKDOWN (a GOVERNED system
        with no explicit mode yet fails closed)
      * governor credential present + not fail_closed → CONTROLLED

    surge-core (upstream) can still TIGHTEN either default up to LOCKDOWN, so an
    un-provisioned box is not left un-lockable by an operator-of-record.
    """
    if not settings.governor_token:
        return SurgeMode.CONTROLLED
    return SurgeMode.LOCKDOWN if settings.governor_fail_closed else SurgeMode.CONTROLLED


def get_local_mode() -> SurgeMode:
    """The local authoritative SurgeMode.

    Returns the persisted mode if one has been set; otherwise the fail-closed
    default. A missing table or a transient DB error also falls back to the
    default (never to a permissive value on the fail-closed path).
    """
    try:
        with session_scope() as db:
            row = db.get(GovernorStateTable, _SINGLETON_ID)
            if row is None:
                return _default_mode()
            try:
                return SurgeMode(row.mode)
            except ValueError:
                return _default_mode()
    except Exception:
        # table missing / DB blip → fail-safe default (LOCKDOWN when fail_closed)
        return _default_mode()


def set_local_mode(mode: SurgeMode, actor: str) -> SurgeMode:
    """Persist the local authoritative mode. Returns the mode set."""
    with session_scope() as db:
        row = db.get(GovernorStateTable, _SINGLETON_ID)
        if row is None:
            row = GovernorStateTable(id=_SINGLETON_ID)
            db.add(row)
        row.mode = mode.value
        row.updated_by = actor
        row.updated_at = _utc_now()
        db.flush()
    return mode
