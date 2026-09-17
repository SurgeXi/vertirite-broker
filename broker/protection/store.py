# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Persistence for self-protection — a singleton instance identity + beacon state.

One row (PK fixed ``"self"``): the broker's own identity (instance_id + canary,
generated first-run) and the health of its phone-home channel (last success +
consecutive failures). Schema is created by alembic (migration 20260617_0013);
the ORM model is registered via db.init_db().

Mirrors the singleton + in-process cache style of intelligence/store.py.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base, session_scope

logger = logging.getLogger("vertirite.protection.store")

_ROW_ID = "self"  # there is exactly one self.


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ProtectionInstanceTable(Base):
    __tablename__ = "protection_instance"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)  # always "self"
    instance_id: Mapped[str] = mapped_column(String(64), nullable=False)
    canary: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_feed_success_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    consecutive_feed_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_suppression_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Mechanism #3 — behavioral binding: the environment fingerprint this install
    # was bound to (first-run). A live fingerprint that stops matching = a copy in
    # a foreign environment. Nullable: pre-existing rows bind lazily on first check.
    bound_fingerprint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    last_foreign_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def get_or_create(instance_id: str, canary: str) -> dict:
    """Return the singleton, creating it first-run with the given id + canary."""
    with session_scope() as db:
        row = db.get(ProtectionInstanceTable, _ROW_ID)
        if row is None:
            row = ProtectionInstanceTable(
                id=_ROW_ID, instance_id=instance_id, canary=canary, created_at=_utcnow(),
                consecutive_feed_failures=0,
            )
            db.add(row)
            db.flush()
        return _as_dict(row)


def _as_dict(row: "ProtectionInstanceTable") -> dict:
    return {
        "instance_id": row.instance_id,
        "canary": row.canary,
        "created_at": _aware(row.created_at),
        "last_feed_success_at": _aware(row.last_feed_success_at),
        "consecutive_feed_failures": int(row.consecutive_feed_failures or 0),
        "last_suppression_at": _aware(row.last_suppression_at),
    }


def get() -> Optional[dict]:
    with session_scope() as db:
        row = db.get(ProtectionInstanceTable, _ROW_ID)
        return _as_dict(row) if row else None


def record_success() -> None:
    """A reachable feed: stamp success, reset the failure counter, and close
    any suppression episode (so a future re-block re-alerts immediately
    instead of being throttled by the OLD episode's stamp)."""
    with session_scope() as db:
        row = db.get(ProtectionInstanceTable, _ROW_ID)
        if row is None:
            return
        row.last_feed_success_at = _utcnow()
        row.consecutive_feed_failures = 0
        row.last_suppression_at = None


def record_failure() -> int:
    """An unreachable feed: increment + return the new consecutive-failure count."""
    with session_scope() as db:
        row = db.get(ProtectionInstanceTable, _ROW_ID)
        if row is None:
            return 0
        row.consecutive_feed_failures = int(row.consecutive_feed_failures or 0) + 1
        return row.consecutive_feed_failures


def mark_suppression() -> None:
    with session_scope() as db:
        row = db.get(ProtectionInstanceTable, _ROW_ID)
        if row is not None:
            row.last_suppression_at = _utcnow()


def get_bound_fingerprint() -> Optional[str]:
    with session_scope() as db:
        row = db.get(ProtectionInstanceTable, _ROW_ID)
        return row.bound_fingerprint if row else None


def set_bound_fingerprint(fingerprint: str) -> None:
    """Bind (or re-bind) this install to an environment fingerprint."""
    with session_scope() as db:
        row = db.get(ProtectionInstanceTable, _ROW_ID)
        if row is not None:
            row.bound_fingerprint = fingerprint


def mark_foreign() -> None:
    with session_scope() as db:
        row = db.get(ProtectionInstanceTable, _ROW_ID)
        if row is not None:
            row.last_foreign_at = _utcnow()
