# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Persistence for the installed license — a singleton row (PK "self").

Schema created by alembic (migration 20260617_0015); ORM model registered via
db.init_db().
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base, session_scope

_ROW_ID = "self"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class LicenseTable(Base):
    __tablename__ = "license"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)  # always "self"
    license_id: Mapped[str] = mapped_column(String(64), nullable=False)
    customer: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    sku: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    features: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON list
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)  # full signed JSON
    installed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def install(payload: Dict[str, Any], issued: datetime, expires: datetime) -> None:
    """Persist the verified license as the active one (replaces any prior)."""
    with session_scope() as db:
        row = db.get(LicenseTable, _ROW_ID)
        if row is None:
            row = LicenseTable(id=_ROW_ID)
            db.add(row)
        row.license_id = str(payload.get("license_id", ""))
        row.customer = str(payload.get("customer", ""))
        row.sku = str(payload.get("sku", ""))
        row.features = json.dumps(list(payload.get("features", []) or []))
        row.issued_at = issued
        row.expires_at = expires
        row.signature = str(payload.get("signature", ""))
        row.payload = json.dumps(payload)
        row.installed_at = _utcnow()


def get() -> Optional[Dict[str, Any]]:
    with session_scope() as db:
        row = db.get(LicenseTable, _ROW_ID)
        if row is None:
            return None
        return {
            "license_id": row.license_id,
            "customer": row.customer,
            "sku": row.sku,
            "features": json.loads(row.features or "[]"),
            "issued_at": _aware(row.issued_at),
            "expires_at": _aware(row.expires_at),
        }
