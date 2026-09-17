# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Persistence for the perishable intelligence catalog.

Two tables:
  * ``intelligence_catalogs`` — every installed signed bundle (the active one
    per tenant is the highest ``catalog_version``).
  * ``intelligence_clock`` — a monotonic per-tenant high-water-mark of observed
    wall-clock time. Anti-rollback: if the system clock later reads BEFORE this
    mark, the clock was rolled back to fake catalog freshness (catalog.py treats
    that as TAMPERED).

Schema is created by alembic (migration 20260617_0012); the ORM models here are
registered via db.init_db().
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, Integer, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base, session_scope

logger = logging.getLogger("vertirite.intel.store")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IntelligenceCatalogTable(Base):
    __tablename__ = "intelligence_catalogs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    catalog_version: Mapped[int] = mapped_column(Integer, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    tenant_scope: Mapped[str] = mapped_column(String(64), nullable=False, default="*")
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)  # full bundle JSON
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    installed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class IntelligenceClockTable(Base):
    __tablename__ = "intelligence_clock"

    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    hwm: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


# In-process caches (cheap reads on the hot path; DB is source of truth).
_hwm_cache: Dict[str, datetime] = {}


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    """SQLite drops tzinfo on round-trip; treat naive stored values as UTC."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def get_max_version(tenant_id: str) -> int:
    with session_scope() as db:
        row = db.scalar(
            select(IntelligenceCatalogTable.catalog_version)
            .where(IntelligenceCatalogTable.tenant_id == tenant_id)
            .order_by(IntelligenceCatalogTable.catalog_version.desc())
            .limit(1)
        )
    return int(row) if row is not None else 0


def install_catalog(tenant_id: str, payload: Dict[str, Any]) -> None:
    """Persist a verified bundle as the active catalog for the tenant, and
    advance the clock high-water-mark. Assumes the caller already verified the
    signature + version (catalog.verify_and_parse)."""
    now = _utcnow()
    issued = _parse_dt(payload["issued_at"])
    expires = _parse_dt(payload["expires_at"])
    with session_scope() as db:
        db.add(
            IntelligenceCatalogTable(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                catalog_version=int(payload["catalog_version"]),
                issued_at=issued,
                expires_at=expires,
                tenant_scope=str(payload.get("tenant_scope", "*")),
                signature=str(payload["signature"]),
                payload=json.dumps(payload),
                status="active",
                installed_at=now,
            )
        )
    # Stamp the clock at real install time + the bundle's issue time, so a
    # later rollback to before either is detectable.
    advance_clock_hwm(tenant_id, max(now, issued))


def get_active_catalog(tenant_id: str) -> Optional[Dict[str, Any]]:
    """The highest-version active catalog for the tenant, parsed. None if absent."""
    with session_scope() as db:
        row = db.scalar(
            select(IntelligenceCatalogTable)
            .where(
                IntelligenceCatalogTable.tenant_id == tenant_id,
                IntelligenceCatalogTable.status == "active",
            )
            .order_by(IntelligenceCatalogTable.catalog_version.desc())
            .limit(1)
        )
        if row is None:
            return None
        bundle = json.loads(row.payload)
        return {
            "catalog_version": row.catalog_version,
            "issued_at": _aware(row.issued_at).isoformat(),
            "expires_at": _aware(row.expires_at).isoformat(),
            "tenant_scope": row.tenant_scope,
            "patterns": list(bundle.get("patterns", [])),
        }


def get_clock_hwm(tenant_id: str) -> Optional[datetime]:
    cached = _hwm_cache.get(tenant_id)
    if cached is not None:
        return cached
    with session_scope() as db:
        row = db.scalar(
            select(IntelligenceClockTable.hwm).where(
                IntelligenceClockTable.tenant_id == tenant_id
            )
        )
    hwm = _aware(row)
    if hwm is not None:
        _hwm_cache[tenant_id] = hwm
    return hwm


def advance_clock_hwm(tenant_id: str, now: datetime) -> datetime:
    """Set hwm = max(existing, now). Monotonic — never moves backward."""
    now = _aware(now)
    current = get_clock_hwm(tenant_id)
    if current is not None and current >= now:
        return current
    with session_scope() as db:
        existing = db.get(IntelligenceClockTable, tenant_id)
        if existing is None:
            db.add(IntelligenceClockTable(tenant_id=tenant_id, hwm=now, updated_at=_utcnow()))
        else:
            existing.hwm = now
            existing.updated_at = _utcnow()
    _hwm_cache[tenant_id] = now
    return now


def _parse_dt(s: str) -> datetime:
    dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def reset_caches() -> None:
    """Test hook."""
    _hwm_cache.clear()
