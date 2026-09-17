# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""fleet_manifest.py — persisted inventory of customer fleet hosts.

This is what the operator (or the SE during pilot install) declares about
the customer's fleet: "we expect these hosts to be running Vertirite
governance." Each row tracks one host through the lifecycle:

    declared → governed → archived
            ↘
              archived (operator removed from active inventory)

The discovery probe in PR #24 will add a fourth state, `witnessed` —
a host Vertirite saw AI-shaped activity on but the operator never
declared. Those rows live in a separate table (witnessed_findings)
so the manifest stays customer-declared-truth and the witnessed list
stays vertirite-observed-truth — auditors can distinguish them.

The lifecycle field is independent from the the fleet agent heartbeat;
heartbeat updates `agentd_last_heartbeat` but does NOT auto-archive a
host that goes silent (silence is operationally meaningful — could be
a node down, could be a forgotten host, but it's never our call to
declare a host out-of-scope).
"""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import DateTime, Integer, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, session_scope

logger = logging.getLogger("vertirite.fleet_manifest")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Roles + lifecycle constants
# ---------------------------------------------------------------------------

# Matches the fleet-roles.json discipline from Brain-Ollama/CLAUDE.md so a
# Vertirite-governed customer fleet uses the same vocabulary.
FLEET_ROLES = (
    "production-core",      # broker, policy engine, audit DB hosts
    "production-edge",      # public-facing web / DNS / mail
    "production-store",     # backups, NFS, durable storage
    "production-gpu",       # AI inference / model-serving hosts
    "edge-customer",        # customer-deployed edges (clinic, plant floor)
    "dev-ephemeral",        # operator laptops, throwaway test boxes
)

LIFECYCLE_STATES = (
    "declared",   # operator added; no agent heartbeat yet
    "governed",   # the fleet agent installed and heartbeating
    "archived",   # operator removed from active scope (audit row kept)
)


# ---------------------------------------------------------------------------
# SQLAlchemy table
# ---------------------------------------------------------------------------

class FleetHostTable(Base):
    __tablename__ = "fleet_hosts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(64), nullable=False, default="production-core")
    tags: Mapped[str] = mapped_column(Text, nullable=False, default="")  # comma-separated; small set

    lifecycle_status: Mapped[str] = mapped_column(String(32), nullable=False, default="declared")
    agentd_installed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # 0/1; treat as bool
    agentd_last_heartbeat: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    declared_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    governed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}$")


def validate_hostname(name: str) -> Optional[str]:
    """Return None if valid, else a human-readable error string."""
    if not name or not name.strip():
        return "hostname is required"
    if not _HOSTNAME_RE.match(name.strip()):
        return f"invalid hostname format: {name!r}"
    return None


def _row_to_dict(row: FleetHostTable) -> Dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "hostname": row.hostname,
        "role": row.role,
        "tags": [t for t in (row.tags or "").split(",") if t.strip()],
        "lifecycle_status": row.lifecycle_status,
        "agentd_installed": bool(row.agentd_installed),
        "agentd_last_heartbeat": row.agentd_last_heartbeat.isoformat() if row.agentd_last_heartbeat else None,
        "declared_at": row.declared_at.isoformat() if row.declared_at else None,
        "governed_at": row.governed_at.isoformat() if row.governed_at else None,
        "archived_at": row.archived_at.isoformat() if row.archived_at else None,
        "notes": row.notes,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def declare_host(
    tenant_id: str,
    hostname: str,
    role: str = "production-core",
    tags: Optional[List[str]] = None,
    notes: str = "",
) -> Dict[str, Any]:
    """Create a new fleet host row in lifecycle=declared. Raises ValueError on bad input."""
    err = validate_hostname(hostname)
    if err:
        raise ValueError(err)
    if role not in FLEET_ROLES:
        raise ValueError(f"invalid role {role!r}. Must be one of: {sorted(FLEET_ROLES)}")
    if not tenant_id:
        raise ValueError("tenant_id is required")

    host_id = str(uuid.uuid4())
    with session_scope() as db:
        # Duplicate-hostname-per-tenant check
        existing = db.scalar(
            select(FleetHostTable).where(
                FleetHostTable.tenant_id == tenant_id,
                FleetHostTable.hostname == hostname.strip(),
                FleetHostTable.lifecycle_status != "archived",
            )
        )
        if existing is not None:
            raise ValueError(
                f"host {hostname!r} already declared for this tenant (lifecycle={existing.lifecycle_status})"
            )

        row = FleetHostTable(
            id=host_id,
            tenant_id=tenant_id,
            hostname=hostname.strip(),
            role=role,
            tags=",".join((tags or [])),
            lifecycle_status="declared",
            agentd_installed=0,
            notes=notes or "",
        )
        db.add(row)
        db.flush()
        result = _row_to_dict(row)

    logger.info("Fleet host declared: id=%s hostname=%s role=%s tenant=%s", host_id, hostname, role, tenant_id)
    return result


def list_hosts(tenant_id: Optional[str] = None, include_archived: bool = False) -> List[Dict[str, Any]]:
    """Return all fleet hosts, optionally scoped to one tenant."""
    with session_scope() as db:
        stmt = select(FleetHostTable)
        if tenant_id is not None:
            stmt = stmt.where(FleetHostTable.tenant_id == tenant_id)
        if not include_archived:
            stmt = stmt.where(FleetHostTable.lifecycle_status != "archived")
        rows = db.execute(stmt).scalars().all()
        return [_row_to_dict(r) for r in rows]


def get_host(host_id: str) -> Optional[Dict[str, Any]]:
    with session_scope() as db:
        row = db.get(FleetHostTable, host_id)
        return _row_to_dict(row) if row else None


def update_host(
    host_id: str,
    role: Optional[str] = None,
    tags: Optional[List[str]] = None,
    notes: Optional[str] = None,
    lifecycle_status: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Apply partial update. Returns updated row or None if not found."""
    if role is not None and role not in FLEET_ROLES:
        raise ValueError(f"invalid role {role!r}. Must be one of: {sorted(FLEET_ROLES)}")
    if lifecycle_status is not None and lifecycle_status not in LIFECYCLE_STATES:
        raise ValueError(
            f"invalid lifecycle_status {lifecycle_status!r}. Must be one of: {sorted(LIFECYCLE_STATES)}"
        )

    with session_scope() as db:
        row = db.get(FleetHostTable, host_id)
        if row is None:
            return None
        if role is not None:
            row.role = role
        if tags is not None:
            row.tags = ",".join(tags)
        if notes is not None:
            row.notes = notes
        if lifecycle_status is not None and lifecycle_status != row.lifecycle_status:
            row.lifecycle_status = lifecycle_status
            if lifecycle_status == "governed" and row.governed_at is None:
                row.governed_at = _utc_now()
            if lifecycle_status == "archived":
                row.archived_at = _utc_now()
        db.flush()
        return _row_to_dict(row)


def archive_host(host_id: str) -> Optional[Dict[str, Any]]:
    """Soft delete — flip to archived, keep the row for audit."""
    return update_host(host_id, lifecycle_status="archived")


def record_heartbeat(host_id: str) -> Optional[Dict[str, Any]]:
    """Called by the fleet agent. Updates last_heartbeat and promotes declared→governed."""
    with session_scope() as db:
        row = db.get(FleetHostTable, host_id)
        if row is None:
            return None
        row.agentd_last_heartbeat = _utc_now()
        row.agentd_installed = 1
        if row.lifecycle_status == "declared":
            row.lifecycle_status = "governed"
            row.governed_at = _utc_now()
        db.flush()
        return _row_to_dict(row)


# ---------------------------------------------------------------------------
# Coverage summary — the data behind the "Coverage Map" UI
# ---------------------------------------------------------------------------

def coverage_summary(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """Roll up the fleet manifest into a coverage report.

    Shape:
        {
          "total_declared": int,
          "governed": int,
          "declared_not_governed": int,
          "archived": int,
          "coverage_pct": float,  # governed / (governed + declared_not_governed)
          "hosts": [...],          # full list, decorated with category
        }

    `category` per host is one of: "governed", "declared", "archived".
    The Witnessed-but-unsanctioned column comes from a separate query
    against witnessed_findings (PR #24); this function does NOT pull it
    so the coverage endpoint stays cheap even on large fleets.
    """
    hosts = list_hosts(tenant_id=tenant_id, include_archived=True)

    governed = 0
    declared_not_governed = 0
    archived = 0
    for h in hosts:
        if h["lifecycle_status"] == "governed":
            governed += 1
            h["category"] = "governed"
        elif h["lifecycle_status"] == "archived":
            archived += 1
            h["category"] = "archived"
        else:  # declared
            declared_not_governed += 1
            h["category"] = "declared"

    in_scope = governed + declared_not_governed
    coverage_pct = (governed / in_scope * 100.0) if in_scope > 0 else 0.0

    return {
        "total_declared": len(hosts) - archived,
        "governed": governed,
        "declared_not_governed": declared_not_governed,
        "archived": archived,
        "coverage_pct": round(coverage_pct, 1),
        "hosts": hosts,
    }
