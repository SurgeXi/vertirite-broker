# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""intelligence_catalogs + intelligence_clock (Mechanism #1)

Revision ID: 20260617_0012
Revises: 20260520_0011
Create Date: 2026-06-17

Persists the perishable intelligence catalog (broker/intelligence/) — the
signed, dated pattern feed that decays without renewal — and the per-tenant
monotonic clock high-water-mark used for anti-rollback decay.

Idempotent.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260617_0012"
down_revision = "20260520_0011"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return inspector.has_table(name)


def upgrade() -> None:
    if not _has_table("intelligence_catalogs"):
        op.create_table(
            "intelligence_catalogs",
            sa.Column("id", sa.String(length=64), primary_key=True),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("catalog_version", sa.Integer, nullable=False),
            sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("tenant_scope", sa.String(length=64), nullable=False, server_default="*"),
            sa.Column("signature", sa.Text, nullable=False),
            sa.Column("payload", sa.Text, nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
            sa.Column(
                "installed_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )
        op.create_index("ix_intel_catalog_tenant", "intelligence_catalogs", ["tenant_id"])
        op.create_index(
            "ix_intel_catalog_tenant_version",
            "intelligence_catalogs",
            ["tenant_id", "catalog_version"],
        )

    if not _has_table("intelligence_clock"):
        op.create_table(
            "intelligence_clock",
            sa.Column("tenant_id", sa.String(length=64), primary_key=True),
            sa.Column("hwm", sa.DateTime(timezone=True), nullable=False),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )


def downgrade() -> None:
    if _has_table("intelligence_clock"):
        op.drop_table("intelligence_clock")
    if _has_table("intelligence_catalogs"):
        for idx in ("ix_intel_catalog_tenant_version", "ix_intel_catalog_tenant"):
            try:
                op.drop_index(idx, table_name="intelligence_catalogs")
            except Exception:
                pass
        op.drop_table("intelligence_catalogs")
