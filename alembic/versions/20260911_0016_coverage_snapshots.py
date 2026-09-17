# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""coverage snapshots (Wave A #2 -- coverage-over-time)

Revision ID: 20260911_0016
Revises: 20260617_0015
Create Date: 2026-09-11

Per-tenant snapshots of the Coverage Map metrics for the exposure-over-time
trend. Idempotent.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260911_0016"
down_revision = "20260617_0015"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if _has_table("coverage_snapshots"):
        return
    op.create_table(
        "coverage_snapshots",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("coverage_pct", sa.Float(), nullable=False, server_default="0"),
        sa.Column("witnessed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("governed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ungoverned", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ungoverned_ai", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ungoverned_suspicious", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_coverage_snapshots_tenant_id", "coverage_snapshots", ["tenant_id"])
    op.create_index("ix_coverage_snapshots_captured_at", "coverage_snapshots", ["captured_at"])


def downgrade() -> None:
    if _has_table("coverage_snapshots"):
        op.drop_table("coverage_snapshots")
