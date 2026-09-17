# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""report_runs — tamper-evident chain of generated reports

Revision ID: 20260520_0009
Revises: 20260520_0008
Create Date: 2026-05-20

Adds a record of each generated Inventory Report PDF, with fingerprint
and chain pointer for tamper-evident verification. See
broker/reports/runs.py.

Idempotent.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260520_0009"
down_revision = "20260520_0008"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return inspector.has_table(name)


def upgrade() -> None:
    if not _has_table("report_runs"):
        op.create_table(
            "report_runs",
            sa.Column("id", sa.String(length=64), primary_key=True),
            sa.Column("report_type", sa.String(length=64), nullable=False, server_default="inventory"),
            sa.Column("tenant_id", sa.String(length=64), nullable=True),
            sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
            sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
            sa.Column("fingerprint", sa.String(length=128), nullable=False),
            sa.Column("previous_fingerprint", sa.String(length=128), nullable=True),
            sa.Column("generated_by", sa.String(length=128), nullable=False),
            sa.Column("summary", sa.Text, nullable=False, server_default=""),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )
        op.create_index("ix_report_runs_tenant", "report_runs", ["tenant_id"])
        op.create_index("ix_report_runs_fingerprint", "report_runs", ["fingerprint"])
        op.create_index("ix_report_runs_type", "report_runs", ["report_type"])


def downgrade() -> None:
    if _has_table("report_runs"):
        for idx in ("ix_report_runs_type", "ix_report_runs_fingerprint", "ix_report_runs_tenant"):
            try:
                op.drop_index(idx, table_name="report_runs")
            except Exception:
                pass
        op.drop_table("report_runs")
