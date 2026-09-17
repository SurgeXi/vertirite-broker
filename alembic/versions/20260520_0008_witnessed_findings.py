# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""witnessed_findings table (Pillar B)

Revision ID: 20260520_0008
Revises: 20260520_0007
Create Date: 2026-05-20

Adds the persisted record of AI-shaped activity the fleet agent witnessed on
governed hosts but that does NOT route through the broker. See
broker/discovery/findings.py for the model + helpers.

Idempotent.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260520_0008"
down_revision = "20260520_0007"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return inspector.has_table(name)


def upgrade() -> None:
    if not _has_table("witnessed_findings"):
        op.create_table(
            "witnessed_findings",
            sa.Column("id", sa.String(length=64), primary_key=True),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("source_host_id", sa.String(length=64), nullable=False),
            sa.Column("target_hostname", sa.String(length=255), nullable=False),
            sa.Column("signal_type", sa.String(length=32), nullable=False),
            sa.Column("pattern_id", sa.String(length=128), nullable=False),
            sa.Column("pattern_name", sa.String(length=255), nullable=False),
            sa.Column("confidence", sa.String(length=16), nullable=False, server_default="medium"),
            sa.Column("evidence", sa.Text, nullable=False, server_default="{}"),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="new"),
            sa.Column("occurrence_count", sa.Integer, nullable=False, server_default="1"),
            sa.Column(
                "first_seen_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.Column(
                "last_seen_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.Column("acknowledged_by", sa.String(length=128), nullable=True),
            sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("governed_host_id", sa.String(length=64), nullable=True),
            sa.Column("dismiss_reason", sa.Text, nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )
        op.create_index("ix_witnessed_tenant", "witnessed_findings", ["tenant_id"])
        op.create_index("ix_witnessed_source_host", "witnessed_findings", ["source_host_id"])
        op.create_index("ix_witnessed_target_host", "witnessed_findings", ["target_hostname"])
        op.create_index("ix_witnessed_signal_type", "witnessed_findings", ["signal_type"])
        op.create_index("ix_witnessed_pattern_id", "witnessed_findings", ["pattern_id"])
        op.create_index("ix_witnessed_status", "witnessed_findings", ["status"])


def downgrade() -> None:
    if _has_table("witnessed_findings"):
        for idx in (
            "ix_witnessed_status",
            "ix_witnessed_pattern_id",
            "ix_witnessed_signal_type",
            "ix_witnessed_target_host",
            "ix_witnessed_source_host",
            "ix_witnessed_tenant",
        ):
            try:
                op.drop_index(idx, table_name="witnessed_findings")
            except Exception:
                pass
        op.drop_table("witnessed_findings")
