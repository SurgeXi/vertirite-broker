# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""break detection P3 — agent_containment_state (detect -> contain)

Revision ID: 20260913_0017
Revises: 20260913_0016
Create Date: 2026-09-13

The per-agent containment override the gate enforces: elevate the approval floor
or quarantine an agent after a break, operator-liftable. See
broker/protection/breaks/containment_state.py.

Idempotent.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260913_0017"
down_revision = "20260913_0016"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if not _has_table("agent_containment_state"):
        op.create_table(
            "agent_containment_state",
            sa.Column("id", sa.String(length=255), primary_key=True),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("actor_id", sa.String(length=128), nullable=False),
            sa.Column("mode", sa.String(length=32), nullable=False, server_default="none"),
            sa.Column("active", sa.Boolean, nullable=False, server_default=sa.false()),
            sa.Column("reason", sa.Text, nullable=False, server_default=""),
            sa.Column("source_break_id", sa.String(length=64), nullable=True),
            sa.Column("set_by", sa.String(length=128), nullable=False, server_default=""),
            sa.Column("set_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("cleared_by", sa.String(length=128), nullable=True),
            sa.Column("cleared_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_acs_tenant", "agent_containment_state", ["tenant_id"])
        op.create_index("ix_acs_actor", "agent_containment_state", ["actor_id"])
        op.create_index("ix_acs_mode", "agent_containment_state", ["mode"])
        op.create_index("ix_acs_active", "agent_containment_state", ["active"])


def downgrade() -> None:
    if _has_table("agent_containment_state"):
        for idx in ("ix_acs_active", "ix_acs_mode", "ix_acs_actor", "ix_acs_tenant"):
            try:
                op.drop_index(idx, table_name="agent_containment_state")
            except Exception:
                pass
        op.drop_table("agent_containment_state")
