# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""break detection P1 — agent_baseline + break_events

Revision ID: 20260913_0016
Revises: 20260617_0015
Create Date: 2026-09-13

Adds the per-agent behavioral baseline and the detected-break record for
Break Detection P1. See broker/protection/breaks/ for the models + helpers.

Idempotent.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260913_0016"
down_revision = "20260617_0015"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return sa.inspect(bind).has_table(name)


def upgrade() -> None:
    if not _has_table("agent_baseline"):
        op.create_table(
            "agent_baseline",
            sa.Column("id", sa.String(length=255), primary_key=True),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("actor_id", sa.String(length=128), nullable=False),
            sa.Column("capabilities", sa.Text, nullable=False, server_default="[]"),
            sa.Column("egress_destinations", sa.Text, nullable=False, server_default="[]"),
            sa.Column("data_classes", sa.Text, nullable=False, server_default="[]"),
            sa.Column("active_hours", sa.Text, nullable=False, server_default="[]"),
            sa.Column("credential_seen", sa.Boolean, nullable=False, server_default=sa.false()),
            sa.Column("irreversible_seen", sa.Boolean, nullable=False, server_default=sa.false()),
            sa.Column("action_count", sa.Integer, nullable=False, server_default="0"),
            sa.Column("state", sa.String(length=16), nullable=False, server_default="warming"),
            sa.Column("recent_denials", sa.Text, nullable=False, server_default="[]"),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_agent_baseline_tenant", "agent_baseline", ["tenant_id"])
        op.create_index("ix_agent_baseline_actor", "agent_baseline", ["actor_id"])
        op.create_index("ix_agent_baseline_state", "agent_baseline", ["state"])

    if not _has_table("break_events"):
        op.create_table(
            "break_events",
            sa.Column("id", sa.String(length=64), primary_key=True),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("actor_id", sa.String(length=128), nullable=False),
            sa.Column("reason", sa.String(length=64), nullable=False),
            sa.Column("severity", sa.String(length=16), nullable=False),
            sa.Column("title", sa.Text, nullable=False),
            sa.Column("target", sa.String(length=255), nullable=False, server_default=""),
            sa.Column("chokepoints", sa.Text, nullable=False, server_default="[]"),
            sa.Column("evidence", sa.Text, nullable=False, server_default="{}"),
            sa.Column("status", sa.String(length=16), nullable=False, server_default="open"),
            sa.Column("occurrence_count", sa.Integer, nullable=False, server_default="1"),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("resolved_by", sa.String(length=128), nullable=True),
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resolve_note", sa.Text, nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_break_events_tenant", "break_events", ["tenant_id"])
        op.create_index("ix_break_events_actor", "break_events", ["actor_id"])
        op.create_index("ix_break_events_reason", "break_events", ["reason"])
        op.create_index("ix_break_events_severity", "break_events", ["severity"])
        op.create_index("ix_break_events_status", "break_events", ["status"])


def downgrade() -> None:
    for tbl, idxs in (
        ("break_events", ("ix_break_events_status", "ix_break_events_severity",
                           "ix_break_events_reason", "ix_break_events_actor",
                           "ix_break_events_tenant")),
        ("agent_baseline", ("ix_agent_baseline_state", "ix_agent_baseline_actor",
                            "ix_agent_baseline_tenant")),
    ):
        if _has_table(tbl):
            for idx in idxs:
                try:
                    op.drop_index(idx, table_name=tbl)
                except Exception:
                    pass
            op.drop_table(tbl)
