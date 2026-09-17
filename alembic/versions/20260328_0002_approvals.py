# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""approval records

Revision ID: 20260328_0002
Revises: 20260328_0001
Create Date: 2026-03-28
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260328_0002"
down_revision = "20260328_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "approvals",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("actor_id", sa.String(length=128), nullable=False),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("mode_at_submit", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("decision_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("surge_task_id", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_approvals_session_id", "approvals", ["session_id"])
    op.create_index("ix_approvals_actor_id", "approvals", ["actor_id"])
    op.create_index("ix_approvals_tool_name", "approvals", ["tool_name"])
    op.create_index("ix_approvals_status", "approvals", ["status"])
    op.create_index("ix_approvals_surge_task_id", "approvals", ["surge_task_id"])


def downgrade() -> None:
    op.drop_index("ix_approvals_surge_task_id", table_name="approvals")
    op.drop_index("ix_approvals_status", table_name="approvals")
    op.drop_index("ix_approvals_tool_name", table_name="approvals")
    op.drop_index("ix_approvals_actor_id", table_name="approvals")
    op.drop_index("ix_approvals_session_id", table_name="approvals")
    op.drop_table("approvals")
