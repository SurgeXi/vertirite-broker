# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""execution results

Revision ID: 20260328_0003
Revises: 20260328_0002
Create Date: 2026-03-28
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260328_0003"
down_revision = "20260328_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "execution_results",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("output_text", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_execution_results_request_id", "execution_results", ["request_id"])
    op.create_index("ix_execution_results_tool_name", "execution_results", ["tool_name"])
    op.create_index("ix_execution_results_status", "execution_results", ["status"])


def downgrade() -> None:
    op.drop_index("ix_execution_results_status", table_name="execution_results")
    op.drop_index("ix_execution_results_tool_name", table_name="execution_results")
    op.drop_index("ix_execution_results_request_id", table_name="execution_results")
    op.drop_table("execution_results")
