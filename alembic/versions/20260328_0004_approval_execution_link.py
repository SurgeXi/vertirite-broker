# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""approval execution link

Revision ID: 20260328_0004
Revises: 20260328_0003
Create Date: 2026-03-28
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260328_0004"
down_revision = "20260328_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("approvals", sa.Column("execution_result_id", sa.String(length=64), nullable=True))
    op.create_index("ix_approvals_execution_result_id", "approvals", ["execution_result_id"])


def downgrade() -> None:
    op.drop_index("ix_approvals_execution_result_id", table_name="approvals")
    op.drop_column("approvals", "execution_result_id")
