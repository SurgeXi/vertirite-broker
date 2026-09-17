# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Phase 3 record-only: drop execution-result machinery.

The publishable Vertirite broker authorizes, records, and audits decisions;
it does NOT execute. The approve handler no longer runs a tool on approval,
so there is no producer for execution results. This migration removes the
now-vestigial ``execution_results`` table and the ``execution_result_id``
column on ``approvals``. The governed-request ledger (``execution_requests``)
and the audit trail are retained — they are the "records" side of the
control plane.

Revision ID: 20260917_0021
Revises: 20260915_0020
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260917_0021"
down_revision = "20260915_0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("approvals") as batch_op:
        batch_op.drop_column("execution_result_id")
    op.drop_table("execution_results")


def downgrade() -> None:
    op.create_table(
        "execution_results",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("request_id", sa.String(length=64), index=True),
        sa.Column("tool_name", sa.String(length=128), index=True),
        sa.Column("status", sa.String(length=64), index=True),
        sa.Column("summary", sa.Text()),
        sa.Column("output_text", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    with op.batch_alter_table("approvals") as batch_op:
        batch_op.add_column(
            sa.Column("execution_result_id", sa.String(length=64), nullable=True)
        )
