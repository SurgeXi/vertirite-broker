# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Approval gate lifecycle: deadline, reminders, and who decided.

``expires_at``       when an unanswered request is DENIED automatically
``notify_count``     announcements sent (the first one plus reminders)
``last_notified_at`` when the last announcement went out
``decided_by``       the person (or ``vertirite-timeout``) who decided

Existing pending rows get no deadline here; the sweeper assigns one on its first pass,
so nothing that was already waiting is denied the moment this migration runs.

Revision ID: 20261012_0022
Revises: 20260917_0021
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261012_0022"
down_revision = "20260917_0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("approvals") as batch_op:
        batch_op.add_column(sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("notify_count", sa.Integer(), nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("last_notified_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("decided_by", sa.String(length=128), nullable=True))
        batch_op.create_index("ix_approvals_expires_at", ["expires_at"])


def downgrade() -> None:
    with op.batch_alter_table("approvals") as batch_op:
        batch_op.drop_index("ix_approvals_expires_at")
        batch_op.drop_column("decided_by")
        batch_op.drop_column("last_notified_at")
        batch_op.drop_column("notify_count")
        batch_op.drop_column("expires_at")
