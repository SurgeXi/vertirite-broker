# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""protection_instance singleton (Mechanism #2 — self-narcs-theft)

Revision ID: 20260617_0013
Revises: 20260617_0012
Create Date: 2026-06-17

The broker's own install identity (instance_id + canary, generated first-run)
plus the health of its phone-home channel (last success + consecutive failures),
used to raise a `self-egress-suppressed` finding when the channel is firewalled.
See broker/protection/.

Idempotent.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260617_0013"
down_revision = "20260617_0012"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return inspector.has_table(name)


def upgrade() -> None:
    if not _has_table("protection_instance"):
        op.create_table(
            "protection_instance",
            sa.Column("id", sa.String(length=16), primary_key=True),
            sa.Column("instance_id", sa.String(length=64), nullable=False),
            sa.Column("canary", sa.String(length=128), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_feed_success_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("consecutive_feed_failures", sa.Integer, nullable=False, server_default="0"),
            sa.Column("last_suppression_at", sa.DateTime(timezone=True), nullable=True),
        )


def downgrade() -> None:
    if _has_table("protection_instance"):
        op.drop_table("protection_instance")
