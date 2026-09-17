# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""governor_state — local mode authority store (gate 01)

Revision ID: 20260915_0020
Revises: 20260914_0019
Create Date: 2026-09-15

Single-row store backing the broker's LOCAL SurgeMode authority so LOCKDOWN can
be engaged even when the external surge-core upstream is unreachable. Writes are
authorized only through the governor trust domain (auth.require_governor). See
broker/governor_store.py. Additive + idempotent.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260915_0020"
down_revision = "20260914_0019"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if not _has_table("governor_state"):
        op.create_table(
            "governor_state",
            sa.Column("id", sa.Integer, primary_key=True),  # singleton row (always 1)
            sa.Column("mode", sa.String(length=32), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_by", sa.String(length=128), nullable=False, server_default=""),
        )


def downgrade() -> None:
    if _has_table("governor_state"):
        op.drop_table("governor_state")
