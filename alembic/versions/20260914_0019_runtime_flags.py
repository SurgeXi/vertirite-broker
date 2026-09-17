# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""runtime_flags — operator-settable break-detection toggles

Revision ID: 20260914_0019
Revises: 20260913_0018
Create Date: 2026-09-14

Backs the interface toggles for VERTIRITE_BREAK_DETECTION / VERTIRITE_DETECT_CONTAIN
(an override row wins over the env default). See
broker/protection/breaks/runtime_config.py. Idempotent.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260914_0019"
down_revision = "20260913_0018"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if not _has_table("runtime_flags"):
        op.create_table(
            "runtime_flags",
            sa.Column("key", sa.String(length=64), primary_key=True),
            sa.Column("value", sa.String(length=16), nullable=False),
            sa.Column("updated_by", sa.String(length=128), nullable=False, server_default=""),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("note", sa.Text, nullable=True),
        )


def downgrade() -> None:
    if _has_table("runtime_flags"):
        op.drop_table("runtime_flags")
