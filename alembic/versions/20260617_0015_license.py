# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""license table (license-token layer)

Revision ID: 20260617_0015
Revises: 20260617_0014
Create Date: 2026-06-17

The installed signed license (singleton). Gates premium features. See
broker/licensing/.

Idempotent.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260617_0015"
down_revision = "20260617_0014"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return sa.inspect(bind).has_table(name)


def upgrade() -> None:
    if not _has_table("license"):
        op.create_table(
            "license",
            sa.Column("id", sa.String(length=16), primary_key=True),
            sa.Column("license_id", sa.String(length=64), nullable=False),
            sa.Column("customer", sa.String(length=255), nullable=False, server_default=""),
            sa.Column("sku", sa.String(length=64), nullable=False, server_default=""),
            sa.Column("features", sa.Text, nullable=False, server_default="[]"),
            sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("signature", sa.Text, nullable=False),
            sa.Column("payload", sa.Text, nullable=False),
            sa.Column("installed_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.func.now()),
        )


def downgrade() -> None:
    if _has_table("license"):
        op.drop_table("license")
