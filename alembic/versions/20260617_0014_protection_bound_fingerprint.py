# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""protection_instance.bound_fingerprint (Mechanism #3 — behavioral binding)

Revision ID: 20260617_0014
Revises: 20260617_0013
Create Date: 2026-06-17

Adds the environment fingerprint this install is bound to (first-run), plus the
last time a foreign environment was observed. A live fingerprint that stops
matching the bound one = a copy in a foreign environment. See
broker/protection/binding.py.

Idempotent + additive (nullable columns).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260617_0014"
down_revision = "20260617_0013"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table(table):
        return False
    return column in {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    if not _has_column("protection_instance", "bound_fingerprint"):
        op.add_column("protection_instance",
                      sa.Column("bound_fingerprint", sa.String(length=128), nullable=True))
    if not _has_column("protection_instance", "last_foreign_at"):
        op.add_column("protection_instance",
                      sa.Column("last_foreign_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    for col in ("last_foreign_at", "bound_fingerprint"):
        if _has_column("protection_instance", col):
            op.drop_column("protection_instance", col)
