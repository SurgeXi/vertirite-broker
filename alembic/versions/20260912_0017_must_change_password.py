# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""must_change_password on tenant_users — force a password change at first login

Revision ID: 20260912_0017
Revises: 20260911_0016
Create Date: 2026-09-12
"""
from alembic import op
import sqlalchemy as sa


revision = "20260912_0017"
down_revision = "20260911_0016"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    try:
        return any(c["name"] == column for c in insp.get_columns(table))
    except Exception:
        return False


def upgrade() -> None:
    if _has_column("tenant_users", "must_change_password"):
        return
    op.add_column(
        "tenant_users",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    if _has_column("tenant_users", "must_change_password"):
        op.drop_column("tenant_users", "must_change_password")
