# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""audit_events.tenant_id — per-tenant audit drill-down

Revision ID: 20260520_0010
Revises: 20260520_0009
Create Date: 2026-05-20

Adds a nullable tenant_id column to audit_events so the audit ledger can
be filtered per tenant — the compliance-reviewer use case ("show me
every action for tenant X this month"). Existing rows keep tenant_id=NULL;
callers that know the tenant scope start populating it on new writes.

Idempotent.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260520_0010"
down_revision = "20260520_0009"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table(table):
        return False
    return column in {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    if not _has_column("audit_events", "tenant_id"):
        op.add_column(
            "audit_events",
            sa.Column("tenant_id", sa.String(length=64), nullable=True),
        )
        op.create_index(
            "ix_audit_events_tenant_id", "audit_events", ["tenant_id"]
        )


def downgrade() -> None:
    if _has_column("audit_events", "tenant_id"):
        try:
            op.drop_index("ix_audit_events_tenant_id", table_name="audit_events")
        except Exception:
            pass
        # SQLite doesn't always support drop column; for v1 leave the
        # column on downgrade (still nullable, no harm). Postgres handles
        # this cleanly via ALTER TABLE DROP COLUMN.
        bind = op.get_bind()
        if bind.dialect.name != "sqlite":
            op.drop_column("audit_events", "tenant_id")
