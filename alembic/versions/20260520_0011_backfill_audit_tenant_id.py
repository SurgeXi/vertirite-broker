# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""backfill audit_events.tenant_id from related entities

Revision ID: 20260520_0011
Revises: 20260520_0010
Create Date: 2026-05-20

Migration 0010 added a nullable audit_events.tenant_id column. New
writes after 0010 populate it via the updated callers in
broker/main.py. This migration backfills the column for rows written
BEFORE 0010 landed, where the tenant scope is derivable from the
existing entity_type + entity_id:

  entity_type='tenant'             → tenant_id = entity_id (the tenant itself)
  entity_type='fleet_host'         → tenant_id = fleet_hosts.tenant_id JOIN
  entity_type='witnessed_finding'  → tenant_id = witnessed_findings.tenant_id JOIN
  entity_type='report_run'         → tenant_id = report_runs.tenant_id JOIN

Rows we cannot derive (entity_type='session', 'user', 'system',
'fleet_tool', etc.) keep tenant_id=NULL. That's correct — those events
are tenant-agnostic or system-wide background activity that doesn't
belong in any per-tenant compliance view.

Idempotent: re-running the UPDATEs is a no-op on already-set rows
(the WHERE tenant_id IS NULL filter). Safe to run on dev DBs that
already had partial backfill.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260520_0011"
down_revision = "20260520_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    # 1) entity_type='tenant' → entity_id IS the tenant_id
    op.execute(
        sa.text(
            """
            UPDATE audit_events
            SET tenant_id = entity_id
            WHERE tenant_id IS NULL
              AND entity_type = 'tenant'
            """
        )
    )

    # 2) entity_type='fleet_host' → JOIN to fleet_hosts
    # SQLite doesn't support UPDATE...FROM in older versions but does support
    # the correlated subquery form, which is portable across SQLite + Postgres.
    op.execute(
        sa.text(
            """
            UPDATE audit_events
            SET tenant_id = (
                SELECT fh.tenant_id
                FROM fleet_hosts fh
                WHERE fh.id = audit_events.entity_id
            )
            WHERE tenant_id IS NULL
              AND entity_type = 'fleet_host'
              AND EXISTS (
                  SELECT 1 FROM fleet_hosts fh
                  WHERE fh.id = audit_events.entity_id
              )
            """
        )
    )

    # 3) entity_type='witnessed_finding' → JOIN to witnessed_findings
    op.execute(
        sa.text(
            """
            UPDATE audit_events
            SET tenant_id = (
                SELECT wf.tenant_id
                FROM witnessed_findings wf
                WHERE wf.id = audit_events.entity_id
            )
            WHERE tenant_id IS NULL
              AND entity_type = 'witnessed_finding'
              AND EXISTS (
                  SELECT 1 FROM witnessed_findings wf
                  WHERE wf.id = audit_events.entity_id
              )
            """
        )
    )

    # 4) entity_type='report_run' → JOIN to report_runs (tenant_id may be NULL
    # on the report itself for cross-tenant reports; the join still resolves
    # to NULL in that case, which is what we want — the audit row for a
    # cross-tenant report has no per-tenant scope).
    op.execute(
        sa.text(
            """
            UPDATE audit_events
            SET tenant_id = (
                SELECT rr.tenant_id
                FROM report_runs rr
                WHERE rr.id = audit_events.entity_id
            )
            WHERE tenant_id IS NULL
              AND entity_type = 'report_run'
              AND EXISTS (
                  SELECT 1 FROM report_runs rr
                  WHERE rr.id = audit_events.entity_id
              )
            """
        )
    )


def downgrade() -> None:
    # Downgrade is intentionally a no-op. The column itself is dropped in
    # 0010's downgrade (on Postgres); on SQLite the column is left in place
    # because SQLite's DROP COLUMN support is finicky. Either way, blanking
    # the backfilled values has no practical benefit — the data was always
    # derivable from the entity links, so we leave the cache in place.
    pass
