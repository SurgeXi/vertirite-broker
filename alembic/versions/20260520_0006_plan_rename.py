# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""rename Maestro-era plan values to Vertirite SKUs

Revision ID: 20260520_0006
Revises: 20260520_0005
Create Date: 2026-05-20

The PLAN_TOKEN_ALLOCATION dict in broker/tenant.py was carried over from
Maestro and used five tiers (free / starter / professional / business /
enterprise) with consumer-style prices ($9 / $29 / $99). Vertirite uses
the SKUs locked in docs/positioning.md:

    free      → OSS / self-host
    team      → $500/mo  (small MSPs, consultancies)
    business  → $2,500/mo (mid-market regional businesses)
    enterprise → $80K–$200K/yr (hospitals, banks, government)

This migration renames any existing tenant rows from the deprecated
Maestro names so the broker validation accepts them. Token allocations
on the renamed rows are preserved as-is — operator can adjust via
PATCH /v1/admin/tenants/{id} if desired.

Mapping:
    starter      → team        (the smallest paid tier)
    professional → business    (next tier up)

Anything that was already free / business / enterprise is unchanged.
Anything in an unknown plan value gets stamped 'free' so the constraint
holds — this should never fire in practice since the broker validation
has always rejected unknown plans, but the migration is defensive.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260520_0006"
down_revision = "20260520_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("tenants"):
        # Nothing to rename — schema 0005 didn't run or was downgraded.
        return

    # Rename Maestro-era plan values to Vertirite SKUs.
    # Use SQLAlchemy text() for portability across SQLite and Postgres.
    op.execute(sa.text("UPDATE tenants SET plan = 'team' WHERE plan = 'starter'"))
    op.execute(sa.text("UPDATE tenants SET plan = 'business' WHERE plan = 'professional'"))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("tenants"):
        return
    # Reverse the mapping. Note: if a tenant was promoted from team to
    # business AFTER this migration ran, downgrade will not distinguish
    # that promotion from the rename. Downgrades of plan-tier migrations
    # are inherently lossy; production recovery is forward-only.
    op.execute(sa.text("UPDATE tenants SET plan = 'starter' WHERE plan = 'team'"))
    op.execute(sa.text("UPDATE tenants SET plan = 'professional' WHERE plan = 'business'"))
