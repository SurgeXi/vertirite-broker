# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""break detection P2 — agent_baseline rate columns

Revision ID: 20260913_0018
Revises: 20260913_0017
Create Date: 2026-09-13

Adds the P2 statistical-band columns to agent_baseline: recent_actions (rolling
timestamps for the rate window) + rate_band_max (learned rate ceiling). Additive
+ idempotent; existing rows get the server defaults. See
broker/protection/breaks/baseline.py.

ALSO a MERGE migration: main carried two heads — the break-detection lineage
(…0016 -> 0017_agent_containment_state) and the pre-existing
20260912_0017_must_change_password lineage. The P1 migration chained off a stale
revision, forking the tree. This revision descends from BOTH heads to converge
them to a single head. The two lineages touch disjoint tables (agent_baseline vs
tenant_users), so the merge is order-independent.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260913_0018"
down_revision = ("20260913_0017", "20260912_0017")
branch_labels = None
depends_on = None


def _cols(table: str) -> set[str]:
    insp = sa.inspect(op.get_bind())
    if not insp.has_table(table):
        return set()
    return {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    cols = _cols("agent_baseline")
    if not cols:
        return
    if "recent_actions" not in cols:
        op.add_column("agent_baseline",
                      sa.Column("recent_actions", sa.Text, nullable=False, server_default="[]"))
    if "rate_band_max" not in cols:
        op.add_column("agent_baseline",
                      sa.Column("rate_band_max", sa.Integer, nullable=False, server_default="0"))


def downgrade() -> None:
    cols = _cols("agent_baseline")
    for c in ("rate_band_max", "recent_actions"):
        if c in cols:
            try:
                op.drop_column("agent_baseline", c)
            except Exception:
                pass  # older SQLite can't drop columns — harmless to leave
