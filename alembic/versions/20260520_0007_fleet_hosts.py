# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""fleet_hosts manifest table

Revision ID: 20260520_0007
Revises: 20260520_0006
Create Date: 2026-05-20

Adds the persisted fleet manifest for Vertirite governance coverage. Each
row is one declared customer host with a lifecycle (declared → governed →
archived) and heartbeat tracking for the the fleet agent daemon on that host.

This is independent from the read-only operational fleet endpoints
(/v1/fleet/health etc.) which talk to the fleet agent live — those query
real-time state, this table records what the operator declared.

Idempotent: uses inspector.has_table() so it's safe on dev DBs that
already had the table created via create_all() before alembic took over.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260520_0007"
down_revision = "20260520_0006"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return inspector.has_table(name)


def upgrade() -> None:
    if not _has_table("fleet_hosts"):
        op.create_table(
            "fleet_hosts",
            sa.Column("id", sa.String(length=64), primary_key=True),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("hostname", sa.String(length=255), nullable=False),
            sa.Column("role", sa.String(length=64), nullable=False, server_default="production-core"),
            sa.Column("tags", sa.Text, nullable=False, server_default=""),
            sa.Column("lifecycle_status", sa.String(length=32), nullable=False, server_default="declared"),
            sa.Column("agentd_installed", sa.Integer, nullable=False, server_default="0"),
            sa.Column("agentd_last_heartbeat", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "declared_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.Column("governed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("notes", sa.Text, nullable=False, server_default=""),
        )
        op.create_index("ix_fleet_hosts_tenant_id", "fleet_hosts", ["tenant_id"])
        op.create_index("ix_fleet_hosts_hostname", "fleet_hosts", ["hostname"])
        op.create_index("ix_fleet_hosts_lifecycle_status", "fleet_hosts", ["lifecycle_status"])


def downgrade() -> None:
    if _has_table("fleet_hosts"):
        op.drop_index("ix_fleet_hosts_lifecycle_status", table_name="fleet_hosts")
        op.drop_index("ix_fleet_hosts_hostname", table_name="fleet_hosts")
        op.drop_index("ix_fleet_hosts_tenant_id", table_name="fleet_hosts")
        op.drop_table("fleet_hosts")
