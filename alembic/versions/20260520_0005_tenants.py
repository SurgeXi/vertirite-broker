# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""tenants, tenant_users, token_usage

Revision ID: 20260520_0005
Revises: 20260328_0004
Create Date: 2026-05-20

Adds the multi-tenant schema to alembic. These tables previously existed
only via Base.metadata.create_all() at broker startup, which is schema
drift — alembic should be the single source of truth.

Idempotent: uses inspector.has_table() so this migration is safe to run
on a database that already has the tables (created by the old
create_all path).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "20260520_0005"
down_revision = "20260328_0004"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return inspector.has_table(name)


def upgrade() -> None:
    if not _has_table("tenants"):
        op.create_table(
            "tenants",
            sa.Column("id", sa.String(length=64), primary_key=True),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("slug", sa.String(length=128), nullable=False, unique=True),
            sa.Column("plan", sa.String(length=64), nullable=False, server_default="free"),
            sa.Column("token_balance", sa.Integer, nullable=False, server_default="1000"),
            sa.Column("tokens_used_total", sa.Integer, nullable=False, server_default="0"),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )
        op.create_index("ix_tenants_slug", "tenants", ["slug"], unique=True)

    if not _has_table("tenant_users"):
        op.create_table(
            "tenant_users",
            sa.Column("id", sa.String(length=64), primary_key=True),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False, unique=True),
            sa.Column("display_name", sa.String(length=255), nullable=False),
            sa.Column("password_hash", sa.String(length=512), nullable=False),
            sa.Column("role", sa.String(length=32), nullable=False, server_default="member"),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
            sa.Column("api_key_hash", sa.String(length=512), nullable=True),
            sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )
        op.create_index("ix_tenant_users_tenant_id", "tenant_users", ["tenant_id"])
        op.create_index("ix_tenant_users_email", "tenant_users", ["email"], unique=True)
        op.create_index("ix_tenant_users_api_key_hash", "tenant_users", ["api_key_hash"])

    if not _has_table("token_usage"):
        op.create_table(
            "token_usage",
            sa.Column("id", sa.String(length=64), primary_key=True),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("user_id", sa.String(length=64), nullable=False),
            sa.Column("action", sa.String(length=64), nullable=False),
            sa.Column("tokens_consumed", sa.Integer, nullable=False),
            sa.Column("model_used", sa.String(length=128), nullable=False, server_default=""),
            sa.Column("session_id", sa.String(length=64), nullable=False, server_default=""),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )
        op.create_index("ix_token_usage_tenant_id", "token_usage", ["tenant_id"])
        op.create_index("ix_token_usage_user_id", "token_usage", ["user_id"])
        op.create_index("ix_token_usage_action", "token_usage", ["action"])


def downgrade() -> None:
    # Down direction is destructive — only the test harness runs downgrade.
    # In production, recovery is forward-only (alembic stamp + new migration).
    if _has_table("token_usage"):
        op.drop_index("ix_token_usage_action", table_name="token_usage")
        op.drop_index("ix_token_usage_user_id", table_name="token_usage")
        op.drop_index("ix_token_usage_tenant_id", table_name="token_usage")
        op.drop_table("token_usage")

    if _has_table("tenant_users"):
        op.drop_index("ix_tenant_users_api_key_hash", table_name="tenant_users")
        op.drop_index("ix_tenant_users_email", table_name="tenant_users")
        op.drop_index("ix_tenant_users_tenant_id", table_name="tenant_users")
        op.drop_table("tenant_users")

    if _has_table("tenants"):
        op.drop_index("ix_tenants_slug", table_name="tenants")
        op.drop_table("tenants")
