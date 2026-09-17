# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""initial broker schema

Revision ID: 20260328_0001
Revises:
Create Date: 2026-03-28
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260328_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sessions",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("user_id", sa.String(length=128), nullable=False),
        sa.Column("client_type", sa.String(length=64), nullable=False),
        sa.Column("session_label", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])

    op.create_table(
        "projects",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=True),
        sa.Column("local_path", sa.Text(), nullable=True),
        sa.Column("remote_path", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_projects_name", "projects", ["name"])
    op.create_index("ix_projects_tenant_id", "projects", ["tenant_id"])

    op.create_table(
        "execution_requests",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("mode_at_submit", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_execution_requests_session_id", "execution_requests", ["session_id"])
    op.create_index("ix_execution_requests_tool_name", "execution_requests", ["tool_name"])
    op.create_index("ix_execution_requests_status", "execution_requests", ["status"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("actor_id", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("entity_type", sa.String(length=128), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_events_actor_id", "audit_events", ["actor_id"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])

    op.create_table(
        "api_tokens",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("user_id", sa.String(length=128), nullable=False),
        sa.Column("token_label", sa.String(length=128), nullable=False),
        sa.Column("token_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_api_tokens_user_id", "api_tokens", ["user_id"])
    op.create_index("ix_api_tokens_token_label", "api_tokens", ["token_label"])
    op.create_index("ix_api_tokens_token_hash", "api_tokens", ["token_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_api_tokens_token_hash", table_name="api_tokens")
    op.drop_index("ix_api_tokens_token_label", table_name="api_tokens")
    op.drop_index("ix_api_tokens_user_id", table_name="api_tokens")
    op.drop_table("api_tokens")

    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_index("ix_audit_events_actor_id", table_name="audit_events")
    op.drop_table("audit_events")

    op.drop_index("ix_execution_requests_status", table_name="execution_requests")
    op.drop_index("ix_execution_requests_tool_name", table_name="execution_requests")
    op.drop_index("ix_execution_requests_session_id", table_name="execution_requests")
    op.drop_table("execution_requests")

    op.drop_index("ix_projects_tenant_id", table_name="projects")
    op.drop_index("ix_projects_name", table_name="projects")
    op.drop_table("projects")

    op.drop_index("ix_sessions_user_id", table_name="sessions")
    op.drop_table("sessions")
