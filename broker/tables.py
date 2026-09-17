# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SessionTable(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(128), index=True)
    client_type: Mapped[str] = mapped_column(String(64))
    session_label: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ProjectTable(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    local_path: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)
    remote_path: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ExecutionRequestTable(Base):
    __tablename__ = "execution_requests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(64), index=True)
    tool_name: Mapped[str] = mapped_column(String(128), index=True)
    payload_json: Mapped[str] = mapped_column(Text())
    mode_at_submit: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(64), index=True)
    summary: Mapped[str] = mapped_column(Text())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AuditEventTable(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    actor_id: Mapped[str] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    entity_type: Mapped[str] = mapped_column(String(128))
    entity_id: Mapped[str] = mapped_column(String(64))
    summary: Mapped[str] = mapped_column(Text())
    # tenant_id (nullable) — populated by callers that know the tenant scope
    # so the audit ledger can be filtered per tenant for compliance review.
    tenant_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ApiTokenTable(Base):
    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(128), index=True)
    token_label: Mapped[str] = mapped_column(String(128), index=True)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ChatMessageTable(Base):
    __tablename__ = "chat_messages"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(64), index=True)
    role: Mapped[str] = mapped_column(String(16))  # "user" or "surge"
    content: Mapped[str] = mapped_column(Text())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ApprovalTable(Base):
    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(64), index=True)
    actor_id: Mapped[str] = mapped_column(String(128), index=True)
    tool_name: Mapped[str] = mapped_column(String(128), index=True)
    mode_at_submit: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(64), index=True)
    summary: Mapped[str] = mapped_column(Text())
    payload_json: Mapped[str] = mapped_column(Text())
    decision_notes: Mapped[str] = mapped_column(Text(), default="")
    surge_task_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
