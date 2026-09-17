# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""support.py — customer-facing issue reporting + surge triage.

Flow:
  1. user posts to /v1/tickets with {subject, body, product, attachments}
  2. broker persists; gathers user's recent audit_events as context
  4. surge attempts triage / safe auto-fix (gated through Phase D for any
     MUTATE+ tool); returns a triage_summary + status update
  5. broker writes the result back to the ticket; if the ticket needs
     operator attention, ntfy-push to Todd's phone
  6. resolution / reply notifications go back to the user via the
     unprompted-speech channel (Slice 2, peer_stream.post_unprompted)

Status state machine:
    open                 — newly created; surge hasn't triaged yet
    triaging             — surge is mid-call
    auto_resolved        — surge fixed it (logged in attempted_action_*)
    awaiting_approval    — surge proposed a fix; user must approve via gate
    awaiting_user_info   — surge needs more info; user should reply in chat
    escalated            — surge couldn't help; operator notified
    resolved             — operator marked closed
    closed               — formally closed; no further updates expected
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from sqlalchemy import Column, DateTime, Integer, String, Text, select
from sqlalchemy.orm import declarative_base

from .db import session_scope, Base

log = logging.getLogger("maestro.support")

# ^ Same-host loopback default per docs/NETWORKING.md. Container deploys
BRAIN_AUTH = os.environ.get("SURGE_OPERATOR_BRAIN_AUTH_TOKEN", "")
NTFY_URL = os.environ.get("SURGE_NTFY_URL", "http://localhost:8088").rstrip("/")
NTFY_TOPIC_OPS = os.environ.get("SURGE_ACTIONS_TOPIC", "surgexi-actions-todd")
TRIAGE_TIER = os.environ.get("SURGE_SUPPORT_TIER", "surge-operator")
TRIAGE_TIMEOUT_S = int(os.environ.get("SURGE_SUPPORT_TIMEOUT_S", "60"))


# ---------- table ----------

class SupportTicketTable(Base):
    __tablename__ = "support_tickets"
    id = Column(String(64), primary_key=True)
    user_id = Column(String(128), nullable=False, index=True)
    tenant_id = Column(String(128), nullable=False, default="creator", index=True)
    product = Column(String(64), nullable=False, default="general", index=True)
    subject = Column(String(300), nullable=False)
    body = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, default="open", index=True)
    priority = Column(String(16), nullable=False, default="medium")
    triage_summary = Column(Text, nullable=True)
    attempted_action = Column(Text, nullable=True)
    attempted_action_result = Column(String(32), nullable=True)
    audit_context = Column(Text, nullable=True)  # JSON-serialized snapshot
    operator_reply = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)


# ---------- public API ----------

async def create_ticket(
    *,
    user_id: str,
    tenant_id: str,
    product: str,
    subject: str,
    body: str,
    priority: str = "medium",
) -> dict:
    """Create a ticket, persist, and kick off surge triage in the background.
    Returns the ticket immediately (status=open or triaging) so the UI can
    show the user a confirmation. Triage updates the row asynchronously."""
    ticket_id = uuid.uuid4().hex[:24]
    now = datetime.now(timezone.utc)


    row = {
        "id": ticket_id,
        "user_id": user_id,
        "tenant_id": tenant_id,
        "product": product[:64],
        "subject": subject[:300],
        "body": body[:8000],
        "status": "open",
        "priority": priority,
        "audit_context": "[]",
        "created_at": now,
        "updated_at": now,
    }
    with session_scope() as db:
        db.add(SupportTicketTable(**row))

    log.info("support ticket created id=%s user=%s product=%s subject=%s",
             ticket_id, user_id, product, subject[:60])


    return _row_to_dict(row)


async def get_ticket(ticket_id: str) -> Optional[dict]:
    with session_scope() as db:
        row = db.get(SupportTicketTable, ticket_id)
        return _row_to_dict_from_table(row) if row else None


async def list_tickets(
    user_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
) -> list:
    with session_scope() as db:
        q = select(SupportTicketTable).order_by(SupportTicketTable.created_at.desc()).limit(limit)
        if user_id:
            q = q.where(SupportTicketTable.user_id == user_id)
        if status:
            q = q.where(SupportTicketTable.status == status)
        return [_row_to_dict_from_table(r) for r in db.scalars(q)]


async def operator_reply(ticket_id: str, reply: str, new_status: str = "resolved") -> Optional[dict]:
    """Operator (Todd or platform_admin) replies to a ticket. Updates row +
    pushes the reply to the user via unprompted-speech channel + ntfy ack."""
    now = datetime.now(timezone.utc)
    with session_scope() as db:
        row = db.get(SupportTicketTable, ticket_id)
        if not row:
            return None
        row.operator_reply = reply[:8000]
        row.status = new_status
        row.updated_at = now
        if new_status in ("resolved", "closed"):
            row.resolved_at = now
        user_id = row.user_id
        subject = row.subject
        product = row.product

    # Push to user via Slice-2 channel
    try:
        from .peer_stream import post_unprompted
        content = (f"Hi — about your '{subject}' ticket: {reply[:500]}"
                   + (" — marked resolved." if new_status == "resolved" else ""))
        await post_unprompted(
            user_id=user_id,
            tenant_id="creator",  # operator replies route through generic for now
            content=content,
            trigger_kind="manual",
        )
    except Exception as e:
        log.warning("failed to push operator reply via peer-stream: %s", e)

    return await get_ticket(ticket_id)


# ---------- triage internals ----------









# ---------- helpers ----------

def _row_to_dict(d: dict) -> dict:
    out = dict(d)
    if "audit_context" in out and isinstance(out["audit_context"], str):
        try:
            out["audit_context"] = json.loads(out["audit_context"])
        except Exception:
            pass
    for k in ("created_at", "updated_at", "resolved_at"):
        v = out.get(k)
        if hasattr(v, "isoformat"):
            out[k] = v.isoformat()
    return out


def _row_to_dict_from_table(row: SupportTicketTable) -> dict:
    return _row_to_dict({
        "id": row.id,
        "user_id": row.user_id,
        "tenant_id": row.tenant_id,
        "product": row.product,
        "subject": row.subject,
        "body": row.body,
        "status": row.status,
        "priority": row.priority,
        "triage_summary": row.triage_summary,
        "attempted_action": row.attempted_action,
        "attempted_action_result": row.attempted_action_result,
        "audit_context": row.audit_context,
        "operator_reply": row.operator_reply,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "resolved_at": row.resolved_at,
    })
