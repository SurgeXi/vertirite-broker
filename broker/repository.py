# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
from __future__ import annotations

import json
import logging
import uuid
from typing import Optional, Tuple

from sqlalchemy import select

from .db import session_scope

logger = logging.getLogger("maestro.repository")
from .models import (
    ApprovalRecord,
    AuditEventRecord,
    ChatMessageRecord,
    ExecuteCommandRequest,
    ProjectCreateRequest,
    ProjectRecord,
    SessionResponse,
    SurgeMode,
    utc_now,
)
from .tables import (
    ApiTokenTable,
    ApprovalTable,
    AuditEventTable,
    ChatMessageTable,
    ExecutionRequestTable,
    ProjectTable,
    SessionTable,
)


def write_audit_event(
    *,
    actor_id: str,
    action: str,
    entity_type: str,
    entity_id: str,
    summary: str,
    tenant_id: Optional[str] = None,
) -> str:
    """Record a single audit event. Returns the new event ID.

    tenant_id is optional and nullable. Callers that know the tenant
    scope of the action should populate it so the compliance-reviewer
    drill-down ("show me every event for tenant X") works. Pre-existing
    callers continue to omit it — the column is nullable.
    """
    event_id = str(uuid.uuid4())
    with session_scope() as db:
        db.add(
            AuditEventTable(
                id=event_id,
                actor_id=actor_id,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                summary=summary,
                tenant_id=tenant_id,
            )
        )
    logger.info(
        "Audit: actor=%s action=%s entity=%s:%s tenant=%s",
        actor_id, action, entity_type, entity_id, tenant_id or "-",
    )
    return event_id


def create_session_record(*, user_id: str, client_type: str, session_label: str) -> SessionResponse:
    session = SessionResponse(
        session_id=str(uuid.uuid4()),
        user_id=user_id,
        client_type=client_type,
        session_label=session_label,
    )
    with session_scope() as db:
        db.add(
            SessionTable(
                id=session.session_id,
                user_id=session.user_id,
                client_type=session.client_type,
                session_label=session.session_label,
                created_at=session.created_at,
            )
        )
    logger.info("Session created: id=%s user=%s client=%s", session.session_id, user_id, client_type)
    return session


def get_session_or_none(session_id: str) -> Optional[SessionResponse]:
    with session_scope() as db:
        row = db.get(SessionTable, session_id)
        if row is None:
            return None
        return SessionResponse(
            session_id=row.id,
            user_id=row.user_id,
            client_type=row.client_type,
            session_label=row.session_label,
            created_at=row.created_at,
        )


def list_projects_records() -> list[ProjectRecord]:
    with session_scope() as db:
        rows = db.scalars(select(ProjectTable).order_by(ProjectTable.created_at.desc())).all()
    return [
        ProjectRecord(
            id=row.id,
            name=row.name,
            tenant_id=row.tenant_id,
            local_path=row.local_path,
            remote_path=row.remote_path,
            created_at=row.created_at,
        )
        for row in rows
    ]


def ensure_api_token_record(*, user_id: str, token_label: str, token_hash: str) -> None:
    with session_scope() as db:
        existing = db.scalar(
            select(ApiTokenTable).where(ApiTokenTable.token_hash == token_hash)
        )
        if existing is not None:
            logger.debug("API token already exists: label=%s user=%s", token_label, user_id)
            return
        db.add(
            ApiTokenTable(
                id=str(uuid.uuid4()),
                user_id=user_id,
                token_label=token_label,
                token_hash=token_hash,
            )
        )
    logger.info("API token registered: label=%s user=%s", token_label, user_id)


def create_approval_record(
    *,
    actor_id: str,
    request: ExecuteCommandRequest,
    mode: SurgeMode,
    status: str,
    summary: str,
    surge_task_id: Optional[str] = None,
) -> ApprovalRecord:
    now = utc_now()
    approval = ApprovalRecord(
        id=str(uuid.uuid4()),
        session_id=request.session_id,
        actor_id=actor_id,
        tool_name=request.tool_name,
        mode_at_submit=mode,
        status=status,
        summary=summary,
        payload=request.payload,
        surge_task_id=surge_task_id,
        created_at=now,
        updated_at=now,
    )
    with session_scope() as db:
        db.add(
            ApprovalTable(
                id=approval.id,
                session_id=approval.session_id,
                actor_id=approval.actor_id,
                tool_name=approval.tool_name,
                mode_at_submit=approval.mode_at_submit.value,
                status=approval.status,
                summary=approval.summary,
                payload_json=json.dumps(approval.payload),
                decision_notes="",
                surge_task_id=approval.surge_task_id,
                created_at=approval.created_at,
                updated_at=approval.updated_at,
            )
        )
        db.add(
            AuditEventTable(
                id=str(uuid.uuid4()),
                actor_id=actor_id,
                action="approval.requested",
                entity_type="approval",
                entity_id=approval.id,
                summary=summary,
            )
        )
    logger.info("Approval created: id=%s actor=%s tool=%s status=%s", approval.id, actor_id, request.tool_name, status)
    return approval


def create_project_record(request: ProjectCreateRequest) -> ProjectRecord:
    project = ProjectRecord(
        id=str(uuid.uuid4()),
        name=request.name,
        tenant_id=request.tenant_id,
        local_path=request.local_path,
        remote_path=request.remote_path,
    )
    with session_scope() as db:
        db.add(
            ProjectTable(
                id=project.id,
                name=project.name,
                tenant_id=project.tenant_id,
                local_path=project.local_path,
                remote_path=project.remote_path,
                created_at=project.created_at,
            )
        )
    return project


def create_execution_and_audit(
    *,
    actor_id: str,
    request: ExecuteCommandRequest,
    mode: SurgeMode,
    status: str,
    summary: str,
) -> Tuple[str, str]:
    request_id = str(uuid.uuid4())
    audit_id = str(uuid.uuid4())
    with session_scope() as db:
        db.add(
            ExecutionRequestTable(
                id=request_id,
                session_id=request.session_id,
                tool_name=request.tool_name,
                payload_json=json.dumps(request.payload),
                mode_at_submit=mode.value,
                status=status,
                summary=summary,
            )
        )
        db.add(
            AuditEventTable(
                id=audit_id,
                actor_id=actor_id,
                action="command.execute",
                entity_type="execution_request",
                entity_id=request_id,
                summary=summary,
            )
        )
    logger.info("Execution recorded: request_id=%s tool=%s status=%s", request_id, request.tool_name, status)
    return request_id, audit_id


def list_audit_events(
    limit: int = 50,
    action_prefix: Optional[str] = None,
    actor_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> list[AuditEventRecord]:
    """List audit events. When `actor_id` is given, restricts to events by
    that actor (the per-tenant `/v1/audit/me` feed uses this).
    When `tenant_id` is given, restricts to events tagged with that tenant
    (the compliance-reviewer drill-down).

    Audit #6 (2026-04-25): pre-Day-3 this returned cross-tenant rows. The
    actor_id and tenant_id filters are the fix; the platform_admin path is
    intentional — admins still need fleet-wide visibility when no filter
    is set.
    """
    with session_scope() as db:
        query = select(AuditEventTable).order_by(AuditEventTable.created_at.desc()).limit(limit)
        if action_prefix:
            query = query.where(AuditEventTable.action.like(f"{action_prefix}%"))
        if actor_id:
            query = query.where(AuditEventTable.actor_id == actor_id)
        if tenant_id:
            query = query.where(AuditEventTable.tenant_id == tenant_id)
        rows = db.scalars(query).all()
    return [
        AuditEventRecord(
            id=row.id,
            actor_id=row.actor_id,
            action=row.action,
            entity_type=row.entity_type,
            entity_id=row.entity_id,
            summary=row.summary,
            created_at=row.created_at,
        )
        for row in rows
    ]


def list_approvals(limit: int = 50) -> list[ApprovalRecord]:
    with session_scope() as db:
        rows = db.scalars(
            select(ApprovalTable).order_by(ApprovalTable.created_at.desc()).limit(limit)
        ).all()
    return [
        ApprovalRecord(
            id=row.id,
            session_id=row.session_id,
            actor_id=row.actor_id,
            tool_name=row.tool_name,
            mode_at_submit=SurgeMode(row.mode_at_submit),
            status=row.status,
            summary=row.summary,
            payload=json.loads(row.payload_json),
            surge_task_id=row.surge_task_id,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
        for row in rows
    ]


def save_chat_message(session_id: str, role: str, content: str) -> ChatMessageRecord:
    record = ChatMessageRecord(
        id=str(uuid.uuid4()),
        session_id=session_id,
        role=role,
        content=content,
        created_at=utc_now(),
    )
    with session_scope() as db:
        db.add(
            ChatMessageTable(
                id=record.id,
                session_id=record.session_id,
                role=record.role,
                content=record.content,
                created_at=record.created_at,
            )
        )
    logger.info("Chat message saved: session=%s role=%s len=%d", session_id, role, len(content))
    return record


def get_chat_history(session_id: str, limit: int = 50) -> list[ChatMessageRecord]:
    with session_scope() as db:
        rows = db.scalars(
            select(ChatMessageTable)
            .where(ChatMessageTable.session_id == session_id)
            .order_by(ChatMessageTable.created_at.asc())
            .limit(limit)
        ).all()
    return [
        ChatMessageRecord(
            id=row.id,
            session_id=row.session_id,
            role=row.role,
            content=row.content,
            created_at=row.created_at,
        )
        for row in rows
    ]


def update_approval_status(
    approval_id: str,
    *,
    status: str,
    decision_notes: str,
) -> Optional[ApprovalRecord]:
    with session_scope() as db:
        row = db.get(ApprovalTable, approval_id)
        if row is None:
            return None
        row.status = status
        row.decision_notes = decision_notes
        row.updated_at = utc_now()
        db.add(
            AuditEventTable(
                id=str(uuid.uuid4()),
                actor_id=row.actor_id,
                action=f"approval.{status}",
                entity_type="approval",
                entity_id=row.id,
                summary=decision_notes or f"Approval marked {status}.",
            )
        )
        return ApprovalRecord(
            id=row.id,
            session_id=row.session_id,
            actor_id=row.actor_id,
            tool_name=row.tool_name,
            mode_at_submit=SurgeMode(row.mode_at_submit),
            status=row.status,
            summary=row.summary,
            payload=json.loads(row.payload_json),
            surge_task_id=row.surge_task_id,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )


# ---------------------------------------------------------------------------
# GDPR-style cascade delete — wipes everything stored under a user_id.
# Backs the DELETE /v1/me endpoint. Idempotent: re-running yields zero deletes.
# Audit-doc Day 3.2 (PR #19 launch-readiness).
# ---------------------------------------------------------------------------
def gdpr_delete_user_data(user_id: str) -> dict:
    """Cascade-delete a user's data across the broker tables.

    Returns a dict of {table: rows_deleted}. Best-effort across qdrant
    (the qdrant collection wipe lives in app code so it can be skipped
    if qdrant is unreachable).
    """
    from .tables import (
        SessionTable, ChatMessageTable, ExecutionRequestTable,
        AuditEventTable, ApprovalTable, ApiTokenTable,
    )
    from sqlalchemy import delete as sql_delete
    counts: dict[str, int] = {}

    with session_scope() as db:
        # Sessions own a lot of children — find them first, then cascade.
        session_ids = [
            row.id
            for row in db.scalars(select(SessionTable).where(SessionTable.user_id == user_id))
        ]
        if session_ids:
            counts["chat_messages"] = db.execute(
                sql_delete(ChatMessageTable).where(ChatMessageTable.session_id.in_(session_ids))
            ).rowcount or 0
            counts["execution_requests"] = db.execute(
                sql_delete(ExecutionRequestTable).where(ExecutionRequestTable.session_id.in_(session_ids))
            ).rowcount or 0
            counts["approvals"] = db.execute(
                sql_delete(ApprovalTable).where(ApprovalTable.session_id.in_(session_ids))
            ).rowcount or 0
            counts["sessions"] = db.execute(
                sql_delete(SessionTable).where(SessionTable.id.in_(session_ids))
            ).rowcount or 0

        # Audit events keyed by actor_id.
        counts["audit_events"] = db.execute(
            sql_delete(AuditEventTable).where(AuditEventTable.actor_id == user_id)
        ).rowcount or 0

        # API tokens (revoke any tokens belonging to this user).
        counts["api_tokens"] = db.execute(
            sql_delete(ApiTokenTable).where(ApiTokenTable.user_id == user_id)
        ).rowcount or 0

    return counts
