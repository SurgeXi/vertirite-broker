# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""The approval gate lifecycle: request -> notify -> wait -> re-notify -> decide, or time out.

    request_approval()  an integrating system asks a human before a gated action. The request is
                        stored PENDING with a deadline, audited, and announced on every channel the
                        operator configured (console, email, webhook, Pushover; see notifications).
    sweep()             runs on a timer. A pending request is re-announced every
                        ``approval_renotify_s`` (at most ``approval_max_reminders`` times). At its
                        deadline it is DENIED automatically and recorded as such.
    decide()            a human approves or denies. Only a PENDING request can be decided: a late
                        answer can never overturn a timeout or an earlier decision.

Invariants (tested in approval_gate_test.py):
  * An unanswered request is never approved. The timeout decision is a constant, not a setting.
  * Every step writes an audit_events row: approval.requested / approval.notified /
    approval.approved / approval.denied / approval.timeout_denied.
  * Notifications go only to channels the operator configured on THIS broker. Nothing here calls
    a vendor or SurgeXi service.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select

from .config import settings
from .db import session_scope
from .tables import ApprovalTable, AuditEventTable

logger = logging.getLogger("vertirite.approval_gate")

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"
#: What happens to a request nobody answered. Deliberately NOT configurable.
TIMEOUT_DECISION = DENIED
TIMEOUT_ACTOR = "vertirite-timeout"


class ApprovalNotFound(LookupError):
    pass


class ApprovalNotPending(RuntimeError):
    """The request was already decided (by a person or by the timeout)."""

    def __init__(self, status: str):
        super().__init__(f"approval is already {status}")
        self.status = status


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _clamp_timeout(timeout_s: Optional[int]) -> int:
    t = int(timeout_s or settings.approval_timeout_s)
    return max(60, min(t, int(settings.approval_timeout_max_s)))


def _audit(db, *, actor_id: str, action: str, approval_id: str, summary: str) -> None:
    db.add(AuditEventTable(id=str(uuid.uuid4()), actor_id=actor_id, action=action,
                           entity_type="approval", entity_id=approval_id, summary=summary))


def to_dict(row: ApprovalTable) -> dict[str, Any]:
    return {
        "id": row.id, "session_id": row.session_id, "actor_id": row.actor_id,
        "tool_name": row.tool_name, "mode_at_submit": row.mode_at_submit, "status": row.status,
        "summary": row.summary, "payload": json.loads(row.payload_json or "{}"),
        "decision_notes": row.decision_notes or "", "decided_by": row.decided_by,
        "surge_task_id": row.surge_task_id,
        "expires_at": _aware(row.expires_at).isoformat() if row.expires_at else None,
        "notify_count": row.notify_count or 0,
        "last_notified_at": _aware(row.last_notified_at).isoformat() if row.last_notified_at else None,
        "created_at": _aware(row.created_at).isoformat(), "updated_at": _aware(row.updated_at).isoformat(),
    }


# ---------------------------------------------------------------- notify
def _message(rec: dict[str, Any], kind: str) -> tuple[str, str, str]:
    """(severity, title, body) for one announcement. Plain text, no links outside the operator's
    own console (``approval_console_url``, unset by default)."""
    tool, rid = rec["tool_name"], rec["id"]
    if kind == "expired":
        sev, title = "warning", f"Approval DENIED by timeout: {tool}"
        lead = ("Nobody answered this approval request before its deadline, so it was denied "
                "automatically (the safe default). The action must not run.")
    elif kind == "reminder":
        # notify_count includes the first announcement, so reminder n is announcement n+1
        sev, title = "critical", f"Reminder {max(1, rec['notify_count'] - 1)}: approval still waiting: {tool}"
        lead = "This approval request is still waiting for a decision."
    else:
        sev, title = "critical", f"Approval needed: {tool}"
        lead = "An action is waiting for your approval."
    console = settings.approval_console_url.rstrip("/")
    how = (f"Decide in the console: {console}/#approvals" if console
           else "Decide in the Vertirite console (Approvals).")
    body = (f"{lead}\n\nRequest: {rec['summary']}\nAction: {tool}\nRequested by: {rec['actor_id']}\n"
            f"Approval ID: {rid}\nDeadline: {rec['expires_at']} (unanswered requests are DENIED)\n\n"
            f"{how}")
    return sev, title, body


async def notify(approval_id: str, kind: str) -> dict[str, Any]:
    """Announce on every configured channel; record which channels took it (names + status only)."""
    from . import notifications

    with session_scope() as db:
        row = db.get(ApprovalTable, approval_id)
        if row is None:
            raise ApprovalNotFound(approval_id)
        if kind != "expired":
            row.notify_count = (row.notify_count or 0) + 1
            row.last_notified_at = _now()
        rec = to_dict(row)
    sev, title, body = _message(rec, kind)
    try:
        res = await notifications.send_alert(severity=sev, title=title, message=body, node="approvals")
    except Exception as exc:  # noqa: BLE001 — a channel failure must never lose the request
        res = {"channels": {"error": {"status": "failed", "error": type(exc).__name__}}}
    chans = {k: (v.get("status") if isinstance(v, dict) else str(v)) for k, v in (res.get("channels") or {}).items()}
    with session_scope() as db:
        _audit(db, actor_id="vertirite-notify", action="approval.notified", approval_id=approval_id,
               summary=f"{kind}: " + (", ".join(f"{k}={v}" for k, v in sorted(chans.items()))
                                      or "console only (no external channel configured)"))
    return {"kind": kind, "channels": chans}


# ---------------------------------------------------------------- request / decide
async def request_approval(*, actor_id: str, tool_name: str, summary: str,
                           payload: Optional[dict[str, Any]] = None, session_id: str = "",
                           timeout_s: Optional[int] = None, mode: str = "CONTROLLED") -> dict[str, Any]:
    now = _now()
    rid = str(uuid.uuid4())
    timeout = _clamp_timeout(timeout_s)
    with session_scope() as db:
        db.add(ApprovalTable(
            id=rid, session_id=session_id or "", actor_id=actor_id, tool_name=tool_name,
            mode_at_submit=mode, status=PENDING, summary=summary,
            payload_json=json.dumps(payload or {}), decision_notes="", surge_task_id=None,
            created_at=now, updated_at=now, expires_at=now + timedelta(seconds=timeout),
            notify_count=0, last_notified_at=None, decided_by=None))
        _audit(db, actor_id=actor_id, action="approval.requested", approval_id=rid,
               summary=f"{tool_name}: {summary} (deadline {timeout}s, then DENY)")
    await notify(rid, "new")
    return get(rid)


def get(approval_id: str) -> dict[str, Any]:
    with session_scope() as db:
        row = db.get(ApprovalTable, approval_id)
        if row is None:
            raise ApprovalNotFound(approval_id)
        return to_dict(row)


def list_requests(*, status: Optional[str] = None, limit: int = 50) -> list[dict[str, Any]]:
    with session_scope() as db:
        q = select(ApprovalTable).order_by(ApprovalTable.created_at.desc()).limit(min(limit, 200))
        if status:
            q = q.where(ApprovalTable.status == status)
        return [to_dict(r) for r in db.scalars(q).all()]


def decide(approval_id: str, *, status: str, decided_by: str, notes: str = "",
           action: Optional[str] = None) -> dict[str, Any]:
    """Approve or deny a PENDING request. Raises ApprovalNotPending if it was already decided."""
    if status not in (APPROVED, DENIED):
        raise ValueError("status must be approved or denied")
    with session_scope() as db:
        row = db.get(ApprovalTable, approval_id, with_for_update=True)
        if row is None:
            raise ApprovalNotFound(approval_id)
        if row.status != PENDING:
            raise ApprovalNotPending(row.status)
        row.status = status
        row.decision_notes = notes
        row.decided_by = decided_by
        row.updated_at = _now()
        _audit(db, actor_id=decided_by, action=action or f"approval.{status}", approval_id=approval_id,
               summary=notes or f"Approval {status} by {decided_by}.")
        return to_dict(row)


# ---------------------------------------------------------------- the timer
async def sweep(now: Optional[datetime] = None) -> dict[str, int]:
    """Re-notify waiting requests and DENY the ones past their deadline."""
    now = now or _now()
    renotify = timedelta(seconds=int(settings.approval_renotify_s))
    expired: list[str] = []
    remind: list[str] = []
    with session_scope() as db:
        for row in db.scalars(select(ApprovalTable).where(ApprovalTable.status == PENDING)).all():
            exp = _aware(row.expires_at)
            if exp is None:  # pre-gate rows: give them a deadline instead of waiting forever
                row.expires_at = (exp := _aware(row.created_at) + timedelta(seconds=_clamp_timeout(None)))
            if now >= exp:
                expired.append(row.id)
            else:
                last = _aware(row.last_notified_at) or _aware(row.created_at)
                if (now - last >= renotify) and (row.notify_count or 0) <= int(settings.approval_max_reminders):
                    remind.append(row.id)
    n_exp = 0
    for rid in expired:
        try:
            decide(rid, status=TIMEOUT_DECISION, decided_by=TIMEOUT_ACTOR, action="approval.timeout_denied",
                   notes="Auto-denied: no decision before the deadline (the safe default).")
        except ApprovalNotPending:
            continue  # a person decided it in the meantime
        n_exp += 1
        await notify(rid, "expired")
    for rid in remind:
        await notify(rid, "reminder")
    return {"expired_denied": n_exp, "reminded": len(remind)}


_task: Optional[asyncio.Task] = None


def start_sweeper() -> None:
    """Start the background timer (idempotent). Runs inside the broker; no external scheduler."""
    global _task
    if _task is not None and not _task.done():
        return

    async def _loop() -> None:
        while True:
            try:
                r = await sweep()
                if r["expired_denied"] or r["reminded"]:
                    logger.info("approval sweep: %s", r)
            except Exception:  # noqa: BLE001 — keep the timer alive; log and retry next tick
                logger.exception("approval sweep failed")
            await asyncio.sleep(max(5, int(settings.approval_sweep_s)))

    _task = asyncio.get_event_loop().create_task(_loop())
