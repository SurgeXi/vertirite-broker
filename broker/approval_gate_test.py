# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Approval gate lifecycle tests (broker/approval_gate.py).

request -> notify -> wait -> re-notify -> approve | deny | time out (DENY), each step audited.
The two properties a security reviewer asks about first:
  * an unanswered request is NEVER approved (timeout -> deny, not configurable);
  * a late answer can never overturn a decision (only PENDING can be decided; HTTP 409).
"""
from __future__ import annotations

import asyncio
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

_db_fd, _db_path = tempfile.mkstemp(suffix="-approval-gate.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from . import approval_gate as G  # noqa: E402
from . import notifications  # noqa: E402
from .auth import AuthContext, require_bearer_token, require_not_demo  # noqa: E402
from .config import settings  # noqa: E402
from .db import Base, engine, init_db, session_scope  # noqa: E402
from .tables import ApprovalTable, AuditEventTable  # noqa: E402

init_db()
Base.metadata.create_all(engine)

T0 = datetime(2026, 10, 12, 20, 0, tzinfo=timezone.utc)


@pytest.fixture()
def clock(monkeypatch):
    """A controllable clock + a recording channel (nothing leaves the test)."""
    state = {"now": T0, "sent": []}
    with session_scope() as db:          # each test starts with an empty queue
        db.query(ApprovalTable).delete()
    monkeypatch.setattr(G, "_now", lambda: state["now"])

    async def fake_send_alert(severity, title, message, node=None):
        state["sent"].append({"severity": severity, "title": title, "message": message})
        return {"channels": {"email": {"status": "sent"}, "webhook": {"status": "sent"}}}

    monkeypatch.setattr(notifications, "send_alert", fake_send_alert)
    monkeypatch.setattr(settings, "approval_renotify_s", 900)
    monkeypatch.setattr(settings, "approval_max_reminders", 2)
    monkeypatch.setattr(settings, "approval_timeout_s", 3600)
    return state


def _audit(approval_id):
    with session_scope() as db:
        return [r.action for r in db.scalars(select(AuditEventTable)
                .where(AuditEventTable.entity_id == approval_id)
                .order_by(AuditEventTable.created_at)).all()]


async def _req(timeout_s=3600, tool="test.harmless"):
    return await G.request_approval(actor_id="integration-1", tool_name=tool,
                                    summary="[SURGEXI-TEST rev117 vertirite-approval]",
                                    payload={"x": 1}, timeout_s=timeout_s)


def test_request_is_pending_announced_and_audited(clock):
    r = asyncio.run(_req())
    assert r["status"] == G.PENDING
    assert r["expires_at"] == (T0 + timedelta(seconds=3600)).isoformat()
    assert r["notify_count"] == 1
    assert len(clock["sent"]) == 1 and clock["sent"][0]["title"].startswith("Approval needed")
    assert "DENIED" in clock["sent"][0]["message"]           # the recipient is told the default
    acts = _audit(r["id"])
    assert acts[:2] == ["approval.requested", "approval.notified"]


def test_approve_records_the_decider_and_late_answer_is_refused(clock):
    r = asyncio.run(_req())
    d = G.decide(r["id"], status=G.APPROVED, decided_by="operator-1", notes="ok")
    assert d["status"] == G.APPROVED and d["decided_by"] == "operator-1"
    with pytest.raises(G.ApprovalNotPending):
        G.decide(r["id"], status=G.DENIED, decided_by="someone-else")
    assert G.get(r["id"])["status"] == G.APPROVED
    assert "approval.approved" in _audit(r["id"])


def test_deny(clock):
    r = asyncio.run(_req())
    d = G.decide(r["id"], status=G.DENIED, decided_by="operator-1", notes="no")
    assert d["status"] == G.DENIED
    assert "approval.denied" in _audit(r["id"])


def test_reminders_then_timeout_denies_and_cannot_be_overturned(clock):
    r = asyncio.run(_req(timeout_s=3600))
    rid = r["id"]
    clock["now"] = T0 + timedelta(seconds=899)
    assert (asyncio.run(G.sweep()))["reminded"] == 0                # not yet due
    clock["now"] = T0 + timedelta(seconds=901)
    assert (asyncio.run(G.sweep()))["reminded"] == 1                # reminder 1
    clock["now"] = T0 + timedelta(seconds=1000)
    assert (asyncio.run(G.sweep()))["reminded"] == 0                # interval restarts from the reminder
    clock["now"] = T0 + timedelta(seconds=1802)
    assert (asyncio.run(G.sweep()))["reminded"] == 1                # reminder 2 (cap = 2)
    clock["now"] = T0 + timedelta(seconds=2703)
    assert (asyncio.run(G.sweep()))["reminded"] == 0                # cap reached: no reminder 3
    clock["now"] = T0 + timedelta(seconds=3600)
    res = asyncio.run(G.sweep())
    assert res["expired_denied"] == 1
    rec = G.get(rid)
    assert rec["status"] == G.DENIED and rec["decided_by"] == G.TIMEOUT_ACTOR
    titles = [m["title"] for m in clock["sent"]]
    assert titles[0].startswith("Approval needed") and titles[-1].startswith("Approval DENIED by timeout")
    assert sum(t.startswith("Reminder") for t in titles) == 2
    assert "approval.timeout_denied" in _audit(rid)
    with pytest.raises(G.ApprovalNotPending):              # a late "approve" cannot revive it
        G.decide(rid, status=G.APPROVED, decided_by="operator-1")
    assert G.get(rid)["status"] == G.DENIED


def test_timeout_default_is_deny_and_not_a_setting():
    assert G.TIMEOUT_DECISION == G.DENIED
    assert not any("timeout_decision" in k or "default_decision" in k
                   for k in type(settings).model_fields if k.startswith("approval"))


def test_timeout_is_clamped(clock):
    r = asyncio.run(_req(timeout_s=10 ** 9))
    exp = datetime.fromisoformat(r["expires_at"])
    assert exp - T0 == timedelta(seconds=settings.approval_timeout_max_s)


def test_channel_failure_never_loses_the_request(clock, monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("smtp down")
    monkeypatch.setattr(notifications, "send_alert", boom)
    r = asyncio.run(_req())
    assert G.get(r["id"])["status"] == G.PENDING
    assert "approval.notified" in _audit(r["id"])


def test_http_create_list_decide_conflict(clock):
    from .main import app
    admin = AuthContext(user_id="operator-1", token_label="test", created_at=T0, role="platform_admin")
    app.dependency_overrides[require_bearer_token] = lambda: admin
    app.dependency_overrides[require_not_demo] = lambda: admin
    try:
        c = TestClient(app)
        r = c.post("/v1/approvals", json={"tool_name": "test.harmless",
                                          "summary": "[SURGEXI-TEST rev117 vertirite-approval]",
                                          "timeout_s": 600})
        assert r.status_code == 201, r.text
        rid = r.json()["id"]
        pend = c.get("/v1/approvals", params={"status": "pending"}).json()
        assert any(a["id"] == rid for a in pend)
        assert c.post(f"/v1/approvals/{rid}/approve", json={"decision_notes": "ok"}).status_code == 200
        again = c.post(f"/v1/approvals/{rid}/deny", json={})
        assert again.status_code == 409
        assert c.post("/v1/approvals/does-not-exist/approve", json={}).status_code == 404
        assert c.post("/v1/approvals", json={"tool_name": "x", "summary": "y", "timeout_s": 5}).status_code == 422
    finally:
        app.dependency_overrides.clear()

