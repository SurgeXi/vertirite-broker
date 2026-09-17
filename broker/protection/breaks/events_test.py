# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""break_events — upsert/dedup, lifecycle, confirm-and-learn folding."""
import os
import tempfile
import uuid

_db_fd, _db_path = tempfile.mkstemp(suffix="-breaks-events.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from broker.protection.breaks import baseline, events  # noqa: E402
from broker.protection.breaks.detector import Break  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(bind=engine)


_schema()

# Unique tenant per run → hermetic against a persistent dev DB.
T = f"t-{uuid.uuid4().hex[:8]}"


def _novel_egress(actor, dest):
    return Break(reason="novel_egress", severity="warning",
                 title=f"{actor} reached {dest}", target=dest,
                 chokepoints=["egress"], evidence={"destination": dest})


def test_report_break_inserts_then_dedups():
    first = events.report_break(T, "agent-e1", _novel_egress("agent-e1", "evil.example.com"))
    assert first["status"] == "open" and first["occurrence_count"] == 1
    second = events.report_break(T, "agent-e1", _novel_egress("agent-e1", "evil.example.com"))
    assert second["id"] == first["id"]  # same open row
    assert second["occurrence_count"] == 2


def test_list_and_summary():
    events.report_break(f"{T}-b", "agent-e2",
                        Break(reason="first_irreversible", severity="critical",
                              title="wire", target="pay_invoice", chokepoints=["irreversible"]))
    rows = events.list_breaks(tenant_id=f"{T}-b")
    assert any(r["reason"] == "first_irreversible" for r in rows)
    summ = events.summary(tenant_id=f"{T}-b")
    assert summ["by_status"]["open"] >= 1
    assert summ["open_by_severity"].get("critical", 0) >= 1


def test_acknowledge_folds_into_baseline():
    b = events.report_break(f"{T}-ack", "agent-ack", _novel_egress("agent-ack", "approved.example.com"))
    events.acknowledge_break(b["id"], "operator-1")
    bl = baseline.get(f"{T}-ack", "agent-ack")
    assert bl is not None and "approved.example.com" in bl["egress_destinations"]
    assert events.get_break(b["id"])["status"] == "acknowledged"


def test_confirm_does_not_fold():
    b = events.report_break(f"{T}-cfm", "agent-confirm", _novel_egress("agent-confirm", "attacker.example.com"))
    events.confirm_break(b["id"], "operator-1", note="real exfil")
    bl = baseline.get(f"{T}-cfm", "agent-confirm")
    assert bl is None or "attacker.example.com" not in bl["egress_destinations"]
    assert events.get_break(b["id"])["status"] == "confirmed"


def test_tenant_isolation():
    events.report_break(f"{T}-A", "shared-name", _novel_egress("shared-name", "a.example.com"))
    events.report_break(f"{T}-B", "shared-name", _novel_egress("shared-name", "b.example.com"))
    a = events.list_breaks(tenant_id=f"{T}-A")
    b = events.list_breaks(tenant_id=f"{T}-B")
    assert all(r["tenant_id"] == f"{T}-A" for r in a)
    assert all(r["tenant_id"] == f"{T}-B" for r in b)
