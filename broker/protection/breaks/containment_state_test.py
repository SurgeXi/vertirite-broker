# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Detect -> contain (P3): containment-state set/clear, enforce, auto-clamp."""
import os
import tempfile
import uuid

_db_fd, _db_path = tempfile.mkstemp(suffix="-breaks-contain.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from broker.protection.breaks import containment_state as cs  # noqa: E402
from broker import approval_types as caps  # noqa: E402

SAFE, SCOPED, GATED, HS = (caps.ApprovalClass.SAFE, caps.ApprovalClass.SCOPED,
                           caps.ApprovalClass.GATED, caps.ApprovalClass.HIGH_STAKES)


def _schema():
    from broker.db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(bind=engine)


_schema()
T = f"t-{uuid.uuid4().hex[:8]}"


def test_no_state_is_passthrough():
    eff, quarantined, _ = cs.enforce(T, "agent-none", SAFE)
    assert eff == SAFE and quarantined is False


def test_set_get_clear():
    cs.set_state(T, "agent-a", "elevated_gated", "test", set_by="op")
    st = cs.get_state(T, "agent-a")
    assert st and st["mode"] == "elevated_gated" and st["active"] is True
    cs.clear_state(T, "agent-a", cleared_by="op")
    assert cs.get_state(T, "agent-a") is None


def test_enforce_elevates_never_lowers():
    cs.set_state(T, "agent-b", "elevated_high_stakes", "clamp", set_by="op")
    # a SAFE action is raised to HIGH_STAKES
    assert cs.enforce(T, "agent-b", SAFE)[0] == HS
    # an already-HIGH_STAKES action stays HIGH_STAKES (never lowered)
    assert cs.enforce(T, "agent-b", HS)[0] == HS


def test_quarantine_signals_deny():
    cs.set_state(T, "agent-q", "quarantined", "confirmed exfil", set_by="op")
    eff, quarantined, reason = cs.enforce(T, "agent-q", SAFE)
    assert quarantined is True and "exfil" in reason


def test_only_raise_keeps_stronger_clamp():
    cs.set_state(T, "agent-r", "quarantined", "operator hard stop", set_by="op")
    # auto-clamp (only_raise) must not weaken a stronger operator clamp
    cs.set_state(T, "agent-r", "elevated_gated", "auto", set_by="vertirite:auto", only_raise=True)
    assert cs.get_state(T, "agent-r")["mode"] == "quarantined"


def test_auto_clamp_only_on_first_irreversible():
    # the dangerous break auto-elevates to high_stakes
    cs.auto_clamp_for_break(T, "agent-ac", "first_irreversible", "brk-1", "critical")
    assert cs.get_state(T, "agent-ac")["mode"] == "elevated_high_stakes"
    # a novel_egress break does NOT auto-clamp
    assert cs.auto_clamp_for_break(T, "agent-ne", "novel_egress", "brk-2", "warning") is None
    assert cs.get_state(T, "agent-ne") is None


def test_auto_clamp_never_quarantines():
    cs.auto_clamp_for_break(T, "agent-nq", "first_irreversible", "brk-3", "critical")
    assert cs.get_state(T, "agent-nq")["mode"] != "quarantined"
