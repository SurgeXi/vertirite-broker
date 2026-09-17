# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Baseline builder — learns while warming, holds novel items once warm."""
import os
import tempfile
import uuid

_db_fd, _db_path = tempfile.mkstemp(suffix="-breaks-baseline.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from broker.protection.breaks import baseline  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(bind=engine)


_schema()

# Namespace every row to a unique tenant per run so the test is hermetic even
# against a persistent dev DB.
T = f"t-{uuid.uuid4().hex[:8]}"


def test_load_creates_warming_row():
    bl = baseline.load(T, "agent-load")
    assert bl.state == "warming"
    assert bl.action_count == 0
    assert bl.egress_destinations == set()


def test_observe_while_warming_learns():
    baseline.observe(T, "agent-warm-learn", "http_get", ["egress"], ["api.openai.com"])
    bl = baseline.load(T, "agent-warm-learn")
    assert "http_get" in bl.capabilities
    assert "api.openai.com" in bl.egress_destinations


def test_observe_sets_seen_flags_while_warming():
    baseline.observe(T, "agent-flags", "fleet_ssh", ["credential", "irreversible"], [])
    bl = baseline.load(T, "agent-flags")
    assert bl.credential_seen is True
    assert bl.irreversible_seen is True


def test_warm_transition_by_action_count(monkeypatch):
    monkeypatch.setattr(baseline, "WARMUP_MIN_ACTIONS", 3)
    for _ in range(3):
        baseline.observe(T, "agent-warmup", "file_read", [], [])
    bl = baseline.load(T, "agent-warmup")
    assert bl.state == "warm"
    assert bl.action_count >= 3


def test_warm_agent_does_not_learn_novel_dest(monkeypatch):
    monkeypatch.setattr(baseline, "WARMUP_MIN_ACTIONS", 1)
    baseline.observe(T, "agent-warmhold", "file_read", [], [])
    assert baseline.load(T, "agent-warmhold").state == "warm"
    # A WARM agent must NOT auto-learn a novel external dest — it stays "novel"
    # until the operator acknowledges the break.
    baseline.observe(T, "agent-warmhold", "http_get", ["egress"], ["late.example.com"])
    assert "late.example.com" not in baseline.load(T, "agent-warmhold").egress_destinations


def test_learn_folds_dest():
    baseline.load(T, "agent-learn")
    baseline.learn(T, "agent-learn", dest="approved.example.com")
    assert "approved.example.com" in baseline.load(T, "agent-learn").egress_destinations


def test_record_denial_counts_in_window():
    assert baseline.record_denial(T, "agent-deny") == 1
    assert baseline.record_denial(T, "agent-deny") == 2
    assert baseline.record_denial(T, "agent-deny") == 3


def test_get_returns_none_for_unknown_agent():
    assert baseline.get(T, "never-seen-agent") is None
