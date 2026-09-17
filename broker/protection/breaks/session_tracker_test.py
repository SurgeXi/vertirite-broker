# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Session-scope drift (P3): benign-then-dangerous mid-session escalation."""
import os
import tempfile
import uuid

_db_fd, _db_path = tempfile.mkstemp(suffix="-breaks-session.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from broker.protection.breaks import session_tracker as st  # noqa: E402
from broker.protection.breaks import detector  # noqa: E402


def _sid():
    return f"sess-{uuid.uuid4().hex[:8]}"


def test_observe_returns_prior_state():
    s = _sid()
    prior, count, newly = st.observe(s, [])
    assert prior == set() and count == 0 and newly == []
    prior, count, newly = st.observe(s, ["egress"])
    assert count == 1  # one action recorded before this one


def test_drift_fires_after_benign_then_dangerous():
    s = _sid()
    for _ in range(st.MIN_BENIGN_BEFORE_DRIFT):
        st.observe(s, [])              # benign actions
    _, prior_count, newly = st.observe(s, ["irreversible"])   # escalation
    assert prior_count >= st.MIN_BENIGN_BEFORE_DRIFT and newly == ["irreversible"]
    breaks = detector.evaluate_session_drift("agent-x", prior_count, newly)
    assert [b.reason for b in breaks] == ["session_scope_drift"]


def test_no_drift_when_dangerous_from_start():
    s = _sid()
    _, prior_count, newly = st.observe(s, ["irreversible"])   # first action is dangerous
    assert prior_count == 0
    assert detector.evaluate_session_drift("agent-x", prior_count, newly) == []


def test_no_drift_before_min_benign():
    s = _sid()
    st.observe(s, [])                                  # only 1 benign action
    _, prior_count, newly = st.observe(s, ["credential"])
    assert prior_count < st.MIN_BENIGN_BEFORE_DRIFT
    assert detector.evaluate_session_drift("agent-x", prior_count, newly) == []


def test_recrossing_same_dangerous_is_not_new():
    s = _sid()
    for _ in range(st.MIN_BENIGN_BEFORE_DRIFT):
        st.observe(s, [])
    st.observe(s, ["credential"])                      # first credential (drift-eligible)
    _, _, newly = st.observe(s, ["credential"])        # again — not newly dangerous
    assert newly == []


def test_evaluate_ignores_benign_escalation():
    # egress is not in the dangerous set for session drift
    assert detector.evaluate_session_drift("agent-x", 10, ["egress"]) == []
