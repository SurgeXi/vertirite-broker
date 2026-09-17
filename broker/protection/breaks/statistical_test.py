# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""P2 statistical deviation rules — deterministic, warm-only, self-healing."""
import os
import tempfile
import uuid

_db_fd, _db_path = tempfile.mkstemp(suffix="-breaks-stat.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from broker.protection.breaks import detector, baseline  # noqa: E402
from broker.protection.breaks.baseline import Baseline  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db(); Base.metadata.create_all(bind=engine)


_schema()
T = f"t-{uuid.uuid4().hex[:8]}"


def _warm(**kw):
    base = dict(active_hours={9, 10, 11}, data_classes={"financial"},
                rate_band_max=4, state="warm")
    base.update(kw)
    return Baseline(T, "agent-x", **base)


def _reasons(bs):
    return {b.reason for b in bs}


# --- warm-only gating ---
def test_warming_raises_nothing():
    bl = Baseline(T, "agent-x", state="warming", active_hours={9}, rate_band_max=4)
    assert detector.evaluate_statistical(bl, now_hour=3, recent_rate=100, data_class="phi") == []


def test_quiet_when_within_bands():
    assert detector.evaluate_statistical(_warm(), now_hour=10, recent_rate=3, data_class="financial") == []


# --- off_hours ---
def test_off_hours_fires():
    bs = detector.evaluate_statistical(_warm(), now_hour=3, recent_rate=2, data_class="financial")
    assert "off_hours" in _reasons(bs)


# --- rate_spike ---
def test_rate_spike_warning_and_critical():
    warn = detector.evaluate_statistical(_warm(), now_hour=10, recent_rate=4 * 3 + 1, data_class="financial")
    assert any(b.reason == "rate_spike" and b.severity == "warning" for b in warn)
    crit = detector.evaluate_statistical(_warm(), now_hour=10, recent_rate=4 * 6 + 1, data_class="financial")
    assert any(b.reason == "rate_spike" and b.severity == "critical" for b in crit)


def test_no_rate_spike_without_band():
    bl = _warm(rate_band_max=0)
    assert not any(b.reason == "rate_spike"
                   for b in detector.evaluate_statistical(bl, now_hour=10, recent_rate=999, data_class="financial"))


# --- dataclass_escalation ---
def test_dataclass_escalation_fires_for_new_class():
    bs = detector.evaluate_statistical(_warm(), now_hour=10, recent_rate=2, data_class="phi")
    assert "dataclass_escalation" in _reasons(bs)


def test_dataclass_quiet_for_known_class():
    bs = detector.evaluate_statistical(_warm(), now_hour=10, recent_rate=2, data_class="financial")
    assert "dataclass_escalation" not in _reasons(bs)


# --- data-class tagger ---
def test_dataclass_of_tagging():
    assert baseline.dataclass_of("read_chart", {"note": "patient MRN 123"}) == "phi"
    assert baseline.dataclass_of("pay_invoice", {"memo": "wire payment"}) == "financial"
    assert baseline.dataclass_of("file_read", {"path": "/etc/hosts"}) is None


# --- baseline rate learning + confirm-and-learn folding ---
def test_observe_learns_rate_band_then_returns_recent_rate(monkeypatch):
    monkeypatch.setattr(baseline, "WARMUP_MIN_ACTIONS", 100)  # stay warming
    a = "agent-rate"
    for _ in range(3):
        snap = baseline.observe(T, a, "file_read", [], [])
    assert snap.recent_rate >= 1
    assert baseline.load(T, a).rate_band_max >= 1  # band learned while warming


def test_learn_folds_hour_and_rate_and_dataclass():
    a = "agent-fold"
    baseline.load(T, a)
    baseline.learn(T, a, hour=3, rate_band=99, data_class="phi")
    g = baseline.get(T, a)
    assert 3 in g["active_hours"] and g["rate_band_max"] == 99 and "phi" in g["data_classes"]
