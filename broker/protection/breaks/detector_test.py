# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Detector rules — deterministic, no DB. Each rule fires on its trigger and
stays SILENT on baselined/benign behavior (the no-false-positive discipline)."""
import os
import tempfile

_db_fd, _db_path = tempfile.mkstemp(suffix="-breaks-detector.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from broker.protection.breaks.baseline import Baseline  # noqa: E402
from broker.protection.breaks import detector  # noqa: E402


def _reasons(breaks):
    return {b.reason for b in breaks}


# --- first_irreversible: fires ALWAYS (even while warming) -------------------

def test_first_irreversible_fires_while_warming():
    bl = Baseline("t", "agent-1")  # warming, nothing seen
    breaks = detector.evaluate_attempt(bl, "pay_invoice", ["irreversible"], [])
    assert "first_irreversible" in _reasons(breaks)
    assert next(b for b in breaks if b.reason == "first_irreversible").severity == "critical"


def test_first_irreversible_silent_once_seen():
    bl = Baseline("t", "agent-1", irreversible_seen=True)
    assert detector.evaluate_attempt(bl, "pay_invoice", ["irreversible"], []) == []


# --- novel_egress: only once WARM; learned (silent) while warming ------------

def test_novel_egress_fires_when_warm():
    bl = Baseline("t", "agent-1", state="warm")
    breaks = detector.evaluate_attempt(bl, "http_get", ["egress"], ["evil.example.com"])
    assert "novel_egress" in _reasons(breaks)


def test_novel_egress_silent_while_warming():
    bl = Baseline("t", "agent-1")  # warming
    assert detector.evaluate_attempt(bl, "http_get", ["egress"], ["evil.example.com"]) == []


def test_known_egress_is_quiet_when_warm():
    bl = Baseline("t", "agent-1", egress_destinations={"api.openai.com"}, state="warm")
    assert detector.evaluate_attempt(bl, "http_get", ["egress"], ["api.openai.com"]) == []


# --- first_credential: only once WARM ----------------------------------------

def test_first_credential_fires_when_warm():
    bl = Baseline("t", "agent-1", state="warm")
    breaks = detector.evaluate_attempt(bl, "fleet_ssh", ["credential"], [])
    assert "first_credential" in _reasons(breaks)


def test_first_credential_silent_when_seen():
    bl = Baseline("t", "agent-1", state="warm", credential_seen=True)
    assert detector.evaluate_attempt(bl, "fleet_ssh", ["credential"], []) == []


# --- a well-behaved warm agent raises nothing (no-false-positive gate) --------

def test_warm_agent_no_chokepoints_is_silent():
    bl = Baseline("t", "agent-1", state="warm",
                  egress_destinations={"api.openai.com"}, credential_seen=True,
                  irreversible_seen=True)
    assert detector.evaluate_attempt(bl, "file_read", [], []) == []


# --- denials: scope_violation always; denial_burst at threshold --------------

def test_scope_violation_always_fires():
    bl = Baseline("t", "agent-1")
    breaks = detector.evaluate_denial(bl, "fleet_ssh", "not scoped for this tenant", denial_count=1)
    assert _reasons(breaks) == {"scope_violation"}


def test_denial_burst_at_threshold():
    bl = Baseline("t", "agent-1")
    breaks = detector.evaluate_denial(bl, "fleet_ssh", "denied", denial_count=detector.DENIAL_BURST_THRESHOLD)
    assert _reasons(breaks) == {"scope_violation", "denial_burst"}
    assert next(b for b in breaks if b.reason == "denial_burst").severity == "critical"
