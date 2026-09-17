#!/usr/bin/env python3
# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""End-to-end smoke for Break Detection (P1/P2/P3) + compliance evidence.

Drives the REAL pipeline in-process (containment.apply -> service.observe_* ->
baseline/detector/events/containment_state -> compliance.report), asserts each
capability, and prints a PASS/FAIL checklist. Exit 0 = all green.

    python3 apps/broker/bench/break_detection_smoke.py

Self-contained: fresh temp DB, both flags ON. Nothing external, no HTTP. This is
the turnkey "does the whole thing work" check for a smoke session; the HTTP + UI +
on-node latency steps are in docs/SMOKE-TEST-BREAK-DETECTION.md.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_fd, _db = tempfile.mkstemp(suffix="-bd-smoke.db"); os.close(_fd)
os.environ["SURGE_OPERATOR_DATABASE_URL"] = f"sqlite+pysqlite:///{_db}"
os.environ["VERTIRITE_BREAK_DETECTION"] = "1"
os.environ["VERTIRITE_DETECT_CONTAIN"] = "1"

from broker import containment                      # noqa: E402
from broker import surge_capabilities as caps        # noqa: E402
from broker.protection.breaks import service, baseline, events, containment_state  # noqa: E402
from broker.compliance import report                 # noqa: E402

TENANT = "smoke"
_results: list[tuple[bool, str]] = []


def _check(ok: bool, label: str) -> None:
    _results.append((bool(ok), label))
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")


def _ctx(actor: str, session: str = "s1") -> caps.InvocationContext:
    return caps.InvocationContext(tenant_id=TENANT, actor_id=actor, actor_role="agent",
                                  request_id=f"req-{actor}", parent_request_id=session)


def _drive(actor: str, capability: str, params: dict, session: str = "s1") -> None:
    """One action through the real gate-side detection path."""
    eff, chokepoints = containment.apply(caps.ApprovalClass.SAFE, capability, params)
    service.observe_attempt(_ctx(actor, session), capability, params, eff, chokepoints)


def _reasons(actor: str) -> set[str]:
    return {b["reason"] for b in events.list_breaks(tenant_id=TENANT) if b["actor_id"] == actor}


def _schema():
    from broker.db import Base, engine, init_db
    init_db(); Base.metadata.create_all(bind=engine)


def main() -> int:
    _schema()
    baseline.WARMUP_MIN_ACTIONS = 3  # quick warm for the smoke

    print("Break Detection E2E smoke\n")

    # 1. Warm-up learns silently (novelty suppressed while warming)
    a = "agent-A"
    for _ in range(3):
        _drive(a, "file_read", {"path": "/etc/hosts"})
    _check(baseline.load(TENANT, a).is_warm, "baseline warms after WARMUP_MIN_ACTIONS")
    _check("novel_egress" not in _reasons(a), "no novelty breaks raised while warming")

    # 2. novel_egress once warm
    _drive(a, "http_get", {"url": "https://evil.example.com/x"})
    _check("novel_egress" in _reasons(a), "novel_egress fires for a warm agent")

    # 3. first_irreversible + P3 auto-clamp to high_stakes
    _drive(a, "pay_invoice", {"amount": "5000", "to": "acct-9"})
    _check("first_irreversible" in _reasons(a), "first_irreversible fires (money movement)")
    st = containment_state.get_state(TENANT, a)
    _check(st and st["mode"] == "elevated_high_stakes",
           "auto-clamp: agent elevated to high_stakes after irreversible break")

    # 4. gate enforcement — the clamp raises a SAFE action to HIGH_STAKES
    eff, quarantined, _ = containment_state.enforce(TENANT, a, caps.ApprovalClass.SAFE)
    _check(eff == caps.ApprovalClass.HIGH_STAKES and not quarantined,
           "enforce() raises a clamped agent's floor to HIGH_STAKES")

    # 5. operator quarantine → deny
    containment_state.set_state(TENANT, "agent-Q", "quarantined", "confirmed exfil", set_by="op")
    _, q, _ = containment_state.enforce(TENANT, "agent-Q", caps.ApprovalClass.SAFE)
    _check(q, "enforce() signals DENY for a quarantined agent")

    # 6. rate_spike — a burst well past the learned band
    b = "agent-B"
    for _ in range(3):
        _drive(b, "file_read", {"path": "/tmp/x"})            # warm (band learned)
    for _ in range(20):
        _drive(b, "file_read", {"path": "/tmp/x"})            # burst
    _check("rate_spike" in _reasons(b), "rate_spike fires on a burst past the learned band")

    # 7. session_scope_drift — benign session that reaches for something dangerous
    c = "agent-C"
    for _ in range(3):
        _drive(c, "file_read", {"path": "/tmp/y"}, session="sess-C")
    _drive(c, "fleet_ssh", {"host": "n1", "command": "sudo rm -rf /data"}, session="sess-C")
    _check("session_scope_drift" in _reasons(c), "session_scope_drift fires on mid-task escalation")

    # 8. compliance evidence report — sealed + reflects activity + maps controls
    rep = report.build_signed_report(TENANT)
    _check(len(rep["integrity"]["hash"]) == 64, "compliance report carries a sha256 integrity anchor")
    _check(rep["activity"]["breaks_total"] > 0, "compliance report reflects detected breaks")
    ctrl_ids = {c["id"] for c in rep["controls_exercised"]}
    _check({"detection.break", "chokepoint.irreversible"} <= ctrl_ids,
           "compliance report maps exercised controls (detection + chokepoints)")
    _check(rep["seal"] in ("ed25519", "sha256-only"), "compliance report declares its seal")

    passed = sum(1 for ok, _ in _results if ok)
    total = len(_results)
    print(f"\n{'='*48}\n{passed}/{total} checks passed — "
          f"{'ALL GREEN' if passed == total else 'FAILURES ABOVE'}\n{'='*48}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
