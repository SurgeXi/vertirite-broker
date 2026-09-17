# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Calibrating gate (Wave B #7) — SUGGEST ONLY.

Approval fatigue is what kills these products in month three. The calibrating
gate watches the human approval history and identifies action patterns that have
been consistently approved (proven-safe) so it can SUGGEST them for
auto-promotion — shrinking the human set over time.

SAFETY (non-negotiable): this NEVER auto-approves. It only produces suggestions.
Turning a suggestion into an actual auto-promote is a separate, explicit,
audited operator opt-in. A single denial disqualifies a pattern. This module is
pure (history in -> suggestions out), so the whole judgment is testable.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List

_APPROVE = ("approve", "approved", "allow", "allowed")
_DENY = ("deny", "denied", "block", "blocked", "reject", "rejected")


def build_promotion_suggestions(history: List[Dict[str, Any]], *,
                                min_approvals: int = 10,
                                min_approve_rate: float = 1.0) -> List[Dict[str, Any]]:
    """``history``: [{"pattern"|"capability": str, "decision": "approve"|"deny"}, ...].

    Returns one suggestion per pattern. ``suggest_auto_promote`` is True ONLY when
    the pattern has >= ``min_approvals`` approvals, ZERO denials, and an approve
    rate >= ``min_approve_rate`` (default 1.0 = every decision approved). Suggest
    only — never acts."""
    agg: Dict[str, Dict[str, int]] = defaultdict(lambda: {"approvals": 0, "denials": 0})
    for h in history or []:
        pat = h.get("pattern") or h.get("capability")
        if not pat:
            continue
        d = (h.get("decision") or "").strip().lower()
        if d in _APPROVE:
            agg[pat]["approvals"] += 1
        elif d in _DENY:
            agg[pat]["denials"] += 1

    out: List[Dict[str, Any]] = []
    for pat, c in sorted(agg.items()):
        total = c["approvals"] + c["denials"]
        rate = (c["approvals"] / total) if total else 0.0
        suggested = (c["approvals"] >= min_approvals and c["denials"] == 0
                     and rate >= min_approve_rate)
        if suggested:
            note = "Consistently approved — consider auto-promoting (operator confirm required)."
        elif c["denials"]:
            note = "Has denials — keep human-gated."
        else:
            note = f"Needs >= {min_approvals} clean approvals (has {c['approvals']})."
        out.append({
            "pattern": pat,
            "approvals": c["approvals"],
            "denials": c["denials"],
            "approve_rate": round(rate, 3),
            "suggest_auto_promote": suggested,
            "note": note,
        })
    return out


def build_promotion(pattern, actor, suggestion, now=None):
    """Turn a SUGGESTION into an actual auto-promotion record — the explicit,
    audited operator opt-in. Guard: only a pattern the gate actually suggested
    (suggest_auto_promote True) can be promoted; anything else is refused.
    Pure + reversible."""
    from datetime import datetime, timezone
    now = now or datetime.now(timezone.utc)
    if not (suggestion and suggestion.get("suggest_auto_promote")):
        return {"promoted": False, "pattern": pattern,
                "reason": "pattern was not suggested for promotion \u2014 refusing to auto-promote"}
    if not actor:
        return {"promoted": False, "pattern": pattern,
                "reason": "missing operator (opt-in required)"}
    return {"promoted": True, "pattern": pattern, "promoted_by": actor,
            "promoted_at": now.isoformat(), "active": True,
            "note": "Operator opt-in recorded; this pattern may now auto-approve. Reversible."}
