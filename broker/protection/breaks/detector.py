# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""detector — the deterministic break rules (P1).

A *break* is an action that deviates from the agent's own learned-normal, or
that is off-policy regardless of history. Everything here is rule-true and
inference-free — no model, no network. This is the non-inference invariant
(docs/FEATURE-break-detection.md): you don't trust AI to police AI, so there is
no AI in the loop.

Two entry points, matching the two gate hooks:
  * ``evaluate_attempt`` — for an action the agent attempted (has the
    containment chokepoints). Fires: first_irreversible (always), novel_egress
    and first_credential (only once the baseline is warm; while warming these
    are learned, not raised).
  * ``evaluate_denial`` — for an action the gate denied. Fires: scope_violation
    (always) and, when the rolling denial count crosses the threshold,
    denial_burst (always).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .baseline import Baseline

# denial_burst threshold — N gate denials inside baseline.record_denial's window.
DENIAL_BURST_THRESHOLD = 5

# P2 rate-spike band multipliers over the agent's learned rate_band_max.
RATE_SPIKE_FACTOR = 3       # > band x this = warning
RATE_SPIKE_CRIT_FACTOR = 6  # > band x this = critical

# severity vocabulary matches notifications.send_alert: critical | warning | info
SEV_CRITICAL = "critical"
SEV_WARNING = "warning"


@dataclass(frozen=True)
class Break:
    reason: str                 # stable machine key, e.g. "novel_egress"
    severity: str               # critical | warning
    title: str                  # human one-liner
    target: str = ""            # the host / capability the break is about (dedup key)
    chokepoints: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)


def evaluate_attempt(baseline: Baseline, capability: str,
                     chokepoints: List[str], external_dests: List[str]) -> List[Break]:
    cp = set(chokepoints or [])
    breaks: List[Break] = []

    # first_irreversible — value movement / mass deletion. Fires ALWAYS (even
    # while warming): a bookkeeping agent's first-ever wire IS the alarm.
    if "irreversible" in cp and not baseline.irreversible_seen:
        breaks.append(Break(
            reason="first_irreversible", severity=SEV_CRITICAL,
            title=f"Agent {baseline.actor_id} attempted a first-ever irreversible action ({capability})",
            target=capability, chokepoints=sorted(cp),
            evidence={"capability": capability},
        ))

    # Novelty signals — only once WARM (while warming they're learned, not raised,
    # so a new agent doesn't spray false breaks).
    if baseline.is_warm:
        for dest in external_dests:
            if dest not in baseline.egress_destinations:
                breaks.append(Break(
                    reason="novel_egress", severity=SEV_WARNING,
                    title=f"Agent {baseline.actor_id} reached a never-before-seen external host: {dest}",
                    target=dest, chokepoints=sorted(cp),
                    evidence={"capability": capability, "destination": dest},
                ))
        if "credential" in cp and not baseline.credential_seen:
            breaks.append(Break(
                reason="first_credential", severity=SEV_WARNING,
                title=f"Agent {baseline.actor_id} used a credential for the first time ({capability})",
                target=capability, chokepoints=sorted(cp),
                evidence={"capability": capability},
            ))
    return breaks


def evaluate_denial(baseline: Baseline, capability: str, reason: str,
                    denial_count: int) -> List[Break]:
    """`denial_count` is the rolling window count from baseline.record_denial."""
    breaks: List[Break] = [
        Break(
            reason="scope_violation", severity=SEV_WARNING,
            title=f"Agent {baseline.actor_id} attempted an action it is not scoped for ({capability})",
            target=capability,
            evidence={"capability": capability, "denial_reason": (reason or "")[:256]},
        )
    ]
    if denial_count >= DENIAL_BURST_THRESHOLD:
        breaks.append(Break(
            reason="denial_burst", severity=SEV_CRITICAL,
            title=(f"Agent {baseline.actor_id} hit {denial_count} gate denials in a short window "
                   f"— possible hijack/probing"),
            target="denial_burst",
            evidence={"denial_count": denial_count, "last_capability": capability},
        ))
    return breaks


def evaluate_session_drift(actor_id: str, prior_count: int,
                           newly_dangerous: List[str]) -> List[Break]:
    """Session-scope drift (P3): a session that ran >= MIN_BENIGN benign actions and
    then newly crosses a dangerous chokepoint (irreversible/credential) mid-chain —
    the hijacked-mid-task signature, complementary to the per-agent baseline rules."""
    from .session_tracker import MIN_BENIGN_BEFORE_DRIFT, _DANGEROUS
    dangerous = [c for c in (newly_dangerous or []) if c in _DANGEROUS]
    if not dangerous or prior_count < MIN_BENIGN_BEFORE_DRIFT:
        return []
    crossed = sorted(dangerous)
    return [Break(
        reason="session_scope_drift", severity=SEV_WARNING,
        title=(f"Agent {actor_id}'s session escalated to {', '.join(crossed)} after "
               f"{prior_count} benign actions — possible mid-task hijack"),
        target=",".join(crossed), chokepoints=crossed,
        evidence={"prior_benign_actions": prior_count, "escalated_to": crossed},
    )]


def evaluate_statistical(baseline: Baseline, now_hour: int, recent_rate: int,
                         data_class: Optional[str]) -> List[Break]:
    """P2 statistical deviations — deterministic math over the agent's OWN learned
    bands (no model). Warm-only; a warming baseline raises nothing (bands not set)."""
    if not baseline.is_warm:
        return []
    breaks: List[Break] = []

    # off_hours — the action's hour is outside the agent's learned active hours.
    if baseline.active_hours and now_hour not in baseline.active_hours:
        breaks.append(Break(
            reason="off_hours", severity=SEV_WARNING,
            title=f"Agent {baseline.actor_id} acted at hour {now_hour}Z — outside its learned active hours",
            target=f"hour:{now_hour}",
            evidence={"hour": now_hour, "active_hours": sorted(baseline.active_hours)},
        ))

    # rate_spike — current rolling-window rate exceeds a multiple of the learned band.
    band = baseline.rate_band_max
    if band > 0 and recent_rate > band * RATE_SPIKE_FACTOR:
        sev = SEV_CRITICAL if recent_rate > band * RATE_SPIKE_CRIT_FACTOR else SEV_WARNING
        breaks.append(Break(
            reason="rate_spike", severity=sev,
            title=(f"Agent {baseline.actor_id} action rate {recent_rate}/window vs learned "
                   f"band {band} — {recent_rate // max(band,1)}x"),
            target=f"rate:{recent_rate}", evidence={"recent_rate": recent_rate, "band": band},
        ))

    # dataclass_escalation — touching a sensitive class not in the learned baseline.
    if data_class and data_class not in baseline.data_classes:
        breaks.append(Break(
            reason="dataclass_escalation", severity=SEV_WARNING,
            title=f"Agent {baseline.actor_id} touched a new sensitive data class: {data_class}",
            target=data_class,
            evidence={"data_class": data_class, "known": sorted(baseline.data_classes)},
        ))
    return breaks
