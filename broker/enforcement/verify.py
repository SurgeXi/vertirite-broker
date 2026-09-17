# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Closed-loop enforcement verification (Wave B #5 — the verify stage).

After a BLOCK is applied at the customer's in-path device (NGFW / DNS / proxy),
DID IT ACTUALLY TAKE? This is the "stop button that proves it stopped" — the moat.

Vertirite is the brain, not the wire, so it does NOT probe by default: the
``AdvisoryProber`` returns "unknown" and generates zero traffic. A real prober
(DNS-resolution or TCP-connect check) is OPT-IN and only runs in a lab /
enforcing-mode configuration. The verdict logic and the prober are separate, so
the whole thing is testable without ever touching a live device.

Staged roadmap: advisory (done) -> connectors (done, gated) -> **verify (here)**
-> managed. See docs/GOVERNANCE-ENFORCEMENT.md.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional, Protocol


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Prober(Protocol):
    def probe(self, target: str, plane: str) -> str:
        """Return 'closed' (blocked), 'open' (still reachable), or 'unknown'."""
        ...


class AdvisoryProber:
    """Default prober: never touches the network (brain not the wire). Verification
    is 'unknown' unless a real prober is configured for a lab / enforcing run."""

    name = "advisory"

    def probe(self, target: str, plane: str) -> str:  # noqa: D401
        return "unknown"


_PROBE_STATES = ("open", "closed", "unknown")


def _applied_of(apply_result: Any) -> bool:
    if isinstance(apply_result, dict):
        return bool(apply_result.get("applied"))
    return bool(getattr(apply_result, "applied", False))


def _connector_of(apply_result: Any) -> Optional[str]:
    if isinstance(apply_result, dict):
        return apply_result.get("connector")
    return getattr(apply_result, "connector", None)


def build_verification_record(apply_result: Any, probe_state: str, target: str,
                              plane: str, checked_at: Optional[datetime] = None) -> dict:
    """Map (apply_result, probe_state) -> a verification verdict. Pure + testable —
    the entire risk surface of this stage."""
    if probe_state not in _PROBE_STATES:
        probe_state = "unknown"
    applied = _applied_of(apply_result)
    if not applied:
        verified, verdict = None, "advisory only — nothing enforced (dry-run)"
    elif probe_state == "closed":
        verified, verdict = True, "verified closed — the block took effect"
    elif probe_state == "open":
        verified, verdict = False, "STILL OPEN — the block did not take; escalate"
    else:
        verified, verdict = None, "applied — live verification unavailable"
    return {
        "type": "vertirite.enforcement.verification",
        "target": target,
        "plane": plane,
        "connector": _connector_of(apply_result),
        "applied": applied,
        "probe": probe_state,
        "verified": verified,
        "verdict": verdict,
        "checked_at": (checked_at or _utc_now()).isoformat(),
    }


def verify_block(target: str, plane: str, apply_result: Any,
                 prober: Optional[Prober] = None) -> dict:
    """Probe the target (default: no-op AdvisoryProber -> 'unknown') and build the
    verdict. Never raises: a prober error degrades to 'unknown'."""
    p = prober or get_prober()
    try:
        state = p.probe(target, plane)
    except Exception:
        state = "unknown"
    return build_verification_record(apply_result, state, target, plane)


import socket


class DnsProber:
    """OPT-IN prober: resolves the hostname. A resolution FAILURE (NXDOMAIN /
    sinkhole) -> 'closed' (the DNS-RPZ block is active); a normal answer ->
    'open'. Makes a REAL DNS query, so it runs only when enforcement verify is
    explicitly enabled (lab / enforcing mode). A pluggable resolver keeps it
    testable without touching the network."""

    name = "dns"

    def __init__(self, resolver=None):
        self._resolve = resolver or (lambda host: socket.getaddrinfo(host, None))

    def probe(self, target: str, plane: str) -> str:
        host = (target or "").split("/")[0].split(":")[0]
        if not host:
            return "unknown"
        try:
            self._resolve(host)
            return "open"      # still resolves -> not blocked
        except Exception:
            return "closed"    # NXDOMAIN / sinkhole -> blocked


def get_prober(settings=None) -> "Prober":
    """The active prober. Default = AdvisoryProber (no-op, brain-not-the-wire).
    A real prober runs ONLY when ``enforcement_verify_enabled`` is set."""
    if settings is None:
        try:
            from ..config import settings as settings  # type: ignore
        except Exception:
            return AdvisoryProber()
    if getattr(settings, "enforcement_verify_enabled", False):
        return DnsProber()
    return AdvisoryProber()
