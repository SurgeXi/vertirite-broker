# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Stage 2 enforcement policy — the ROUTE / BLOCK decision the forward-proxy
applies to each AI call before it leaves the building.

Deterministic + inference-free, like the rest of the gate. Reuses the SAME
threat / AI markers the Coverage Map ranks by (``discovery/coverage.py``) so
"what discovery flags" and "what the proxy blocks" can never drift apart.

Decision ladder:
  1. destination/model matches a THREAT signature  -> BLOCK (never routed)
  2. model is on the sanctioned allowlist           -> ROUTE (explicitly approved)
  3. otherwise (unsanctioned, non-threat)           -> settings.proxy_default_decision
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from ..config import settings
from ..discovery.coverage import _THREAT_MARKERS


@dataclass(frozen=True)
class Decision:
    action: str          # "route" | "block"
    reason: str
    sanctioned: bool     # destination/model explicitly approved
    is_threat: bool      # matched a threat marker

    @property
    def allowed(self) -> bool:
        return self.action != "block"


def _sanctioned_models() -> tuple[str, ...]:
    raw = (settings.proxy_sanctioned_models or "").strip()
    return tuple(p.strip().lower() for p in raw.split(",") if p.strip())


def _host_of(destination: str) -> str:
    """Normalise a URL or host:port down to a bare hostname for matching."""
    d = (destination or "").strip().lower()
    if "://" in d:
        d = urlparse(d).hostname or d
    return d.split("/")[0].split(":")[0]


def decide(destination: str, model: str = "") -> Decision:
    """Return the ROUTE/BLOCK decision for a (destination, model) pair."""
    host = _host_of(destination)
    blob = f"{host} {(model or '').lower()}"

    # 1. Threat -> always BLOCK. A miner / exfil / C2 destination is never routed.
    if any(m in blob for m in _THREAT_MARKERS):
        return Decision("block", f"destination matches a threat signature ({host})",
                        sanctioned=False, is_threat=True)

    # 2. Sanctioned model allowlist -> ROUTE (explicitly approved).
    allow = _sanctioned_models()
    if allow and any((model or "").lower().startswith(p) for p in allow):
        return Decision("route", f"model '{model}' is on the sanctioned allowlist",
                        sanctioned=True, is_threat=False)

    # 3. Unsanctioned, non-threat -> the configured default.
    default = (settings.proxy_default_decision or "route").lower()
    if default == "block":
        return Decision("block", "unsanctioned destination and default policy is block",
                        sanctioned=False, is_threat=False)
    return Decision("route", "unsanctioned — allowed but audited + flagged for review",
                    sanctioned=False, is_threat=False)
