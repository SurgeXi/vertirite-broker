# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Credential brokering (Wave B #6) — grant EVALUATION core.

Govern the resource an AI can't fabricate: credentials. Instead of an agent
holding a long-lived key, it requests a SCOPED, SHORT-LIVED, REVOCABLE grant.
This is the pure evaluation core: given a request + a tenant policy, decide and
SHAPE the grant (deny out-of-policy scope, cap TTL, dedupe scopes). It ISSUES
NOTHING REAL — minting/revocation against an IdP or secrets store is a separate,
lab-gated, operator-configured slice. Pure -> fully testable.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def evaluate_credential_request(request: Dict[str, Any], policy: Dict[str, Any],
                                now: Optional[datetime] = None) -> Dict[str, Any]:
    """request: {agent_id, scopes:[...], ttl_seconds?}. policy: {allowed_scopes:[...],
    max_ttl_seconds, default_ttl_seconds?}. Returns a decision + shaped grant.
    Denies scopes not in the allowlist and caps TTL to the policy max. Issues nothing."""
    now = now or _utc_now()
    req = request or {}
    pol = policy or {}
    agent = (req.get("agent_id") or "").strip()
    req_scopes = [s for s in (req.get("scopes") or []) if s]
    allowed = set(pol.get("allowed_scopes") or [])
    max_ttl = int(pol.get("max_ttl_seconds") or 3600)
    default_ttl = int(pol.get("default_ttl_seconds") or min(900, max_ttl))

    if not agent:
        return {"granted": False, "reason": "missing agent_id"}
    if not req_scopes:
        return {"granted": False, "reason": "no scopes requested"}

    denied = sorted({s for s in req_scopes if s not in allowed})
    if denied:
        return {"granted": False, "reason": f"scopes not permitted by policy: {denied}",
                "denied_scopes": denied}

    ttl = int(req.get("ttl_seconds") or default_ttl)
    capped = ttl > max_ttl
    ttl = min(ttl, max_ttl)
    if ttl <= 0:
        return {"granted": False, "reason": "non-positive ttl"}

    return {
        "granted": True,
        "grant_id": str(uuid.uuid4()),
        "agent_id": agent,
        "scopes": sorted(set(req_scopes)),
        "ttl_seconds": ttl,
        "ttl_capped": capped,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=ttl)).isoformat(),
        "note": "Evaluated + shaped only — no real credential minted (issuance is a lab-gated slice).",
    }
