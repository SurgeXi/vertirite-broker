# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Behavioral binding — Mechanism #3 (docs/PROTECTION-MODEL.md §2.3).

"Bind to the body it governs, not the metal." On first run the edge records its
environment fingerprint as the BOUND fingerprint. If the live fingerprint ever
stops matching, the install is running in a FOREIGN environment (it was copied) —
an immune rejection. Mechanism #2 DETECTS the copy at the control plane; #3 makes
the copy useless on the edge.

Two postures:
  * detection (default) — record the binding, detect drift, raise a finding. Safe
    on the software/container tier where a recreate can change the fingerprint.
  * enforcement (settings.protection_binding_enforce, opt-in) — a foreign
    fingerprint withholds the premium catalog (baseline-only). Recommended on the
    fixed-hardware Pulse Edge node, where the fingerprint is stable.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from ..config import settings
from . import fingerprint, identity, store

logger = logging.getLogger("vertirite.protection.binding")

_cached_bound: Optional[str] = None


def _bound() -> Optional[str]:
    global _cached_bound
    if _cached_bound is not None:
        return _cached_bound
    _cached_bound = store.get_bound_fingerprint()
    return _cached_bound


def _bind_if_unset() -> str:
    """First-run / upgrade: bind to the current environment if not yet bound."""
    global _cached_bound
    cur = fingerprint.compute()
    if not _bound():
        store.set_bound_fingerprint(cur)
        _cached_bound = cur
        logger.info("protection: bound to environment fingerprint %s…", cur[:12])
    return cur


def is_foreign() -> bool:
    """True if bound AND the live fingerprint no longer matches. Cheap (cached
    fingerprint + cached bound value) — safe on the hot path. False when binding
    is disabled or not yet bound."""
    if not settings.protection_binding_enabled:
        return False
    bound = _bound()
    if not bound:
        return False
    return fingerprint.compute() != bound


def enforced() -> bool:
    return bool(settings.protection_binding_enabled and settings.protection_binding_enforce)


def binding_state() -> Dict[str, Any]:
    cur = fingerprint.compute()
    bound = _bound()
    matches = (bound is None) or (cur == bound)
    return {
        "bound_fingerprint": (bound[:12] + "…") if bound else None,
        "current_fingerprint": cur[:12] + "…",
        "matches": matches,
        "foreign": (not matches),
        "enforced": enforced(),
    }


def rebind() -> Dict[str, Any]:
    """Operator action: re-bind to the CURRENT environment (a legitimate move)."""
    global _cached_bound
    cur = fingerprint.compute()
    store.set_bound_fingerprint(cur)
    _cached_bound = cur
    logger.info("protection: re-bound to environment fingerprint %s…", cur[:12])
    return binding_state()


def check(tenant_id: str = "default") -> Dict[str, Any]:
    """Cold-path: bind-if-unset, and if foreign raise the self-finding. Returns
    the binding state. Called from catalog_status + the feed sweep."""
    if not settings.protection_binding_enabled:
        return {"enforced": False, "foreign": False, "matches": True,
                "bound_fingerprint": None, "current_fingerprint": None}
    _bind_if_unset()
    state = binding_state()
    if state["foreign"]:
        _raise_foreign_finding(tenant_id, state)
    return state


def _raise_foreign_finding(tenant_id: str, state: Dict[str, Any]) -> None:
    from ..discovery.findings import report_finding

    rec = identity.get_instance()
    report_finding(
        tenant_id=tenant_id,
        source_host_id=rec["instance_id"],
        target_hostname="vertirite-self",
        signal_type="network",
        pattern_id="self-environment-changed",
        confidence_override="high",
        evidence={
            "plane": "self",
            "bound_fingerprint": state["bound_fingerprint"],
            "current_fingerprint": state["current_fingerprint"],
            "enforced": state["enforced"],
            "instance_id": rec["instance_id"],
        },
    )
    store.mark_foreign()
    logger.warning(
        "SELF-ENVIRONMENT-CHANGED: live fingerprint %s no longer matches bound %s "
        "— this install may be a copy in a foreign environment%s",
        state["current_fingerprint"], state["bound_fingerprint"],
        " (premium catalog withheld)" if state["enforced"] else " (detection only)",
    )


def reset_cache() -> None:
    """Test hook."""
    global _cached_bound
    _cached_bound = None
