# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""The edge beacon — Mechanism #2 PR2 (docs/FLEET-ARCHITECTURE.md step 4).

On the Connected phone-home cadence, the edge sends a METADATA-ONLY beacon
(instance_id + canary + environment fingerprint + catalog/suppression state) to
the configured ingress. The control plane uses it to detect a copy reporting from
a foreign environment (foreign-fingerprint) and to surface suppression/tamper
across the fleet.

**Metadata only** — NEVER findings, traffic, or host inventory contents. That is
the privacy line that keeps the phone-home honest (FLEET-ARCHITECTURE §3).
"""
from __future__ import annotations

import logging
from typing import Any, Dict

import httpx

from ..config import settings
from . import fingerprint, identity

logger = logging.getLogger("vertirite.protection.beacon")

# The exact, closed set of fields a beacon may carry. Anything else is a leak.
BEACON_FIELDS = (
    "instance_id", "canary", "fingerprint", "tier",
    "catalog_version", "catalog_state", "suppressed",
)

# Mechanism #4 — federation telemetry: COUNTS ONLY, no hostnames / findings.
TELEMETRY_FIELDS = (
    "coverage_pct", "witnessed", "governed",
    "ai_services", "threats", "unknown", "east_west", "self",
)


def build_telemetry(tenant_id: str) -> Dict[str, Any]:
    """Metadata-only discovery aggregate for fleet learning (Mechanism #4,
    docs/PROTECTION-MODEL.md §2.4). Counts only — NEVER hostnames or findings
    content (FLEET-ARCHITECTURE §3 privacy boundary)."""
    from ..discovery.coverage import coverage_map

    cm = coverage_map(tenant_id)
    c = cm.get("counts", {})
    return {
        "coverage_pct": cm.get("coverage_pct", 0.0),
        "witnessed": c.get("witnessed", 0),
        "governed": c.get("governed", 0),
        "ai_services": c.get("ungoverned_ai_services", 0),
        "threats": c.get("ungoverned_suspicious", 0),
        "unknown": c.get("ungoverned_unknown", 0),
        "east_west": c.get("east_west", 0),
        "self": c.get("ungoverned_self", 0),
    }


def _tier() -> str:
    if settings.intelligence_feed_enabled and (settings.intelligence_feed_url or "").strip():
        return "connected"
    return "sovereign"


def build_beacon(tenant_id: str = "default") -> Dict[str, Any]:
    """Assemble the metadata-only beacon payload."""
    from ..intelligence.catalog import catalog_status

    rec = identity.get_instance()
    cat = catalog_status(tenant_id)
    state = identity.beacon_state(settings.protection_suppression_threshold)
    payload = {
        "instance_id": rec["instance_id"],
        "canary": rec["canary"],
        "fingerprint": fingerprint.compute(),
        "tier": _tier(),
        "catalog_version": cat.get("catalog_version", 0),
        "catalog_state": cat.get("state", "baseline-only"),
        "suppressed": bool(state.get("suppressed")),
    }
    # Mechanism #4 — opt-in federation: contribute metadata-only discovery counts.
    # Premium feature — requires both the toggle AND the 'federation' entitlement.
    if settings.protection_federation_enabled:
        from ..licensing.license import entitled
        if entitled("federation"):
            payload["telemetry"] = build_telemetry(tenant_id)
    return payload


def send_beacon(tenant_id: str = "default") -> Dict[str, Any]:
    """POST the beacon to the configured ingress. Never raises. No URL → disabled
    (Sovereign default = no phone-home)."""
    url = (settings.protection_beacon_url or "").strip()
    if not url:
        return {"status": "disabled"}
    payload = build_beacon(tenant_id)
    headers = {}
    if settings.protection_beacon_token:
        headers["X-Ingest-Token"] = settings.protection_beacon_token
    try:
        with httpx.Client(timeout=settings.intelligence_feed_timeout_s) as client:
            resp = client.post(url, json=payload, headers=headers)
        if resp.status_code // 100 == 2:
            body = {}
            try:
                body = resp.json()
            except Exception:
                pass
            return {"status": "sent", "http": resp.status_code,
                    "signals": body.get("signals", [])}
        return {"status": "rejected", "http": resp.status_code}
    except Exception as exc:  # a blocked beacon channel just retries next cycle
        logger.warning("beacon send failed (%s) — will retry next cycle", exc)
        return {"status": "unreachable", "error": str(exc)}
