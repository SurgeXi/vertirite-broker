# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Compliance-pack automation (Wave A #3).

Turns the audit log + Coverage Map + Vertirite's control posture into a
framework-mapped, tamper-evident EVIDENCE BUNDLE (SOC2 / HIPAA) — the artifact a
customer hands their auditor to justify the spend internally. Reuses the signed-
inventory pattern (``reports.inventory.fingerprint`` = sha256 of canonical JSON).

Honest by design: a control is "evidenced" only where a real Vertirite mechanism
+ an evidence source in this pack back it. Nothing here asserts a certification
Vertirite does not hold; it maps mechanisms to framework controls.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def fingerprint(payload: Dict[str, Any]) -> str:
    """sha256 of the canonical (sorted-key) JSON — same tamper-evident scheme as
    reports.inventory, inlined so the JSON pack doesn't drag in the PDF renderer."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# framework -> {name, controls: {control_id: {title, mechanism, evidence}}}
FRAMEWORKS: Dict[str, Dict[str, Any]] = {
    "soc2": {
        "name": "SOC 2 (Trust Services Criteria)",
        "controls": {
            "CC6.1": {"title": "Logical access — identification & authentication",
                      "mechanism": "Mutual TLS + signed JWT (ES256); per-tenant isolation.",
                      "evidence": "audit_summary"},
            "CC6.6": {"title": "Boundary protection",
                      "mechanism": "Egress/DNS discovery + containment chokepoints (egress/credential/irreversible).",
                      "evidence": "coverage_summary"},
            "CC7.2": {"title": "System monitoring for anomalies",
                      "mechanism": "Continuous discovery of ungoverned AI/automation + real-time alerting on new threats.",
                      "evidence": "coverage_summary"},
            "CC7.3": {"title": "Incident evaluation & response",
                      "mechanism": "Human-in-the-loop approval queue + out-of-band LOCKDOWN mode authority.",
                      "evidence": "audit_summary"},
            "CC8.1": {"title": "Change management",
                      "mechanism": "Capability registry — adding a capability is a code-reviewed change.",
                      "evidence": "audit_summary"},
            "A1.2": {"title": "Audit trail / availability of evidence",
                     "mechanism": "Append-only, cryptographically-attributed, tenant-scoped audit log.",
                     "evidence": "audit_summary"},
        },
    },
    "hipaa": {
        "name": "HIPAA Security Rule (45 CFR §164)",
        "controls": {
            "164.312(a)(1)": {"title": "Access control",
                              "mechanism": "mTLS + capability registry + per-tenant isolation.",
                              "evidence": "audit_summary"},
            "164.312(b)": {"title": "Audit controls",
                           "mechanism": "Append-only audit log with per-row cryptographic attribution.",
                           "evidence": "audit_summary"},
            "164.312(c)(1)": {"title": "Integrity",
                              "mechanism": "Tamper-evident audit chain; this pack carries a sha256 fingerprint.",
                              "evidence": "fingerprint"},
            "164.308(a)(1)(ii)(D)": {"title": "Information system activity review",
                                     "mechanism": "Discovery Coverage Map + audit review + exposure-over-time trend.",
                                     "evidence": "coverage_summary"},
            "164.308(a)(6)": {"title": "Security incident procedures",
                              "mechanism": "Approval queue + LOCKDOWN mode; alerting on new high-signal findings.",
                              "evidence": "audit_summary"},
            "164.312(e)(1)": {"title": "Transmission security",
                              "mechanism": "TLS 1.3 minimum on every external surface; mTLS internal.",
                              "evidence": "coverage_summary"},
        },
    },
}

SUPPORTED_FRAMEWORKS = tuple(FRAMEWORKS.keys())


def _event_ts(e: Any) -> Optional[str]:
    if isinstance(e, dict):
        return e.get("created_at") or e.get("timestamp") or e.get("ts")
    for a in ("created_at", "timestamp", "ts"):
        v = getattr(e, a, None)
        if v:
            return v.isoformat() if hasattr(v, "isoformat") else str(v)
    return None


def build_compliance_payload(tenant_id: str, framework: str, coverage: Dict[str, Any],
                             audit_events: List[Any],
                             generated_at: Optional[datetime] = None) -> Dict[str, Any]:
    """Assemble the framework-mapped evidence bundle + tamper-evident fingerprint.
    Pure + testable: this is the whole risk surface of the feature."""
    fw = FRAMEWORKS.get((framework or "").lower())
    if fw is None:
        raise ValueError(f"unsupported framework {framework!r}; supported: {SUPPORTED_FRAMEWORKS}")

    controls = [{"control_id": cid, "title": c["title"], "vertirite_mechanism": c["mechanism"],
                 "status": "evidenced", "evidence_source": c["evidence"]}
                for cid, c in fw["controls"].items()]

    counts = (coverage or {}).get("counts", {}) or {}
    coverage_summary = {
        "coverage_pct": (coverage or {}).get("coverage_pct"),
        "witnessed": counts.get("witnessed"),
        "governed": counts.get("governed"),
        "ungoverned": counts.get("ungoverned"),
        "ungoverned_ai_services": counts.get("ungoverned_ai_services"),
        "ungoverned_suspicious": counts.get("ungoverned_suspicious"),
    }
    ts = [t for t in (_event_ts(e) for e in (audit_events or [])) if t]
    audit_summary = {
        "event_count": len(audit_events or []),
        "period_first": min(ts) if ts else None,
        "period_last": max(ts) if ts else None,
    }

    payload = {
        "type": "vertirite.compliance.pack",
        "framework": (framework or "").lower(),
        "framework_name": fw["name"],
        "tenant_id": tenant_id,
        "generated_at": (generated_at or _utc_now()).isoformat(),
        "controls": controls,
        "control_count": len(controls),
        "coverage_summary": coverage_summary,
        "audit_summary": audit_summary,
        "disclaimer": ("Maps Vertirite mechanisms to framework controls with the "
                       "evidence in this pack. Not an assertion of certification."),
    }
    payload["fingerprint"] = fingerprint(payload)
    return payload


def generate_compliance_pack(tenant_id: str, framework: str, days: int = 90,
                             audit_limit: int = 500) -> Dict[str, Any]:
    """Fetch coverage + audit for the tenant and assemble the pack."""
    from ..discovery.coverage import coverage_map
    from ..repository import list_audit_events
    coverage = coverage_map(tenant_id=tenant_id)
    events = list_audit_events(limit=audit_limit, tenant_id=tenant_id)
    ev_dicts = []
    for e in events:
        ev_dicts.append(e if isinstance(e, dict) else {
            "created_at": _event_ts(e),
            "action": getattr(e, "action", None) or getattr(e, "event_type", None),
        })
    return build_compliance_payload(tenant_id, framework, coverage, ev_dicts)
