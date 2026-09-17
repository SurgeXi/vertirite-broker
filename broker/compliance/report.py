# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""report — the compliance-evidence report generator (pillar 3).

For a tenant + time window, aggregates the deterministic enforcement activity Vertirite
recorded (breaks detected/severity/status, containment actions, governance audit
events, chokepoints crossed) and maps it to the control frameworks (frameworks.py).
The result is sealed with a deterministic content hash so it is tamper-evident — the
"signed record an auditor can accept", produced on-node.

Everything here reads structured tables (break_events, agent_containment_state,
audit_events) — no model, no external call. Ed25519 signing (reusing
intelligence/signing.sign_bundle with a per-node compliance key) is the production
seal on top of the content hash; wired via sign() when a key is provided.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..config import settings
from ..db import session_scope
from ..intelligence import signing
from . import frameworks
from ..protection.breaks.events import BreakEventTable
from ..protection.breaks.containment_state import AgentContainmentStateTable
from ..tables import AuditEventTable


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _in_window(dt: Optional[datetime], since: Optional[datetime], until: Optional[datetime]) -> bool:
    dt = _aware(dt)
    if dt is None:
        return False
    if since and dt < since:
        return False
    if until and dt > until:
        return False
    return True


def _tally(d: Dict[str, int], key: str) -> None:
    d[key] = d.get(key, 0) + 1


def build_report(tenant_id: str, since: Optional[datetime] = None,
                 until: Optional[datetime] = None) -> Dict[str, Any]:
    since, until = _aware(since), _aware(until or datetime.now(timezone.utc))

    breaks_by_reason: Dict[str, int] = {}
    breaks_by_severity: Dict[str, int] = {}
    breaks_by_status: Dict[str, int] = {}
    chokepoints_seen: set[str] = set()
    breaks_total = 0

    with session_scope() as db:
        for row in db.execute(
            select(BreakEventTable).where(BreakEventTable.tenant_id == tenant_id)
        ).scalars().all():
            if not _in_window(row.first_seen_at, since, until):
                continue
            breaks_total += 1
            _tally(breaks_by_reason, row.reason)
            _tally(breaks_by_severity, row.severity)
            _tally(breaks_by_status, row.status)
            try:
                chokepoints_seen.update(json.loads(row.chokepoints or "[]"))
            except Exception:
                pass

        containment_modes: Dict[str, int] = {}
        containment_actions = 0
        for row in db.execute(
            select(AgentContainmentStateTable).where(AgentContainmentStateTable.tenant_id == tenant_id)
        ).scalars().all():
            if row.set_at and _in_window(row.set_at, since, until):
                containment_actions += 1
                _tally(containment_modes, row.mode)

        governance_actions = 0
        for row in db.execute(
            select(AuditEventTable).where(AuditEventTable.tenant_id == tenant_id)
        ).scalars().all():
            if (row.action or "").split(".", 1)[0] in ("break", "containment") \
                    and _in_window(row.created_at, since, until):
                governance_actions += 1

    # Which controls were demonstrably exercised in the period.
    exercised: List[str] = ["audit.trail"]  # the audit trail is always in force
    if breaks_total:
        exercised.append("detection.break")
    if "egress" in chokepoints_seen:
        exercised.append("chokepoint.egress")
    if "irreversible" in chokepoints_seen:
        exercised.append("chokepoint.irreversible")
    if "credential" in chokepoints_seen:
        exercised.append("chokepoint.credential")
    if containment_actions:
        exercised.append("containment.detect_to_contain")
        exercised.append("approval.human_gate")  # elevations force approval

    report: Dict[str, Any] = {
        "report_type": "vertirite_compliance_evidence",
        "tenant_id": tenant_id,
        "period": {"since": since.isoformat() if since else None,
                   "until": until.isoformat() if until else None},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "activity": {
            "breaks_total": breaks_total,
            "breaks_by_reason": breaks_by_reason,
            "breaks_by_severity": breaks_by_severity,
            "breaks_by_status": breaks_by_status,
            "chokepoints_crossed": sorted(chokepoints_seen),
            "containment_actions": containment_actions,
            "containment_modes": containment_modes,
            "governance_audit_events": governance_actions,
        },
        "controls_exercised": [frameworks.control_by_id(c) for c in dict.fromkeys(exercised)],
        "control_catalog": frameworks.catalog(),
        "attestation": (
            f"Over the reported period, Vertirite deterministically governed this tenant's "
            f"AI/automation actions on-node: {breaks_total} behavioral break(s) detected, "
            f"{containment_actions} containment action(s) applied, "
            f"{governance_actions} governance event(s) recorded in the append-only audit trail. "
            f"Chokepoints exercised: {', '.join(sorted(chokepoints_seen)) or 'none in period'}."
        ),
        "disclaimer": frameworks.catalog()["disclaimer"],
    }
    report["integrity"] = _integrity(report)
    return report


def _integrity(report: Dict[str, Any]) -> Dict[str, str]:
    """Deterministic content hash over the report body (tamper-evidence anchor)."""
    digest = hashlib.sha256(signing.canonical_bytes(report)).hexdigest()
    return {"algo": "sha256", "hash": digest,
            "canonical": "intelligence.signing.canonical_bytes (sorted-key JSON)"}


def _load_signing_key() -> Optional[Ed25519PrivateKey]:
    """Load the per-node Ed25519 compliance signing key from settings (PEM string or
    file path). None if not configured — then reports carry the sha256 anchor only."""
    pem = (settings.compliance_signing_key or "").strip()
    if not pem and settings.compliance_signing_key_path:
        try:
            with open(settings.compliance_signing_key_path, "rb") as f:
                pem = f.read().decode()
        except OSError:
            return None
    if not pem:
        return None
    if "\\n" in pem:            # tolerate escaped-newline env delivery
        pem = pem.replace("\\n", "\n")
    try:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
    except Exception:
        return None
    return key if isinstance(key, Ed25519PrivateKey) else None


def sign(report: Dict[str, Any], private_key: Ed25519PrivateKey) -> Dict[str, Any]:
    """Attach an Ed25519 signature over the report (reuses intelligence.signing)."""
    return signing.sign_bundle(report, private_key)


def build_signed_report(tenant_id: str, since: Optional[datetime] = None,
                        until: Optional[datetime] = None) -> Dict[str, Any]:
    """build_report + the production seal: Ed25519-sign with the per-node compliance
    key when configured; otherwise the sha256 integrity anchor stands alone."""
    report = build_report(tenant_id, since, until)
    key = _load_signing_key()
    if key is not None:
        report["seal"] = "ed25519"   # set BEFORE signing so the signature covers it
        report = sign(report, key)
    else:
        report["seal"] = "sha256-only"
        report["signature"] = None
        report["signature_note"] = ("no compliance signing key configured "
                                     "(SURGE_OPERATOR_COMPLIANCE_SIGNING_KEY); "
                                     "sha256 integrity anchor only")
    return report
