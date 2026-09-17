# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""frameworks — the control-mapping catalog (pillar 3: compliance-grade evidence).

Maps each Vertirite enforcement primitive to the specific controls it demonstrably
enforces across the frameworks regulated buyers are audited against. This is what
lets an auditor accept "the AI was governed" as a *provable, deterministic* record
rather than "the AI probably caught it" — and it's producible on-node, which cloud
rivals can't match.

INDICATIVE MAPPING. These are the controls each primitive supports; the exact
control language and scope must be validated with the customer's own auditor. We
never claim certification — we provide the deterministic evidence a certification
relies on.
"""
from __future__ import annotations

from typing import Any, Dict, List

FRAMEWORKS = ["OWASP_LLM", "MITRE_ATLAS", "HIPAA", "SOX", "NIST_800_82", "IEC_62443"]

# Each entry: a Vertirite primitive → the controls it enforces, per framework.
CONTROLS: List[Dict[str, Any]] = [
    {
        "id": "chokepoint.egress",
        "what": "Gates/holds an AI action that reaches a destination outside the perimeter.",
        "frameworks": {
            "OWASP_LLM": ["LLM06 Sensitive Information Disclosure", "LLM02 Insecure Output Handling"],
            "MITRE_ATLAS": ["AML.T0024 Exfiltration via ML Inference API", "TA0010 Exfiltration"],
            "HIPAA": ["§164.312(e)(1) Transmission Security"],
            "SOX": ["Data-egress change control", "ITGC — data confidentiality"],
            "NIST_800_82": ["SC-7 Boundary Protection"],
            "IEC_62443": ["CR 5.1 Network segmentation", "CR 4.1 Information confidentiality"],
        },
    },
    {
        "id": "chokepoint.irreversible",
        "what": "Elevates/holds un-undoable actions — deletion, value movement, force-push.",
        "frameworks": {
            "OWASP_LLM": ["LLM08 Excessive Agency"],
            "MITRE_ATLAS": ["TA0040 Impact"],
            "HIPAA": ["§164.312(c)(1) Integrity"],
            "SOX": ["Segregation of duties", "Authorization of material transactions"],
            "NIST_800_82": ["CM-5 Access Restrictions for Change"],
            "IEC_62443": ["CR 3.1 Communication integrity"],
        },
    },
    {
        "id": "chokepoint.credential",
        "what": "Gates actions that require a secret/credential to act (sudo/ssh/api-key).",
        "frameworks": {
            "OWASP_LLM": ["LLM06 Sensitive Information Disclosure", "LLM08 Excessive Agency"],
            "MITRE_ATLAS": ["TA0006 Credential Access"],
            "HIPAA": ["§164.312(a)(1) Access Control", "§164.312(d) Person/Entity Authentication"],
            "SOX": ["Logical access controls"],
            "NIST_800_82": ["AC-3 Access Enforcement", "IA-5 Authenticator Management"],
            "IEC_62443": ["CR 1.1 Identification & authentication control"],
        },
    },
    {
        "id": "approval.human_gate",
        "what": "Human-in-the-loop approval (GATED / HIGH_STAKES) before a risky action runs.",
        "frameworks": {
            "OWASP_LLM": ["LLM08 Excessive Agency", "LLM09 Overreliance"],
            "MITRE_ATLAS": ["Mitigation — human oversight of ML actions"],
            "HIPAA": ["§164.308(a)(4) Information Access Management"],
            "SOX": ["Segregation of duties", "Authorization controls"],
            "NIST_800_82": ["AC-6 Least Privilege"],
            "IEC_62443": ["CR 2.1 Authorization enforcement"],
        },
    },
    {
        "id": "audit.trail",
        "what": "Append-only, cryptographically attributable record of every action.",
        "frameworks": {
            "OWASP_LLM": ["LLM09 Overreliance — monitoring"],
            "MITRE_ATLAS": ["Logging & detection coverage"],
            "HIPAA": ["§164.312(b) Audit Controls", "§164.308(a)(1)(ii)(D) Activity Review"],
            "SOX": ["§404 internal control over financial reporting — audit trail"],
            "NIST_800_82": ["AU-2 Audit Events", "AU-12 Audit Generation"],
            "IEC_62443": ["CR 2.8 Auditable events", "CR 6.1 Audit log accessibility"],
        },
    },
    {
        "id": "detection.break",
        "what": "Deterministic detection of agent behavioral deviation (break detection).",
        "frameworks": {
            "OWASP_LLM": ["LLM09 Overreliance — anomaly monitoring"],
            "MITRE_ATLAS": ["Detection of adversarial ML behavior"],
            "HIPAA": ["§164.308(a)(1)(ii)(D) Information System Activity Review"],
            "SOX": ["Monitoring controls"],
            "NIST_800_82": ["SI-4 System Monitoring"],
            "IEC_62443": ["CR 6.2 Continuous monitoring"],
        },
    },
    {
        "id": "containment.detect_to_contain",
        "what": "Automatic/operator containment of a deviating agent (elevate floor / quarantine).",
        "frameworks": {
            "OWASP_LLM": ["LLM08 Excessive Agency — containment"],
            "MITRE_ATLAS": ["Incident response / response actions"],
            "HIPAA": ["§164.308(a)(6) Security Incident Procedures"],
            "SOX": ["Incident response"],
            "NIST_800_82": ["IR-4 Incident Handling"],
            "IEC_62443": ["CR 6.2 — response to detected events"],
        },
    },
]

# Which primitive each activity category demonstrates (for the report roll-up).
ACTIVITY_TO_CONTROL = {
    "chokepoint_egress": "chokepoint.egress",
    "chokepoint_irreversible": "chokepoint.irreversible",
    "chokepoint_credential": "chokepoint.credential",
    "approvals_gated": "approval.human_gate",
    "audit_events": "audit.trail",
    "breaks_detected": "detection.break",
    "containment_actions": "containment.detect_to_contain",
}


def catalog() -> Dict[str, Any]:
    return {
        "frameworks": FRAMEWORKS,
        "controls": CONTROLS,
        "disclaimer": ("Indicative control mapping. Vertirite provides the deterministic, "
                       "on-node evidence a certification relies on; validate exact control "
                       "scope with your auditor. We do not claim certification."),
    }


def control_by_id(cid: str) -> Dict[str, Any] | None:
    return next((c for c in CONTROLS if c["id"] == cid), None)
