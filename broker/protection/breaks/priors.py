# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""priors — per-vertical cold-start seeds for a new agent's baseline.

A brand-new agent has no history, so its first legitimate actions (touching PHI,
moving money) would otherwise read as novel. Per the FEATURE-break-detection.md
resolved decision, a new agent inherits its vertical pack's PRIOR — initial
expectations that the learned per-agent baseline then overrides as it warms.

Seeding is data-class-focused (the safest, most concrete seed): a medical agent
expects PHI, an accounting agent expects financial data, so day-one legitimate
work doesn't fire dataclass_escalation. The prior also records egress expectations
(OT never reaches the internet) for future tightening — carried here, applied to
data-classes today.

Vertical is resolved from settings.tenant_verticals (JSON map tenant_id -> vertical);
unknown tenants get no prior (identical to prior behavior). Deterministic, no model.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from ...config import settings

logger = logging.getLogger("vertirite.breaks.priors")

# vertical -> prior. `data_classes` seed the baseline; `internet_egress_expected`
# is carried for future egress tightening (OT should never reach the internet).
PRIORS = {
    "medical": {
        "data_classes": ["phi"],
        "internet_egress_expected": True,   # cloud EHR/telehealth common
    },
    "accounting": {
        "data_classes": ["financial", "pii"],
        "internet_egress_expected": True,
    },
    "manufacturing": {   # OT / industrial
        "data_classes": [],
        "internet_egress_expected": False,  # OT east-west; internet egress is suspicious
    },
}


def vertical_for(tenant_id: str) -> Optional[str]:
    """Resolve a tenant's vertical from settings.tenant_verticals (JSON map), or None."""
    raw = (settings.tenant_verticals or "").strip()
    if not raw:
        return None
    try:
        mapping = json.loads(raw)
    except Exception:
        logger.warning("tenant_verticals is not valid JSON; ignoring")
        return None
    v = mapping.get(tenant_id)
    return v if v in PRIORS else None


def prior_for(tenant_id: str) -> Optional[dict]:
    v = vertical_for(tenant_id)
    return {"vertical": v, **PRIORS[v]} if v else None
