# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""SKU → feature bundles.

The license carries an explicit ``features`` list (the broker only reads that), but
licenses are minted FROM a SKU — this map is the source of truth for what each SKU
grants. The mint CLI derives features from the SKU unless overridden.

Tiers mirror the two-metabolic-rate model (docs/PROTECTION-MODEL.md §4):
  * sovereign  — air-gapped: premium intelligence, but NO federation (no phone-home).
  * connected  — full Connected tier.
  * enterprise — connected + vertical packs.
  * free       — baseline discovery only (no premium MODULES).

The broker (including the full governance surface) is BSL-open and free; the license
gates the four premium MODULES only. Governance is never gated — see licensing/license.py.
"""
from __future__ import annotations

from typing import List

SKU_FEATURES: dict[str, List[str]] = {
    "free": [],
    "sovereign": ["intelligence", "enforcement"],
    "connected": ["intelligence", "enforcement", "federation"],
    "enterprise": ["intelligence", "enforcement", "federation", "vertical-packs"],
}


def features_for_sku(sku: str) -> List[str]:
    """Default feature bundle for a SKU (empty list for an unknown SKU)."""
    return list(SKU_FEATURES.get((sku or "").strip().lower(), []))


def known_skus() -> List[str]:
    return sorted(SKU_FEATURES)
