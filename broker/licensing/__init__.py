# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""License-token layer — the commercial keystone (docs/PROTECTION-MODEL.md §3,
the "human floor").

A signed entitlement (SKU + features + expiry) gates the PREMIUM features/tier —
NOT broker startup (the broker is BSL-open by design). No license → free/baseline
tier (open discovery still works); a valid license unlocks its SKU's features;
expiry degrades back to free, like catalog rot. Ed25519-signed by SurgeXi's
license key; the broker only verifies.
"""
from . import store  # noqa: F401 — registers the ORM table for init_db()
