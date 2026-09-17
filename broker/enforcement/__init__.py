# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Stage 2 enforcement — turning discovery findings into applied governance.

Two primitives, per docs/GOVERNANCE-ENFORCEMENT.md:
  * ROUTE  — send a call THROUGH the broker so it is policy-gated + audited
             (``proxy.py``, the OpenAI-compatible forward-proxy).
  * BLOCK  — deny a call at the customer's own in-path device via that device's
             API (``connectors.py``; advisory/dry-run by default).

The decision that drives both lives in ``policy.py``. Vertirite is the brain,
not an inline all-traffic chokepoint — enforcement is opt-in and selective.
"""
