# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Compliance-grade evidence (pillar 3) — control mapping + signed evidence reports.

Vertirite's answer to "you can't tell an auditor the AI *probably* caught it": a
deterministic, on-node record of the enforcement activity, mapped to the frameworks
regulated buyers are audited against (OWASP LLM Top-10, MITRE ATLAS, HIPAA, SOX,
NIST 800-82, IEC 62443) and sealed with a content hash. No tables of its own — it
reads the break/containment/audit surfaces the rest of the spine already records.

See docs/MESSAGING.md pillar 3.
"""
