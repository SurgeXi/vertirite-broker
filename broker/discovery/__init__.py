# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Vertirite discovery — Pillar B.

Lightweight, local-only telemetry from the fleet agent that surfaces AI-shaped
activity Vertirite did not previously know about. Each finding is a
"witnessed but unsanctioned" observation: a process / network connection /
container / log entry that matches a known AI pattern but does NOT route
through the broker.

Architectural contract:
- Discovery runs ONLY on already-governed hosts (no separate scanner host)
- Discovery sees ONLY local-to-host state (no network sniffing)
- Findings carry METADATA, never customer payload (no data exfil)
- Findings are caller-attested via the same mTLS that governs other agent
  calls; the broker trusts the source host's signature
- Each finding is opt-in remediation, never auto-action; the operator
  decides whether to bring a witnessed pattern under governance

See docs/DISCOVERY-DESIGN.md for the full pattern catalog and signal
provenance rules.
"""
from .findings import WitnessedFindingTable  # noqa: F401 — register table on import
from .patterns import PATTERN_LIBRARY, lookup_pattern, list_patterns  # noqa: F401
from .coverage import coverage_map  # noqa: F401 — SEEN − GOVERNED roll-up
