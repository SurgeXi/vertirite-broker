# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Governance risk-classification enums.

Extracted from surge_capabilities so containment (the chokepoint-based stop
button) and the rest of the governance surface depend only on these plain
types — not on any capability registry or executor.
"""
import enum


class ApprovalClass(str, enum.Enum):
    SAFE = "safe"                  # read-only, auto-approved
    SCOPED = "scoped"              # writes within a tenant; auto-approved if scope checks pass
    GATED = "gated"                # operator approval required (ntfy + dashboard)
    HIGH_STAKES = "high_stakes"    # operator approval AND disagreement-AI review


class AuditClass(str, enum.Enum):
    QUIET = "quiet"
    NORMAL = "normal"
    LOUD = "loud"
