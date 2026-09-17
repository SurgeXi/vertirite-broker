# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""MSP federation (Wave B #8) — fleet-view aggregation core.

Lets an MSP see many customer edges from one NOC — but METADATA-ONLY and
OPT-IN: each edge reports coverage % + finding COUNTS, never customer data (no
hostnames, no findings, no PII). This is the pure aggregation core: edge reports
in -> a fleet summary out, edges ranked most-exposed first. The transport
(edge->NOC beacon, opt-in enrolment, auth) is a separate slice; this is the
judgment, and it's testable. Consistent with the no-multi-tenant-honeypot rule.
"""
from __future__ import annotations

from typing import Any, Dict, List


def build_fleet_view(edge_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """edge_reports: [{edge_id, tenant_label?, coverage_pct, ungoverned,
    ungoverned_suspicious, last_seen?}] — metadata only. Returns the MSP NOC
    summary with edges ranked most-exposed first (most threats, then lowest
    coverage)."""
    edges: List[Dict[str, Any]] = []
    for e in edge_reports or []:
        eid = e.get("edge_id")
        if not eid:
            continue
        edges.append({
            "edge_id": eid,
            "tenant_label": e.get("tenant_label") or eid,
            "coverage_pct": float(e.get("coverage_pct") or 0.0),
            "ungoverned": int(e.get("ungoverned") or 0),
            "ungoverned_suspicious": int(e.get("ungoverned_suspicious") or 0),
            "last_seen": e.get("last_seen"),
        })
    n = len(edges)
    ranked = sorted(edges, key=lambda x: (-x["ungoverned_suspicious"], x["coverage_pct"], x["edge_id"]))
    return {
        "type": "vertirite.fleet.view",
        "edge_count": n,
        "fleet_coverage_avg": round(sum(x["coverage_pct"] for x in edges) / n, 1) if n else 0.0,
        "total_ungoverned": sum(x["ungoverned"] for x in edges),
        "total_suspicious": sum(x["ungoverned_suspicious"] for x in edges),
        "edges_by_exposure": ranked,
    }


_ALLOWED_EDGE_KEYS = ("edge_id", "tenant_label", "coverage_pct", "ungoverned",
                      "ungoverned_suspicious", "last_seen")


def record_edge_report(store, report):
    """Store one edge's metadata report (keyed by edge_id). METADATA-ONLY guard:
    keeps only the allowed keys so a misbehaving/compromised edge can never push
    customer data (hostnames, findings, PII) into the NOC."""
    eid = (report or {}).get("edge_id")
    if not eid:
        return store
    store[eid] = {k: (report or {}).get(k) for k in _ALLOWED_EDGE_KEYS}
    return store


def fleet_view_from_store(store):
    return build_fleet_view(list((store or {}).values()))
