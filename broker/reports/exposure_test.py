# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Exposure report (§8.1) — payload shape, ranking labels, deterministic fingerprint,
and that a real PDF renders. Metadata-only; no governance/audit content leaks in."""
import pytest

# reportlab is a prod dependency (apps/broker/pyproject.toml) but may be absent from a
# lightweight env — skip the whole module cleanly rather than error at collection.
pytest.importorskip("reportlab")

from broker.reports.exposure import (  # noqa: E402
    build_exposure_payload,
    build_and_render_exposure,
    render_exposure_pdf,
    _classify,
)
from broker.reports.inventory import fingerprint  # noqa: E402


def _coverage():
    return {
        "coverage_pct": 42.0,
        "counts": {
            "witnessed": 12, "governed": 5, "ungoverned": 7,
            "ungoverned_ai_services": 3, "ungoverned_suspicious": 2,
            "ungoverned_unknown": 1, "ungoverned_self": 0,
            "north_south": 4, "east_west": 2, "host_local": 1,
        },
        "ungoverned": [
            {"target_hostname": "db-1", "pattern_name": "OpenAI egress", "signal_type": "network",
             "plane": "north-south", "suspicious": False, "is_ai_service": True, "unclassified": False,
             "confidence": "high", "occurrence_count": 9, "remediation": "route via broker"},
            {"target_hostname": "web-2", "pattern_name": "Unknown outbound", "signal_type": "network",
             "plane": "north-south", "suspicious": True, "is_ai_service": False, "unclassified": False,
             "confidence": "medium", "occurrence_count": 3, "remediation": "block"},
        ],
    }


def test_classification_labels():
    assert _classify({"suspicious": True}) == "threat"
    assert _classify({"is_ai_service": True}) == "AI service"
    assert _classify({"unclassified": True}) == "unknown"
    assert _classify({}) == "other"


def test_payload_shape_and_no_governance_leak():
    p = build_exposure_payload(_coverage(), tenant_label="acme", generated_by="op-1")
    assert p["report_type"] == "exposure"
    assert p["coverage_pct"] == 42.0
    assert p["counts"]["ungoverned"] == 7
    assert len(p["ranked_exposure"]) == 2
    assert p["ranked_exposure"][0]["classification"] == "AI service"
    # the exposure report is a SEES artifact — it must not carry governance/audit fields.
    assert "audit_summary" not in p
    assert "findings" not in p  # renamed to ranked_exposure; no raw governance worklist ids


def test_fingerprint_is_deterministic():
    p1 = build_exposure_payload(_coverage(), "acme", "op-1")
    p2 = dict(p1)  # same body → same fingerprint
    assert fingerprint(p1) == fingerprint(p2)


def test_pdf_renders():
    pytest.importorskip("reportlab")
    pdf = build_and_render_exposure(_coverage(), tenant_label="acme", generated_by="op-1")
    assert pdf[:4] == b"%PDF"
    assert len(pdf) > 1000


def test_empty_exposure_renders():
    pytest.importorskip("reportlab")
    empty = {"coverage_pct": 100.0, "counts": {"witnessed": 0, "governed": 0, "ungoverned": 0}, "ungoverned": []}
    p = build_exposure_payload(empty, None, "op-1")
    assert p["ranked_exposure"] == []
    pdf = render_exposure_pdf(p, fingerprint(p))
    assert pdf[:4] == b"%PDF"
