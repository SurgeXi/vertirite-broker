# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Compliance-pack (Wave A #3). Pure assembly + control maps + fingerprint, no DB."""
from datetime import datetime, timezone
import pytest
import broker.reports.compliance as C


def _cov():
    return {"coverage_pct": 27.8, "counts": {"witnessed": 18, "governed": 5,
            "ungoverned": 13, "ungoverned_ai_services": 1, "ungoverned_suspicious": 6}}


def _events():
    return [{"created_at": "2026-09-01T10:00:00Z", "action": "govern"},
            {"created_at": "2026-09-11T12:00:00Z", "action": "block"}]


def test_soc2_pack_structure():
    p = C.build_compliance_payload("t1", "soc2", _cov(), _events(),
                                   datetime(2026, 9, 11, tzinfo=timezone.utc))
    assert p["framework"] == "soc2" and p["tenant_id"] == "t1"
    assert p["control_count"] == 6
    assert any(c["control_id"] == "CC6.1" for c in p["controls"])
    assert all(c["status"] == "evidenced" for c in p["controls"])
    assert p["coverage_summary"]["ungoverned_suspicious"] == 6
    assert p["audit_summary"]["event_count"] == 2
    assert p["audit_summary"]["period_first"] == "2026-09-01T10:00:00Z"
    assert p["audit_summary"]["period_last"] == "2026-09-11T12:00:00Z"
    assert p["fingerprint"] and len(p["fingerprint"]) == 64


def test_hipaa_pack_has_hipaa_controls():
    p = C.build_compliance_payload("t", "hipaa", _cov(), _events())
    ids = {c["control_id"] for c in p["controls"]}
    assert "164.312(b)" in ids and "164.308(a)(6)" in ids


def test_case_insensitive_framework():
    assert C.build_compliance_payload("t", "SOC2", _cov(), [])["framework"] == "soc2"


def test_unknown_framework_raises():
    with pytest.raises(ValueError):
        C.build_compliance_payload("t", "pci", _cov(), [])


def test_fingerprint_deterministic():
    at = datetime(2026, 9, 11, tzinfo=timezone.utc)
    a = C.build_compliance_payload("t", "soc2", _cov(), _events(), at)
    b = C.build_compliance_payload("t", "soc2", _cov(), _events(), at)
    assert a["fingerprint"] == b["fingerprint"]


def test_empty_audit_ok():
    p = C.build_compliance_payload("t", "soc2", _cov(), [])
    assert p["audit_summary"]["event_count"] == 0 and p["audit_summary"]["period_first"] is None
