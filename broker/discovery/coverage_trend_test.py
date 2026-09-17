# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Coverage-over-time (Wave A #2). Pure snapshot-mapping logic, no DB."""
from datetime import datetime, timezone
import broker.discovery.coverage_trend as CT


def _cov(pct=27.8, gov=5, ung=13, ai=1, susp=6, wit=18):
    return {"coverage_pct": pct, "counts": {"witnessed": wit, "governed": gov,
            "ungoverned": ung, "ungoverned_ai_services": ai, "ungoverned_suspicious": susp}}


def test_build_snapshot_maps_all_counts():
    r = CT.build_snapshot_record(_cov(), "t1", datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc))
    assert r["tenant_id"] == "t1"
    assert r["coverage_pct"] == 27.8
    assert r["governed"] == 5 and r["ungoverned"] == 13
    assert r["ungoverned_ai"] == 1 and r["ungoverned_suspicious"] == 6
    assert r["witnessed"] == 18
    assert r["captured_at"].year == 2026 and r["id"]


def test_build_snapshot_empty_coverage_is_zero():
    r = CT.build_snapshot_record({}, "t2")
    assert r["coverage_pct"] == 0.0 and r["governed"] == 0 and r["witnessed"] == 0
    assert r["ungoverned_ai"] == 0 and r["tenant_id"] == "t2"


def test_build_snapshot_defaults_captured_at_now():
    r = CT.build_snapshot_record(_cov(), "t3")
    assert r["captured_at"] is not None and r["captured_at"].tzinfo is not None


def test_build_snapshot_ids_unique():
    a = CT.build_snapshot_record(_cov(), "t")
    b = CT.build_snapshot_record(_cov(), "t")
    assert a["id"] != b["id"]
