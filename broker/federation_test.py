# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""MSP federation (Wave B #8). Pure aggregation of metadata-only edge reports."""
import broker.federation as F


def _edges():
    return [
        {"edge_id": "e1", "tenant_label": "Acme Health", "coverage_pct": 80.0, "ungoverned": 4, "ungoverned_suspicious": 1},
        {"edge_id": "e2", "tenant_label": "Acme Finance", "coverage_pct": 20.0, "ungoverned": 16, "ungoverned_suspicious": 6},
        {"edge_id": "e3", "tenant_label": "SurgeXi", "coverage_pct": 50.0, "ungoverned": 8, "ungoverned_suspicious": 0},
    ]


def test_fleet_aggregates():
    v = F.build_fleet_view(_edges())
    assert v["edge_count"] == 3
    assert v["fleet_coverage_avg"] == 50.0
    assert v["total_ungoverned"] == 28 and v["total_suspicious"] == 7


def test_ranked_most_exposed_first():
    v = F.build_fleet_view(_edges())
    # e2 (6 threats) first, then e1 (1 threat), then e3 (0 threats)
    assert [e["edge_id"] for e in v["edges_by_exposure"]] == ["e2", "e1", "e3"]


def test_tie_break_lowest_coverage_first():
    edges = [{"edge_id": "a", "coverage_pct": 90.0, "ungoverned_suspicious": 0},
             {"edge_id": "b", "coverage_pct": 30.0, "ungoverned_suspicious": 0}]
    v = F.build_fleet_view(edges)
    assert [e["edge_id"] for e in v["edges_by_exposure"]] == ["b", "a"]


def test_empty_fleet():
    v = F.build_fleet_view([])
    assert v["edge_count"] == 0 and v["fleet_coverage_avg"] == 0.0 and v["edges_by_exposure"] == []


def test_skips_edges_without_id():
    v = F.build_fleet_view([{"coverage_pct": 10.0}, {"edge_id": "x", "coverage_pct": 10.0}])
    assert v["edge_count"] == 1


def test_metadata_only_no_customer_data():
    v = F.build_fleet_view(_edges())
    keys = set(v["edges_by_exposure"][0].keys())
    # counts + coverage + labels only — never findings/hostnames/PII
    assert keys == {"edge_id", "tenant_label", "coverage_pct", "ungoverned", "ungoverned_suspicious", "last_seen"}


def test_record_strips_customer_data():
    store = {}
    F.record_edge_report(store, {"edge_id": "e1", "coverage_pct": 50.0,
                                 "hostname": "patient-db.acme.com", "finding": "secret"})
    assert set(store["e1"].keys()) == set(F._ALLOWED_EDGE_KEYS)
    assert "hostname" not in store["e1"] and "finding" not in store["e1"]


def test_record_skips_no_id():
    store = {}
    F.record_edge_report(store, {"coverage_pct": 10.0})
    assert store == {}


def test_fleet_view_from_store():
    store = {}
    F.record_edge_report(store, {"edge_id": "e1", "coverage_pct": 20.0, "ungoverned_suspicious": 6})
    F.record_edge_report(store, {"edge_id": "e2", "coverage_pct": 80.0, "ungoverned_suspicious": 0})
    v = F.fleet_view_from_store(store)
    assert v["edge_count"] == 2 and v["edges_by_exposure"][0]["edge_id"] == "e1"
