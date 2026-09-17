# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Discovery sensor registry — catalog + derived partial-view status."""
import broker.discovery.sensors as sensors


def _patch(monkeypatch, findings):
    monkeypatch.setattr(sensors, "list_findings", lambda **kw: findings)


def test_catalog_covers_all_three_planes():
    planes = {p for t in sensors.SENSOR_TIERS for p in t["planes"]}
    assert planes == {"north-south", "east-west", "host-local"}
    # every tier declares the fields the onboarding UI + doc rely on
    for t in sensors.SENSOR_TIERS:
        for k in ("id", "title", "planes", "feed", "catches", "placement",
                  "method", "consent", "enforcement", "status"):
            assert t.get(k), f"{t['id']} missing {k}"


def test_laptop_only_is_partial_and_recommends_everything(monkeypatch):
    # Only host/process findings — the laptop keyhole.
    _patch(monkeypatch, [
        {"signal_type": "process", "evidence": {}},
    ])
    s = sensors.discovery_sources()
    assert s["partial_view"] is True
    # egress + flow both missing -> both recommended
    joined = " ".join(s["recommendations"]).lower()
    assert "egress proxy" in joined and "east-west" in joined
    assert s["planes_covered"]["east-west"] is False


def test_egress_plus_flow_is_not_partial(monkeypatch):
    _patch(monkeypatch, [
        {"signal_type": "network", "evidence": {"sensor": "egress", "plane": "north-south"}},
        {"signal_type": "network", "evidence": {"sensor": "flow", "plane": "east-west"}},
    ])
    s = sensors.discovery_sources()
    assert s["partial_view"] is False
    assert s["planes_covered"]["north-south"] and s["planes_covered"]["east-west"]
    active_ids = {t["id"] for t in s["tiers"] if t["active"]}
    assert "egress-proxy" in active_ids
    assert any(t["feed"] == "flow" and t["active"] for t in s["tiers"])
