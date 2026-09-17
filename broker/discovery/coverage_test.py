# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Coverage Map = SEEN − GOVERNED, AI-services-first (docs/STRATEGY.md).

Unit-tests the strategic roll-up over witnessed findings without touching the
DB by patching list_findings with canned rows.
"""
import broker.discovery.coverage as cov


def _patch(monkeypatch, governed, ungoverned):
    def fake_list(tenant_id=None, status_filter=None, limit=200):
        if status_filter == ["governed"]:
            return list(governed)
        return list(ungoverned)
    monkeypatch.setattr(cov, "list_findings", fake_list)


def test_coverage_ratio_and_ai_first_ranking(monkeypatch):
    governed = [
        {"status": "governed", "target_hostname": "api.openai.com",
         "pattern_name": "openai-egress", "confidence": "high", "occurrence_count": 5},
    ]
    ungoverned = [
        {"status": "new", "target_hostname": "cron.internal",
         "pattern_name": "scheduled-automation", "confidence": "low", "occurrence_count": 2},
        {"status": "acknowledged", "target_hostname": "api.anthropic.com",
         "pattern_name": "anthropic-api", "confidence": "high", "occurrence_count": 9},
    ]
    _patch(monkeypatch, governed, ungoverned)

    cm = cov.coverage_map()
    assert cm["counts"] == {
        "witnessed": 3, "governed": 1, "ungoverned": 2,
        "ungoverned_ai_services": 1, "ungoverned_suspicious": 0,
        "ungoverned_unknown": 0, "ungoverned_self": 0,
        "north_south": 2, "east_west": 0, "host_local": 0,
    }
    assert cm["coverage_pct"] == 33.3
    # The AI service surfaces FIRST in the ungoverned worklist (highest signal),
    # even though the generic automation was listed first in the raw data.
    assert cm["ungoverned"][0]["target_hostname"] == "api.anthropic.com"


def test_no_findings_is_full_coverage(monkeypatch):
    _patch(monkeypatch, [], [])
    cm = cov.coverage_map()
    assert cm["coverage_pct"] == 100.0
    assert cm["counts"]["witnessed"] == 0


def test_ai_marker_detection():
    assert cov._looks_like_ai_service({"target_hostname": "my.openai.azure-openai.net"})
    assert cov._looks_like_ai_service({"pattern_name": "anthropic-claude-call"})
    assert not cov._looks_like_ai_service({"target_hostname": "payroll.corp.local",
                                           "pattern_name": "scheduled-job"})


def test_suspicious_ranks_above_ai_and_is_flagged(monkeypatch):
    ungoverned = [
        {"status": "new", "target_hostname": "api.openai.com",
         "pattern_name": "OpenAI", "confidence": "high", "occurrence_count": 1},
        {"status": "new", "target_hostname": "pool.minexmr.com",
         "pattern_name": "Crypto-mining pool", "confidence": "high", "occurrence_count": 1},
    ]
    _patch(monkeypatch, [], ungoverned)
    cm = cov.coverage_map()
    assert cm["counts"]["ungoverned_suspicious"] == 1
    # Threat ranks ABOVE the sanctioned AI service.
    assert cm["ungoverned"][0]["target_hostname"] == "pool.minexmr.com"
    assert cm["ungoverned"][0]["suspicious"] is True


def test_ec2_is_not_a_threat():
    # Regression: bare "c2" marker false-positived on "ec2.amazonaws.com".
    assert not cov._looks_suspicious({"target_hostname": "ec2.amazonaws.com",
                                      "pattern_name": "unrecognized"})
    # ...but a real C2 relay still trips the (hyphenated) marker.
    assert cov._looks_suspicious({"target_hostname": "c2-relay.serveo.net",
                                  "pattern_name": "unrecognized"})


def test_unknown_shape_detection():
    # Raw IP, non-web port, and disposable TLD all read as "unknown — investigate".
    assert cov._looks_unknown({"target_hostname": "185.220.14.7"})
    assert cov._looks_unknown({"target_hostname": "45.83.220.19:8443"})
    assert cov._looks_unknown({"target_hostname": "kx9f-update.win"})
    # Ordinary internet is NOT unknown — it baselines/dismisses, it doesn't review.
    assert not cov._looks_unknown({"target_hostname": "www.bing.com"})
    assert not cov._looks_unknown({"target_hostname": "api.openai.com"})
    assert not cov._looks_unknown({"target_hostname": "drive.google.com:443"})


def test_unknown_ranks_above_baseline_below_threat_and_ai(monkeypatch):
    ungoverned = [
        {"status": "new", "target_hostname": "www.bing.com",
         "pattern_id": "net-unrecognized-external-egress",
         "pattern_name": "unrecognized", "confidence": "low", "occurrence_count": 9},
        {"status": "new", "target_hostname": "185.220.14.7:8443",
         "pattern_id": "net-unrecognized-external-egress",
         "pattern_name": "unrecognized", "confidence": "low", "occurrence_count": 1},
        {"status": "new", "target_hostname": "api.openai.com",
         "pattern_id": "net-openai-saas",
         "pattern_name": "OpenAI", "confidence": "high", "occurrence_count": 1},
        {"status": "new", "target_hostname": "pool.minexmr.com",
         "pattern_id": "net-crypto-mining-pool",
         "pattern_name": "Crypto-mining pool", "confidence": "high", "occurrence_count": 1},
    ]
    _patch(monkeypatch, [], ungoverned)
    cm = cov.coverage_map()
    assert cm["counts"]["ungoverned_unknown"] == 1
    order = [f["target_hostname"] for f in cm["ungoverned"]]
    # threat > ai > unknown > baseline internet
    assert order == ["pool.minexmr.com", "api.openai.com", "185.220.14.7:8443", "www.bing.com"]
    unknown = next(f for f in cm["ungoverned"] if f["target_hostname"] == "185.220.14.7:8443")
    assert unknown["unclassified"] is True
    assert unknown["suspicious"] is False and unknown["is_ai_service"] is False


def test_recognized_internal_flow_is_not_unknown(monkeypatch):
    # A named internal pattern (OT/internal-LLM) on a bare IP must NOT fall into
    # the unknown tier just because internal traffic is all raw IPs. It surfaces
    # via the east-west plane instead.
    ungoverned = [
        {"status": "new", "target_hostname": "10.20.3.9", "pattern_id": "net-ot-protocol",
         "pattern_name": "Industrial control protocol (east-west)", "confidence": "medium",
         "evidence": {"plane": "east-west", "dst_port": 502}, "occurrence_count": 3},
        {"status": "new", "target_hostname": "10.10.1.7", "pattern_id": "net-internal-llm-port",
         "pattern_name": "Internal AI inference endpoint (east-west)", "confidence": "high",
         "evidence": {"plane": "east-west", "dst_port": 11434}, "occurrence_count": 2},
    ]
    _patch(monkeypatch, [], ungoverned)
    cm = cov.coverage_map()
    assert cm["counts"]["ungoverned_unknown"] == 0
    assert cm["counts"]["east_west"] == 2
    ot = next(f for f in cm["ungoverned"] if f["pattern_id"] == "net-ot-protocol")
    assert ot["unclassified"] is False and ot["plane"] == "east-west"
    llm = next(f for f in cm["ungoverned"] if f["pattern_id"] == "net-internal-llm-port")
    assert llm["is_ai_service"] is True and llm["plane"] == "east-west"
