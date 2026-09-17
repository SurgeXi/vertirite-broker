# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Remediation guidance — "show me how" BLOCK/ROUTE per plane."""
import broker.discovery.remediation as r


def test_north_south_block_and_route():
    g = r.guidance_for({
        "id": "f1", "target_hostname": "api.openai.com", "pattern_id": "net-openai-saas",
        "evidence": {"plane": "north-south"},
    })
    assert g["plane"] == "north-south"
    assert g["summary"]  # the pattern's remediation text
    # BLOCK is always available at the existing chokepoint
    targets = [s["target"] for s in g["block"]["snippets"]]
    assert any("DNS" in t for t in targets) and any("Squid" in t or "NGFW" in t for t in targets)
    # ROUTE applies and includes the OpenAI base_url repoint
    assert g["route"]["applicable"] is True
    assert any("base_url" in s["code"] or "OpenAI" in s["code"] for s in g["route"]["snippets"])
    # honest: route-through needs the Stage 2 forward-proxy
    assert "forward-proxy" in g["route"]["note"]


def test_east_west_block_is_segmentation_route_na():
    g = r.guidance_for({
        "id": "f2", "target_hostname": "10.20.3.9", "pattern_id": "net-ot-protocol",
        "evidence": {"plane": "east-west", "dst_port": 502},
    })
    assert g["plane"] == "east-west"
    # block uses switch/segmentation, NOT an inline box
    blob = " ".join(s["target"] + s["code"] for s in g["block"]["snippets"]).lower()
    assert "switch acl" in blob or "segment" in blob
    assert "wire" in g["block"]["note"].lower()
    # route does not apply to internal device traffic
    assert g["route"]["applicable"] is False


def test_host_local_block_is_on_host():
    g = r.guidance_for({
        "id": "f3", "target_hostname": "127.0.0.1", "pattern_id": "net-host-local-ipc",
        "evidence": {"plane": "host-local", "dst_port": 8000},
    })
    assert g["plane"] == "host-local"
    assert "8000" in " ".join(s["code"] for s in g["block"]["snippets"])
    assert g["route"]["applicable"] is False


def test_raw_ip_north_south_adds_iptables():
    g = r.guidance_for({
        "id": "f4", "target_hostname": "185.220.14.7",
        "pattern_id": "net-unrecognized-external-egress",
        "evidence": {"plane": "north-south"},
    })
    assert any("iptables" in s["target"].lower() for s in g["block"]["snippets"])


def test_summary_falls_back_when_no_pattern():
    s = r.remediation_summary({"pattern_id": None})
    assert "govern" in s.lower() or "review" in s.lower()
