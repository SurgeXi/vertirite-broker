# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Egress + DNS sensors -> network findings (docs/STRATEGY.md, CONTAINMENT.md)."""
import broker.discovery.network_sensor as ns


def test_match_known_ai_services():
    assert ns.match_host("api.openai.com") == "net-openai-saas"
    assert ns.match_host("https://api.anthropic.com/v1/x") == "net-anthropic-saas"
    assert ns.match_host("my-dep.openai.azure.com") == "net-azure-openai"


def test_external_unknown_is_generic():
    assert ns.match_host("api.some-random-saas.com") == "net-unrecognized-external-egress"


def test_internal_hosts_are_ignored():
    assert ns.match_host("internal-svc.local") is None
    assert ns.match_host("10.0.0.5") is None
    assert ns.match_host("10.0.0.37") is None       # CGNAT CGNAT = internal
    assert ns.match_host("localhost") is None


def test_parse_squid_log():
    log = (
        "1781474425.941 10.0.0.125 NONE_NONE/200 0 CONNECT api.openai.com:443 - -\n"
        "1781473641.759 10.0.0.125 TCP_MISS/200 921 GET http://example.com/ - text/html\n"
    )
    obs = ns.parse_squid_log(log)
    assert {"destination": "api.openai.com", "source": "10.0.0.125"} in obs
    assert {"destination": "example.com", "source": "10.0.0.125"} in obs


def test_parse_dns_log():
    log = "Jun 14 20:00:00 dnsmasq[123]: query[A] api.anthropic.com from 10.0.0.5"
    assert ns.parse_dns_log(log) == [{"domain": "api.anthropic.com", "source": "10.0.0.5"}]


def test_analyze_egress_reports_external_skips_internal(monkeypatch):
    calls = []
    def fake_report(**kw):
        calls.append(kw)
        return {"pattern_id": kw["pattern_id"]}
    monkeypatch.setattr(ns, "report_finding", fake_report)

    summary = ns.analyze_egress([
        {"destination": "api.openai.com", "source": "vm1"},        # AI
        {"destination": "api.some-saas.com", "source": "vm1"},     # external generic
        {"destination": "internal-db.local", "source": "vm1"},     # internal — skipped
    ], tenant_id="acme")

    assert summary == {"sensor": "egress", "reported": 2, "ai_services": 1}
    assert len(calls) == 2
    assert all(c["signal_type"] == "network" for c in calls)


def test_analyze_dns_tags_sensor(monkeypatch):
    seen = []
    monkeypatch.setattr(ns, "report_finding",
                        lambda **kw: seen.append(kw["evidence"]["sensor"]) or {"pattern_id": kw["pattern_id"]})
    ns.analyze_dns([{"domain": "api.anthropic.com", "source": "h1"}], tenant_id="acme")
    assert seen == ["dns"]


# --- east-west / flow sensor ------------------------------------------------

def test_classify_flow_planes():
    # external destination -> north-south, classified like egress
    assert ns._classify_flow("api.openai.com", 443, "vm1") == ("north-south", "net-openai-saas")
    assert ns._classify_flow("api.some-saas.com", 443, "vm1") == ("north-south", "net-unrecognized-external-egress")
    # internal destinations -> east-west, kept (NOT dropped), classified by port
    assert ns._classify_flow("10.0.0.9", 502, "plc-1") == ("east-west", "net-ot-protocol")
    assert ns._classify_flow("10.0.0.20", 11434, "app-1") == ("east-west", "net-internal-llm-port")
    assert ns._classify_flow("10.0.0.30", 5432, "app-1") == ("east-west", "net-internal-lateral")
    # same host / loopback -> host-local
    assert ns._classify_flow("127.0.0.1", 8000, "app-1") == ("host-local", "net-host-local-ipc")
    assert ns._classify_flow("app-1", 9000, "app-1") == ("host-local", "net-host-local-ipc")


def test_analyze_flow_keeps_internal_and_tags_plane(monkeypatch):
    calls = []
    monkeypatch.setattr(ns, "report_finding",
                        lambda **kw: calls.append(kw) or {"pattern_id": kw["pattern_id"]})
    summary = ns.analyze_flow([
        {"src": "plc-1", "dst": "10.0.0.9", "dst_port": 502},        # east-west OT
        {"src": "app-1", "dst": "10.0.0.20", "dst_port": 11434},     # east-west internal AI
        {"src": "vm1", "dst": "api.openai.com", "dst_port": 443},    # north-south
        {"src": "app-1", "dst": "127.0.0.1", "dst_port": 8000},      # host-local
    ], tenant_id="acme")
    # The internal flows the egress tier would have DROPPED are all kept here.
    assert summary == {"sensor": "flow", "reported": 4,
                       "by_plane": {"north-south": 1, "east-west": 2, "host-local": 1}}
    planes = [c["evidence"]["plane"] for c in calls]
    assert planes.count("east-west") == 2
    assert all(c["evidence"]["sensor"] == "flow" for c in calls)


def test_parse_zeek_conn():
    log = (
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        "1622000000\tC1\t10.0.0.5\t51920\t10.0.0.9\t502\ttcp\n"
        "1622000001\tC2\t10.0.0.5\t51921\t10.0.0.20\t11434\ttcp\n"
    )
    flows = ns.parse_zeek_conn(log)
    assert {"src": "10.0.0.5", "dst": "10.0.0.9", "dst_port": "502", "proto": "tcp"} in flows
    assert any(f["dst"] == "10.0.0.20" and f["dst_port"] == "11434" for f in flows)
