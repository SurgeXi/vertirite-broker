# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Closed-loop enforcement verification (Wave B #5). Pure verdict logic +
pluggable prober — no live device."""
import broker.enforcement.verify as V


class _AR:  # ApplyResult-like
    def __init__(self, applied, connector="dns-rpz"):
        self.applied = applied
        self.connector = connector


class _Prober:
    def __init__(self, state):
        self.state = state

    def probe(self, target, plane):
        return self.state


def test_advisory_not_enforced():
    r = V.build_verification_record(_AR(False), "unknown", "minexmr.com", "north-south")
    assert r["applied"] is False and r["verified"] is None and "advisory" in r["verdict"]


def test_applied_and_closed_is_verified():
    r = V.build_verification_record(_AR(True), "closed", "minexmr.com", "north-south")
    assert r["applied"] and r["verified"] is True and "verified closed" in r["verdict"]


def test_applied_but_open_is_failure():
    r = V.build_verification_record(_AR(True), "open", "minexmr.com", "north-south")
    assert r["verified"] is False and "STILL OPEN" in r["verdict"]


def test_applied_unknown_is_unavailable():
    r = V.build_verification_record(_AR(True), "unknown", "x", "north-south")
    assert r["verified"] is None and "unavailable" in r["verdict"]


def test_default_prober_is_no_op():
    # brain-not-the-wire: no prober configured -> no traffic -> unknown
    r = V.verify_block("minexmr.com", "north-south", _AR(True))
    assert r["probe"] == "unknown" and r["verified"] is None


def test_verify_block_with_mock_prober():
    r = V.verify_block("minexmr.com", "north-south", _AR(True), prober=_Prober("closed"))
    assert r["verified"] is True and r["verdict"].startswith("verified closed")


def test_invalid_probe_state_coerced():
    r = V.build_verification_record(_AR(True), "garbage", "x", "north-south")
    assert r["probe"] == "unknown"


def test_dict_apply_result():
    r = V.build_verification_record({"applied": True, "connector": "webhook"}, "closed", "x", "north-south")
    assert r["connector"] == "webhook" and r["verified"] is True


def test_prober_error_degrades_to_unknown():
    class _Boom:
        def probe(self, t, p):
            raise RuntimeError("device unreachable")
    r = V.verify_block("x", "north-south", _AR(True), prober=_Boom())
    assert r["probe"] == "unknown" and r["verified"] is None


def test_dns_prober_closed_on_nxdomain():
    def _boom(host):
        raise OSError("NXDOMAIN")
    assert V.DnsProber(resolver=_boom).probe("minexmr.com", "north-south") == "closed"


def test_dns_prober_open_when_resolves():
    assert V.DnsProber(resolver=lambda h: [("x",)]).probe("api.openai.com", "north-south") == "open"


def test_get_prober_default_is_advisory():
    class _S: enforcement_verify_enabled = False
    assert isinstance(V.get_prober(_S()), V.AdvisoryProber)


def test_get_prober_dns_when_enabled():
    class _S: enforcement_verify_enabled = True
    assert isinstance(V.get_prober(_S()), V.DnsProber)
