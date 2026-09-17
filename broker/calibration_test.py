# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Calibrating gate (Wave B #7) — suggest-only. Pure logic, no DB, never acts."""
import broker.calibration as C


def _hist(pattern, approvals, denials):
    return ([{"pattern": pattern, "decision": "approve"}] * approvals +
            [{"pattern": pattern, "decision": "deny"}] * denials)


def test_clean_high_volume_is_suggested():
    s = C.build_promotion_suggestions(_hist("read-invoice", 12, 0))
    assert len(s) == 1 and s[0]["suggest_auto_promote"] is True
    assert s[0]["approvals"] == 12 and s[0]["denials"] == 0 and s[0]["approve_rate"] == 1.0


def test_any_denial_disqualifies():
    s = C.build_promotion_suggestions(_hist("wire-transfer", 50, 1))
    assert s[0]["suggest_auto_promote"] is False and "denials" in s[0]["note"]


def test_below_min_volume_not_suggested():
    s = C.build_promotion_suggestions(_hist("rare-op", 5, 0))
    assert s[0]["suggest_auto_promote"] is False and "Needs >=" in s[0]["note"]


def test_capability_key_alias():
    s = C.build_promotion_suggestions([{"capability": "x", "decision": "approve"}] * 11)
    assert s[0]["pattern"] == "x" and s[0]["suggest_auto_promote"] is True


def test_empty_history():
    assert C.build_promotion_suggestions([]) == []
    assert C.build_promotion_suggestions(None) == []


def test_never_acts_output_is_advisory_only():
    # the ONLY output is a suggestion flag + counts — no side effect, no auto-approve
    s = C.build_promotion_suggestions(_hist("p", 20, 0))
    assert set(s[0].keys()) == {"pattern", "approvals", "denials", "approve_rate",
                                "suggest_auto_promote", "note"}


def test_custom_thresholds():
    s = C.build_promotion_suggestions(_hist("p", 3, 0), min_approvals=3)
    assert s[0]["suggest_auto_promote"] is True


def test_multiple_patterns_sorted():
    h = _hist("bbb", 11, 0) + _hist("aaa", 11, 0)
    s = C.build_promotion_suggestions(h)
    assert [x["pattern"] for x in s] == ["aaa", "bbb"]


def test_promote_suggested_pattern():
    sug = {"suggest_auto_promote": True}
    r = C.build_promotion("read-invoice", "operator@acme", sug)
    assert r["promoted"] is True and r["promoted_by"] == "operator@acme" and r["active"] is True


def test_refuse_promote_unsuggested():
    r = C.build_promotion("wire-transfer", "op", {"suggest_auto_promote": False})
    assert r["promoted"] is False and "not suggested" in r["reason"]


def test_refuse_promote_without_operator():
    r = C.build_promotion("p", "", {"suggest_auto_promote": True})
    assert r["promoted"] is False and "opt-in" in r["reason"]
