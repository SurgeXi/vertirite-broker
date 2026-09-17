# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""The narc: sustained feed suppression raises a self-egress-suppressed finding.

Unique tenant per test (so report_finding's dedup doesn't bleed across tests);
the shared singleton failure counter is reset in _setup.
"""
import os
import tempfile
import uuid

_db_fd, _db_path = tempfile.mkstemp(suffix="-protection-sw.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

import broker.protection.selfwitness as sw  # noqa: E402
import broker.protection.identity as identity  # noqa: E402
import broker.protection.store as store  # noqa: E402
import broker.discovery.findings as findings  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(bind=engine)


_schema()

FEED = "https://feed.vertirite.example/catalog"


def _self_findings(tenant):
    return [f for f in findings.list_findings(tenant_id=tenant)
            if f["pattern_id"] == "self-egress-suppressed"]


def _setup(monkeypatch):
    monkeypatch.setattr(sw.settings, "protection_enabled", True)
    monkeypatch.setattr(sw.settings, "protection_suppression_threshold", 3)
    identity.reset_cache()
    identity.get_instance()
    store.record_success()  # zero the shared failure counter
    return "t-" + uuid.uuid4().hex[:8]


def test_sustained_unreachable_raises_self_finding(monkeypatch):
    t = _setup(monkeypatch)
    # below threshold → nothing
    sw.on_feed_result("unreachable", tenant_id=t, feed_url=FEED)
    sw.on_feed_result("unreachable", tenant_id=t, feed_url=FEED)
    assert _self_findings(t) == []
    # third consecutive → the narc fires
    sw.on_feed_result("unreachable", tenant_id=t, feed_url=FEED)
    fs = _self_findings(t)
    assert len(fs) == 1
    assert fs[0]["target_hostname"] == "feed.vertirite.example"
    assert fs[0]["confidence"] == "high"


def test_reachable_resets_the_counter(monkeypatch):
    t = _setup(monkeypatch)
    sw.on_feed_result("unreachable", tenant_id=t, feed_url=FEED)
    sw.on_feed_result("unreachable", tenant_id=t, feed_url=FEED)
    sw.on_feed_result("up_to_date", tenant_id=t, feed_url=FEED)  # HTTP response = egress works
    assert identity.beacon_state(3)["consecutive_failures"] == 0


def test_http_error_counts_as_reachable(monkeypatch):
    t = _setup(monkeypatch)
    # an HTTP error means we REACHED the server → not suppression
    for _ in range(5):
        sw.on_feed_result("feed_error", tenant_id=t, feed_url=FEED)
    assert _self_findings(t) == []
    assert identity.beacon_state(3)["consecutive_failures"] == 0


def test_disabled_status_never_narcs(monkeypatch):
    t = _setup(monkeypatch)
    for _ in range(5):
        sw.on_feed_result("disabled", tenant_id=t)
    assert _self_findings(t) == []


def test_protection_disabled_never_narcs(monkeypatch):
    t = _setup(monkeypatch)
    monkeypatch.setattr(sw.settings, "protection_enabled", False)
    for _ in range(5):
        sw.on_feed_result("unreachable", tenant_id=t, feed_url=FEED)
    assert _self_findings(t) == []


def test_realert_is_throttled_within_window(monkeypatch):
    t = _setup(monkeypatch)
    alerts = []
    monkeypatch.setattr(sw, "_alert", lambda *a, **k: alerts.append(a))
    # 6 consecutive unreachable pulls: threshold crossed at #3; #4-#6 are the
    # SAME episode and must not re-fire the critical alert every pull.
    for _ in range(6):
        sw.on_feed_result("unreachable", tenant_id=t, feed_url=FEED)
    assert len(_self_findings(t)) == 1
    assert len(alerts) == 1


def test_recovery_clears_throttle_so_new_episode_realerts(monkeypatch):
    t = _setup(monkeypatch)
    alerts = []
    monkeypatch.setattr(sw, "_alert", lambda *a, **k: alerts.append(a))
    for _ in range(4):
        sw.on_feed_result("unreachable", tenant_id=t, feed_url=FEED)
    assert len(alerts) == 1
    sw.on_feed_result("up_to_date", tenant_id=t, feed_url=FEED)  # recovery closes the episode
    for _ in range(3):
        sw.on_feed_result("unreachable", tenant_id=t, feed_url=FEED)
    assert len(alerts) == 2  # a NEW suppression episode alerts immediately


def test_self_finding_ranks_as_threat_in_coverage(monkeypatch):
    import broker.discovery.coverage as cov
    t = _setup(monkeypatch)
    for _ in range(3):
        sw.on_feed_result("unreachable", tenant_id=t, feed_url=FEED)
    cmap = cov.coverage_map(tenant_id=t)
    assert cmap["counts"]["ungoverned_self"] == 1
    top = cmap["ungoverned"][0]
    assert top["pattern_id"] == "self-egress-suppressed"
    assert top["is_self"] is True and top["suspicious"] is True
