# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""The edge beacon: metadata-only payload, gated, sent with the ingest token."""
import os
import tempfile

_db_fd, _db_path = tempfile.mkstemp(suffix="-beacon.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

import broker.protection.beacon as beacon  # noqa: E402
import broker.protection.identity as identity  # noqa: E402
import broker.protection.fingerprint as fingerprint  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(bind=engine)


_schema()


class _FakeResp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body or {"accepted": True, "signals": []}

    def json(self):
        return self._body


class _FakeClient:
    last: dict = {}
    status = 200
    raise_exc = None

    def __init__(self, timeout=None):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def post(self, url, json=None, headers=None):
        if _FakeClient.raise_exc:
            raise _FakeClient.raise_exc
        _FakeClient.last = {"url": url, "json": json, "headers": headers or {}}
        return _FakeResp(_FakeClient.status)


def _setup(monkeypatch, **over):
    _FakeClient.last = {}; _FakeClient.status = 200; _FakeClient.raise_exc = None
    monkeypatch.setattr(beacon.settings, "protection_beacon_url", "https://ingress.example/v1/fleet/beacon")
    monkeypatch.setattr(beacon.settings, "protection_beacon_token", "ing-token")
    monkeypatch.setattr(beacon.settings, "protection_suppression_threshold", 3)
    monkeypatch.setattr(beacon.settings, "intelligence_feed_enabled", True)
    monkeypatch.setattr(beacon.settings, "intelligence_feed_url", "https://feed.example/c")
    monkeypatch.setattr(beacon.settings, "intelligence_feed_timeout_s", 5.0)
    for k, v in over.items():
        monkeypatch.setattr(beacon.settings, k, v)
    identity.reset_cache(); identity.get_instance(); fingerprint.reset_cache()
    monkeypatch.setattr(beacon.httpx, "Client", _FakeClient)


def test_beacon_is_metadata_only_and_sent_with_token(monkeypatch):
    _setup(monkeypatch)
    r = beacon.send_beacon("default")
    assert r["status"] == "sent"
    sent = _FakeClient.last["json"]
    # exactly the closed field set — no findings/traffic/host contents leaked
    assert set(sent.keys()) == set(beacon.BEACON_FIELDS)
    assert _FakeClient.last["headers"].get("X-Ingest-Token") == "ing-token"
    assert _FakeClient.last["url"].endswith("/v1/fleet/beacon")
    assert sent["tier"] == "connected"
    assert sent["instance_id"] and sent["canary"] and sent["fingerprint"]


def test_no_url_is_disabled(monkeypatch):
    _setup(monkeypatch, protection_beacon_url="")
    assert beacon.send_beacon("default")["status"] == "disabled"
    assert _FakeClient.last == {}  # nothing sent


def test_sovereign_tier_when_no_feed(monkeypatch):
    _setup(monkeypatch, intelligence_feed_enabled=False)
    beacon.send_beacon("default")
    assert _FakeClient.last["json"]["tier"] == "sovereign"


def test_unreachable_degrades_gracefully(monkeypatch):
    _setup(monkeypatch)
    _FakeClient.raise_exc = ConnectionError("blocked")
    assert beacon.send_beacon("default")["status"] == "unreachable"


def test_suppressed_state_carried(monkeypatch):
    _setup(monkeypatch)
    import broker.protection.store as store
    store.record_failure(); store.record_failure(); store.record_failure()  # >= threshold
    beacon.send_beacon("default")
    assert _FakeClient.last["json"]["suppressed"] is True


def test_federation_off_sends_no_telemetry(monkeypatch):
    _setup(monkeypatch)
    monkeypatch.setattr(beacon.settings, "protection_federation_enabled", False)
    beacon.send_beacon("default")
    assert "telemetry" not in _FakeClient.last["json"]


def test_federation_on_adds_metadata_only_counts(monkeypatch):
    _setup(monkeypatch)
    monkeypatch.setattr(beacon.settings, "protection_federation_enabled", True)
    beacon.send_beacon("default")
    tel = _FakeClient.last["json"].get("telemetry")
    assert tel is not None
    # exactly the closed COUNT set — no hostnames / findings content leaked
    assert set(tel.keys()) == set(beacon.TELEMETRY_FIELDS)
    assert all(isinstance(v, (int, float)) for v in tel.values())
