# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Connected-tier auto-pull: install newer, no-op up-to-date, degrade gracefully.

The feed HTTP client is mocked; install goes through the real verify + store.
"""
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

_db_fd, _db_path = tempfile.mkstemp(suffix="-intel-feed.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

import broker.intelligence.signing as signing  # noqa: E402
import broker.intelligence.catalog as catalog  # noqa: E402
import broker.intelligence.store as store  # noqa: E402
import broker.intelligence.mint as mintlib  # noqa: E402
import broker.intelligence.feed as feed  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(bind=engine)


_schema()


class _FakeResp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


class _FakeClient:
    """Patched in place of httpx.Client; returns a preset response or raises."""
    status = 200
    payload = None
    raise_exc = None

    def __init__(self, timeout=None):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get(self, url, headers=None, params=None):
        if _FakeClient.raise_exc:
            raise _FakeClient.raise_exc
        return _FakeResp(_FakeClient.status, _FakeClient.payload)


def _setup(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    monkeypatch.setattr(signing.settings, "intelligence_public_key", signing.load_public_pem(priv.public_key()))
    monkeypatch.setattr(catalog.settings, "intelligence_enabled", True)
    monkeypatch.setattr(catalog.settings, "intelligence_grace_days", 14)
    monkeypatch.setattr(feed.settings, "intelligence_feed_url", "https://feed.example/catalog")
    monkeypatch.setattr(feed.settings, "intelligence_feed_token", "")
    monkeypatch.setattr(feed.settings, "intelligence_feed_timeout_s", 5.0)
    monkeypatch.setattr(feed.httpx, "Client", _FakeClient)
    signing.reset_cache(); catalog.clear_cache(); store.reset_caches()
    _FakeClient.status = 200; _FakeClient.payload = None; _FakeClient.raise_exc = None
    return priv


def _bundle(priv, version):
    return mintlib.mint(patterns=[{"pattern_id": "premium-feed-x", "name": "Feed X",
                                   "signal_type": "network", "match": {"host_re": "x"},
                                   "confidence": "high", "category": "service-endpoint",
                                   "remediation": "y"}],
                        catalog_version=version, private_key=priv, valid_days=30)


def test_pull_installs_newer_catalog(monkeypatch):
    priv = _setup(monkeypatch)
    t = "t-" + uuid.uuid4().hex[:8]
    _FakeClient.payload = _bundle(priv, version=1)
    r = feed.pull_once(t)
    assert r["status"] == "installed" and r["catalog_version"] == 1
    assert catalog.catalog_status(t)["state"] == "fresh"


def test_pull_up_to_date_is_noop(monkeypatch):
    priv = _setup(monkeypatch)
    t = "t-" + uuid.uuid4().hex[:8]
    _FakeClient.payload = _bundle(priv, version=2)
    assert feed.pull_once(t)["status"] == "installed"
    # same version again → not newer → up_to_date, no error
    assert feed.pull_once(t)["status"] == "up_to_date"


def test_pull_unreachable_degrades_gracefully(monkeypatch):
    _setup(monkeypatch)
    _FakeClient.raise_exc = ConnectionError("no route to feed")
    r = feed.pull_once("t-" + uuid.uuid4().hex[:8])
    assert r["status"] == "unreachable"  # never raises; current catalog kept


def test_pull_http_error_is_feed_error(monkeypatch):
    _setup(monkeypatch)
    _FakeClient.status = 503
    _FakeClient.payload = {}
    assert feed.pull_once("t-" + uuid.uuid4().hex[:8])["status"] == "feed_error"


def test_pull_bad_signature_is_rejected(monkeypatch):
    _setup(monkeypatch)
    other = Ed25519PrivateKey.generate()  # signed by the WRONG key
    _FakeClient.payload = _bundle(other, version=1)
    assert feed.pull_once("t-" + uuid.uuid4().hex[:8])["status"] == "rejected"


def test_pull_disabled_when_no_url(monkeypatch):
    _setup(monkeypatch)
    monkeypatch.setattr(feed.settings, "intelligence_feed_url", "")
    assert feed.pull_once("t-" + uuid.uuid4().hex[:8])["status"] == "disabled"
