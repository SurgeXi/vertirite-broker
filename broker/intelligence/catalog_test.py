# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""The decay state machine + resolver — the heart of Mechanism #1.

FRESH/STALE keep the premium layer; EXPIRED/TAMPERED drop it to baseline-only.
The open baseline survives every state (crown-jewel rule).
"""
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

import pytest

_db_fd, _db_path = tempfile.mkstemp(suffix="-intel-catalog.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

import broker.intelligence.signing as signing  # noqa: E402
import broker.intelligence.catalog as catalog  # noqa: E402
import broker.intelligence.store as store  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(bind=engine)


_schema()

PREMIUM = {
    "pattern_id": "premium-test-ai", "name": "Premium Test AI", "signal_type": "network",
    "match": {"host_re": r"premium-ai\.example\.com"}, "confidence": "high",
    "category": "service-endpoint", "remediation": "route through the broker",
}


def _now():
    return datetime.now(timezone.utc)


def _bundle(priv, *, version=1, issued=None, expires=None, patterns=None):
    issued = issued or (_now() - timedelta(days=1))
    expires = expires or (_now() + timedelta(days=30))
    payload = {
        "schema": "vertirite.intel.v1", "catalog_version": version,
        "issued_at": issued.isoformat(), "expires_at": expires.isoformat(),
        "tenant_scope": "*", "patterns": patterns or [],
    }
    return signing.sign_bundle(payload, priv)


def _setup(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    monkeypatch.setattr(signing.settings, "intelligence_public_key", signing.load_public_pem(priv.public_key()))
    monkeypatch.setattr(signing.settings, "intelligence_public_key_path", "")
    monkeypatch.setattr(catalog.settings, "intelligence_enabled", True)
    monkeypatch.setattr(catalog.settings, "intelligence_grace_days", 14)
    signing.reset_cache()
    catalog.clear_cache()
    store.reset_caches()
    return priv


def _ids(tenant):
    catalog.clear_cache()
    return {p["pattern_id"] for p in catalog.active_patterns(tenant)}


def test_verify_and_parse_accepts_valid(monkeypatch):
    priv = _setup(monkeypatch)
    assert catalog.verify_and_parse(_bundle(priv, version=1)).catalog_version == 1


def test_verify_and_parse_rejects_tampered_signature(monkeypatch):
    priv = _setup(monkeypatch)
    b = _bundle(priv)
    b["patterns"] = [PREMIUM]  # tamper after signing
    with pytest.raises(catalog.CatalogError):
        catalog.verify_and_parse(b)


def test_verify_and_parse_rejects_downgrade(monkeypatch):
    priv = _setup(monkeypatch)
    with pytest.raises(catalog.CatalogError):
        catalog.verify_and_parse(_bundle(priv, version=2), current_version=2)


def test_fresh_merges_premium_over_baseline(monkeypatch):
    priv = _setup(monkeypatch)
    t = "t-" + uuid.uuid4().hex[:8]
    catalog.install(t, _bundle(priv, version=1, patterns=[PREMIUM]))
    ids = _ids(t)
    assert "premium-test-ai" in ids        # premium present
    assert "net-openai-saas" in ids        # baseline still there
    st = catalog.catalog_status(t)
    assert st["state"] == "fresh" and st["baseline_only"] is False
    assert st["premium_pattern_count"] == 1


def test_stale_within_grace_keeps_premium(monkeypatch):
    priv = _setup(monkeypatch)
    t = "t-" + uuid.uuid4().hex[:8]
    catalog.install(t, _bundle(priv, version=1,
                               issued=_now() - timedelta(days=10),
                               expires=_now() - timedelta(days=2), patterns=[PREMIUM]))
    assert catalog.catalog_status(t)["state"] == "stale"
    assert "premium-test-ai" in _ids(t)


def test_expired_drops_premium_to_baseline(monkeypatch):
    priv = _setup(monkeypatch)
    t = "t-" + uuid.uuid4().hex[:8]
    catalog.install(t, _bundle(priv, version=1,
                               issued=_now() - timedelta(days=60),
                               expires=_now() - timedelta(days=30), patterns=[PREMIUM]))
    ids = _ids(t)
    assert "premium-test-ai" not in ids    # rotted out
    assert "net-openai-saas" in ids        # baseline survives
    st = catalog.catalog_status(t)
    assert st["state"] == "expired" and st["baseline_only"] is True


def test_clock_rollback_is_tampered(monkeypatch):
    priv = _setup(monkeypatch)
    t = "t-" + uuid.uuid4().hex[:8]
    catalog.install(t, _bundle(priv, version=1, patterns=[PREMIUM]))
    store.advance_clock_hwm(t, _now() + timedelta(days=2))  # clock rolled back
    assert catalog.catalog_status(t)["state"] == "tampered"
    assert "premium-test-ai" not in _ids(t)  # premium dropped under tamper


def test_no_tenant_is_baseline_only(monkeypatch):
    _setup(monkeypatch)
    assert "premium-test-ai" not in _ids(None)
    assert catalog.catalog_status(None)["baseline_only"] is True


def test_disabled_is_baseline_only(monkeypatch):
    priv = _setup(monkeypatch)
    t = "t-" + uuid.uuid4().hex[:8]
    catalog.install(t, _bundle(priv, version=1, patterns=[PREMIUM]))
    monkeypatch.setattr(catalog.settings, "intelligence_enabled", False)
    assert "premium-test-ai" not in _ids(t)
