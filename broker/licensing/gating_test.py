# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""License PR2: SKU bundles, intelligence feature-gating, expiry anti-rollback."""
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

_db_fd, _db_path = tempfile.mkstemp(suffix="-gating.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

import broker.licensing.license as lic  # noqa: E402
import broker.licensing.signing as licsign  # noqa: E402
import broker.licensing.mint as licmint  # noqa: E402
import broker.licensing.skus as skus  # noqa: E402
import broker.intelligence.catalog as catalog  # noqa: E402
import broker.intelligence.signing as signing  # noqa: E402
import broker.intelligence.mint as mintlib  # noqa: E402
import broker.intelligence.store as intel_store  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(bind=engine)


_schema()


def _now():
    return datetime.now(timezone.utc)


def _pub(priv):
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def test_sku_feature_bundles():
    assert skus.features_for_sku("connected") == ["intelligence", "enforcement", "federation"]
    assert skus.features_for_sku("sovereign") == ["intelligence", "enforcement"]  # no federation
    assert skus.features_for_sku("free") == []
    assert skus.features_for_sku("nope") == []
    # governance is NOT a gated feature — the broker is open-core, governance is free.
    for sku in ("free", "sovereign", "connected", "enterprise"):
        assert "govern" not in skus.features_for_sku(sku)


def test_mint_derives_features_from_sku(tmp_path):
    import broker.licensing.cli as cli
    keys = tmp_path / "k"
    cli.main(["keygen", "--out-dir", str(keys)])
    out = tmp_path / "l.json"
    cli.main(["mint", "--customer", "Acme", "--sku", "connected", "--valid-days", "30",
              "--private", str(keys / "private.pem"), "--out", str(out)])
    import json
    lic_doc = json.loads(out.read_text())
    assert lic_doc["features"] == ["intelligence", "enforcement", "federation"]


def _install_intel_catalog(monkeypatch, tenant):
    """Install a FRESH premium catalog so we can test the license gate on it."""
    priv = Ed25519PrivateKey.generate()
    monkeypatch.setattr(signing.settings, "intelligence_public_key", signing.load_public_pem(priv.public_key()))
    monkeypatch.setattr(catalog.settings, "intelligence_enabled", True)
    signing.reset_cache(); catalog.clear_cache()
    bundle = mintlib.mint(patterns=[{"pattern_id": "premium-lic", "name": "P", "signal_type": "network",
                                     "match": {"host_re": "x"}, "confidence": "high",
                                     "category": "service-endpoint", "remediation": "y"}],
                          catalog_version=1, private_key=priv, valid_days=30)
    catalog.install(tenant, bundle)


def test_intelligence_gated_by_license(monkeypatch):
    t = "t-" + uuid.uuid4().hex[:8]
    _install_intel_catalog(monkeypatch, t)
    # licensing ON, but NO license → premium withheld (free baseline tier)
    monkeypatch.setattr(lic.settings, "license_enabled", True)
    lic.reset_clock(); catalog.clear_cache()
    assert "premium-lic" not in {p["pattern_id"] for p in catalog.active_patterns(t)}
    assert catalog.catalog_status(t)["state"] == "unlicensed"

    # install a license granting 'intelligence' → premium unlocked
    priv = Ed25519PrivateKey.generate()
    monkeypatch.setattr(licsign.settings, "license_public_key", _pub(priv))
    licsign.reset_cache()
    lic.install(licmint.mint(customer="Acme", sku="connected",
                             features=["intelligence"], valid_days=30, private_key=priv))
    catalog.clear_cache()
    assert "premium-lic" in {p["pattern_id"] for p in catalog.active_patterns(t)}


def test_licensing_off_keeps_premium(monkeypatch):
    # default unlicensed-open: premium works without any license
    t = "t-" + uuid.uuid4().hex[:8]
    _install_intel_catalog(monkeypatch, t)
    monkeypatch.setattr(lic.settings, "license_enabled", False)
    lic._clear(); catalog.clear_cache()
    assert "premium-lic" in {p["pattern_id"] for p in catalog.active_patterns(t)}


def test_governance_is_never_a_gated_feature():
    """Open-core invariant: governance is free and never appears as a license
    feature. entitled('govern') is always False because 'govern' isn't a known
    gated feature — the broker's governance surface is BSL-open, not licensed."""
    assert "govern" not in lic.KNOWN_FEATURES


def test_expiry_anti_rollback(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    monkeypatch.setattr(licsign.settings, "license_public_key", _pub(priv))
    monkeypatch.setattr(lic.settings, "license_enabled", True)
    licsign.reset_cache(); lic.reset_clock()
    lic.install(licmint.mint(customer="Acme", sku="connected", features=["enforcement"],
                             valid_days=365, private_key=priv))
    assert lic.license_state()["state"] == "valid"
    # roll the clock back: push the license HWM into the future
    intel_store.advance_clock_hwm("__license__", _now() + timedelta(days=2))
    lic._clear()
    assert lic.license_state()["state"] == "tampered"
    assert lic.entitled("enforcement") is False
