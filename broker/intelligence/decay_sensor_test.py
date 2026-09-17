# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""End-to-end: decay narrows REAL detection through the network sensor.

A FRESH premium catalog lets the sensor name a host that the open baseline can't;
once the catalog rots (EXPIRED), that host falls back to the generic catch-all —
the "rotting brain" made observable at the sensor, not just in the resolver.
"""
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

_db_fd, _db_path = tempfile.mkstemp(suffix="-intel-decay.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

import broker.intelligence.signing as signing  # noqa: E402
import broker.intelligence.catalog as catalog  # noqa: E402
import broker.intelligence.store as store  # noqa: E402
import broker.discovery.network_sensor as ns  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(bind=engine)


_schema()

PREMIUM_NET = {
    "pattern_id": "premium-acme-llm", "name": "Acme Secret LLM", "signal_type": "network",
    "match": {"host_re": r"acme-secret-llm\.example\.com"}, "confidence": "high",
    "category": "service-endpoint", "remediation": "route through the broker",
}
HOST = "acme-secret-llm.example.com"


def _now():
    return datetime.now(timezone.utc)


def _bundle(priv, *, version, issued=None, expires=None):
    issued = issued or (_now() - timedelta(days=1))
    expires = expires or (_now() + timedelta(days=30))
    return signing.sign_bundle({
        "schema": "vertirite.intel.v1", "catalog_version": version,
        "issued_at": issued.isoformat(), "expires_at": expires.isoformat(),
        "tenant_scope": "*", "patterns": [PREMIUM_NET],
    }, priv)


def test_decay_narrows_real_sensor_detection(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    monkeypatch.setattr(signing.settings, "intelligence_public_key", signing.load_public_pem(priv.public_key()))
    monkeypatch.setattr(catalog.settings, "intelligence_enabled", True)
    monkeypatch.setattr(catalog.settings, "intelligence_grace_days", 14)
    signing.reset_cache(); catalog.clear_cache(); store.reset_caches()

    t = "t-" + uuid.uuid4().hex[:8]

    # Baseline (no catalog) cannot name the host — falls to the generic catch-all.
    assert ns.match_host(HOST, None) == "net-unrecognized-external-egress"

    # FRESH premium catalog → the sensor now NAMES the host.
    catalog.install(t, _bundle(priv, version=1))
    catalog.clear_cache()
    assert ns.match_host(HOST, t) == "premium-acme-llm"

    # EXPIRED → premium rots out → the host goes dark again (generic catch-all).
    catalog.install(t, _bundle(priv, version=2,
                               issued=_now() - timedelta(days=60),
                               expires=_now() - timedelta(days=30)))
    catalog.clear_cache(); store.reset_caches()
    assert ns.match_host(HOST, t) == "net-unrecognized-external-egress"
