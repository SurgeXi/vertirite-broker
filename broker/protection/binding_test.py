# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Behavioral binding: bind first-run, detect foreign env, withhold premium when
enforced, re-bind clears it."""
import os
import tempfile
import uuid

_db_fd, _db_path = tempfile.mkstemp(suffix="-binding.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

import broker.protection.binding as binding  # noqa: E402
import broker.protection.identity as identity  # noqa: E402
import broker.protection.fingerprint as fingerprint  # noqa: E402
import broker.protection.store as store  # noqa: E402
import broker.discovery.findings as findings  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(bind=engine)


_schema()


def _setup(monkeypatch, enforce=False):
    monkeypatch.setattr(binding.settings, "protection_binding_enabled", True)
    monkeypatch.setattr(binding.settings, "protection_binding_enforce", enforce)
    identity.reset_cache(); identity.get_instance()
    fingerprint.reset_cache(); binding.reset_cache()
    store.set_bound_fingerprint("")  # start unbound (empty)
    binding.reset_cache()


def _self_findings(tenant):
    return [f for f in findings.list_findings(tenant_id=tenant)
            if f["pattern_id"] == "self-environment-changed"]


def test_first_run_binds_to_current_env(monkeypatch):
    _setup(monkeypatch)
    monkeypatch.setattr(fingerprint, "compute", lambda: "fp-home")
    st = binding.check("default")
    assert st["matches"] is True and st["foreign"] is False
    assert store.get_bound_fingerprint() == "fp-home"


def test_foreign_env_detected(monkeypatch):
    t = "t-" + uuid.uuid4().hex[:8]
    _setup(monkeypatch)
    monkeypatch.setattr(fingerprint, "compute", lambda: "fp-home")
    binding.check(t)                       # binds to fp-home
    monkeypatch.setattr(fingerprint, "compute", lambda: "fp-THIEF")  # copied!
    binding.reset_cache()
    assert binding.is_foreign() is True
    st = binding.check(t)
    assert st["foreign"] is True
    assert len(_self_findings(t)) == 1     # drift finding raised


def test_detection_only_does_not_withhold_premium(monkeypatch):
    # enforce=False (default): foreign is detected but is_foreign-gate is NOT
    # enforced, so active_patterns must NOT drop premium for binding reasons.
    _setup(monkeypatch, enforce=False)
    monkeypatch.setattr(fingerprint, "compute", lambda: "fp-home")
    binding.check("default")
    monkeypatch.setattr(fingerprint, "compute", lambda: "fp-elsewhere")
    binding.reset_cache()
    assert binding.enforced() is False          # not enforced
    assert binding.is_foreign() is True         # but detected


def test_enforced_foreign_withholds_premium(monkeypatch):
    import broker.intelligence.catalog as catalog
    import broker.intelligence.signing as signing
    import broker.intelligence.mint as mintlib
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    t = "t-" + uuid.uuid4().hex[:8]
    _setup(monkeypatch, enforce=True)
    # install a FRESH premium catalog for the tenant
    priv = Ed25519PrivateKey.generate()
    monkeypatch.setattr(signing.settings, "intelligence_public_key", signing.load_public_pem(priv.public_key()))
    monkeypatch.setattr(catalog.settings, "intelligence_enabled", True)
    signing.reset_cache(); catalog.clear_cache()
    bundle = mintlib.mint(patterns=[{"pattern_id": "premium-bind", "name": "P", "signal_type": "network",
                                     "match": {"host_re": "x"}, "confidence": "high",
                                     "category": "service-endpoint", "remediation": "y"}],
                          catalog_version=1, private_key=priv, valid_days=30)
    catalog.install(t, bundle)
    # bound to home → premium present
    monkeypatch.setattr(fingerprint, "compute", lambda: "fp-home")
    binding.check(t); catalog.clear_cache()
    assert "premium-bind" in {p["pattern_id"] for p in catalog.active_patterns(t)}
    # foreign env under enforcement → premium WITHHELD (immune rejection)
    monkeypatch.setattr(fingerprint, "compute", lambda: "fp-foreign")
    binding.reset_cache(); catalog.clear_cache()
    ids = {p["pattern_id"] for p in catalog.active_patterns(t)}
    assert "premium-bind" not in ids
    assert "net-openai-saas" in ids             # baseline survives
    assert catalog.catalog_status(t)["state"] == "foreign"


def test_rebind_clears_foreign(monkeypatch):
    _setup(monkeypatch)
    monkeypatch.setattr(fingerprint, "compute", lambda: "fp-home")
    binding.check("default")
    monkeypatch.setattr(fingerprint, "compute", lambda: "fp-new-home")  # legit move
    binding.reset_cache()
    assert binding.is_foreign() is True
    st = binding.rebind()
    assert st["foreign"] is False and store.get_bound_fingerprint() == "fp-new-home"


def test_disabled_is_never_foreign(monkeypatch):
    _setup(monkeypatch)
    monkeypatch.setattr(binding.settings, "protection_binding_enabled", False)
    monkeypatch.setattr(fingerprint, "compute", lambda: "anything")
    assert binding.is_foreign() is False
