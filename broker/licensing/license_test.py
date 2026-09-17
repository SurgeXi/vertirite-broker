# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""License: verify/install, expiry, entitlement gating, mint CLI round-trip."""
import os
import tempfile

_db_fd, _db_path = tempfile.mkstemp(suffix="-license.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from datetime import datetime, timedelta, timezone  # noqa: E402

import broker.licensing.license as lic  # noqa: E402
import broker.licensing.signing as signing  # noqa: E402
import broker.licensing.store as store  # noqa: E402
import broker.licensing.mint as mintlib  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(bind=engine)


_schema()


def _now():
    return datetime.now(timezone.utc)


def _setup(monkeypatch, enabled=True):
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    monkeypatch.setattr(signing.settings, "license_public_key", pub)
    monkeypatch.setattr(signing.settings, "license_public_key_path", "")
    monkeypatch.setattr(lic.settings, "license_enabled", enabled)
    signing.reset_cache(); lic.reset_clock()
    return priv


def _mint(priv, *, features, valid_days=365, issued=None):
    return mintlib.mint(customer="Acme", sku="connected", features=features,
                        valid_days=valid_days, private_key=priv,
                        issued_at=issued or _now())


def test_install_valid_license(monkeypatch):
    priv = _setup(monkeypatch)
    st = lic.install(_mint(priv, features=["intelligence", "enforcement"]))
    assert st["state"] == "valid" and st["sku"] == "connected"
    assert "enforcement" in st["features"]


def test_entitled_only_for_granted_features(monkeypatch):
    priv = _setup(monkeypatch)
    lic.install(_mint(priv, features=["intelligence"]))
    assert lic.entitled("intelligence") is True
    assert lic.entitled("enforcement") is False     # not granted
    assert lic.entitled("federation") is False


def test_no_license_is_free_tier(monkeypatch):
    _setup(monkeypatch)
    store.install({"license_id": "", "features": []}, _now(), _now() + timedelta(days=1))
    # wipe to truly-none:
    from broker.db import session_scope
    from broker.licensing.store import LicenseTable
    with session_scope() as db:
        row = db.get(LicenseTable, "self")
        if row:
            db.delete(row)
    lic._clear()
    assert lic.license_state()["state"] == "none"
    assert lic.entitled("enforcement") is False


def test_expired_license_grants_nothing(monkeypatch):
    priv = _setup(monkeypatch)
    # issued + expires both in the past
    lic.install(_mint(priv, features=["enforcement"], valid_days=10,
                      issued=_now() - timedelta(days=40)))
    st = lic.license_state()
    assert st["state"] == "expired" and st["features"] == []
    assert lic.entitled("enforcement") is False


def test_bad_signature_rejected(monkeypatch):
    priv = _setup(monkeypatch)
    bad = _mint(priv, features=["enforcement"])
    bad["features"] = ["federation"]  # tamper after signing
    import pytest
    with pytest.raises(lic.LicenseError):
        lic.verify_and_parse(bad)


def test_licensing_disabled_entitles_everything(monkeypatch):
    _setup(monkeypatch, enabled=False)
    lic._clear()
    assert lic.entitled("enforcement") is True   # dev / unlicensed-open mode


def test_cli_keygen_mint_verify(tmp_path):
    import broker.licensing.cli as cli
    keys = tmp_path / "lk"
    assert cli.main(["keygen", "--out-dir", str(keys)]) == 0
    out = tmp_path / "acme.json"
    assert cli.main(["mint", "--customer", "Acme", "--sku", "connected",
                     "--features", "intelligence,enforcement", "--valid-days", "365",
                     "--private", str(keys / "private.pem"), "--out", str(out)]) == 0
    assert cli.main(["verify", "--license", str(out), "--public", str(keys / "public.pem")]) == 0
