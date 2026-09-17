# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Ed25519 catalog signature verification — accept the genuine, reject the rest."""
import broker.intelligence.signing as signing
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _keypair():
    priv = Ed25519PrivateKey.generate()
    return priv, signing.load_public_pem(priv.public_key())


def _bundle():
    return {
        "schema": "vertirite.intel.v1", "catalog_version": 1,
        "issued_at": "2026-01-01T00:00:00+00:00",
        "expires_at": "2027-01-01T00:00:00+00:00",
        "tenant_scope": "*", "patterns": [],
    }


def _use_key(monkeypatch, pub):
    monkeypatch.setattr(signing.settings, "intelligence_public_key", pub)
    monkeypatch.setattr(signing.settings, "intelligence_public_key_path", "")
    signing.reset_cache()


def test_valid_signature_verifies(monkeypatch):
    priv, pub = _keypair()
    _use_key(monkeypatch, pub)
    assert signing.verify(signing.sign_bundle(_bundle(), priv)) is True


def test_tampered_payload_fails(monkeypatch):
    priv, pub = _keypair()
    _use_key(monkeypatch, pub)
    signed = signing.sign_bundle(_bundle(), priv)
    signed["catalog_version"] = 999  # tamper AFTER signing
    assert signing.verify(signed) is False


def test_wrong_key_fails(monkeypatch):
    priv, _ = _keypair()
    _, other_pub = _keypair()
    _use_key(monkeypatch, other_pub)
    assert signing.verify(signing.sign_bundle(_bundle(), priv)) is False


def test_no_key_configured_rejects(monkeypatch):
    priv, _ = _keypair()
    _use_key(monkeypatch, "")
    assert signing.verify(signing.sign_bundle(_bundle(), priv)) is False


def test_no_signature_rejects(monkeypatch):
    _, pub = _keypair()
    _use_key(monkeypatch, pub)
    assert signing.verify(_bundle()) is False  # no signature field


def test_canonical_bytes_excludes_signature():
    b = _bundle()
    assert signing.canonical_bytes(b) == signing.canonical_bytes({**b, "signature": "deadbeef"})
