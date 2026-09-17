# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Minting: a freshly-minted bundle verifies + parses; env-PEM delivery works.

No DB needed — verify_and_parse + signing are pure (storage is exercised
elsewhere).
"""
from datetime import datetime

import broker.intelligence.catalog as catalog
import broker.intelligence.mint as mintlib
import broker.intelligence.signing as signing


def _use_key(monkeypatch, pub):
    monkeypatch.setattr(signing.settings, "intelligence_public_key", pub)
    monkeypatch.setattr(signing.settings, "intelligence_public_key_path", "")
    signing.reset_cache()


def test_keygen_mint_verify_roundtrip(monkeypatch):
    priv_pem, pub_pem = mintlib.generate_keypair()
    _use_key(monkeypatch, pub_pem)
    priv = mintlib.load_private_key(priv_pem)
    bundle = mintlib.mint(patterns=[{"pattern_id": "x"}], catalog_version=5,
                          private_key=priv, valid_days=30)
    assert signing.verify(bundle) is True
    cat = catalog.verify_and_parse(bundle)
    assert cat.catalog_version == 5 and len(cat.patterns) == 1


def test_minted_expiry_is_valid_days_after_issue(monkeypatch):
    priv_pem, _ = mintlib.generate_keypair()
    priv = mintlib.load_private_key(priv_pem)
    b = mintlib.mint(patterns=[], catalog_version=1, private_key=priv, valid_days=10)
    iss = datetime.fromisoformat(b["issued_at"])
    exp = datetime.fromisoformat(b["expires_at"])
    assert (exp - iss).days == 10


def test_env_pem_with_escaped_newlines_verifies(monkeypatch):
    # Simulate single-line env delivery: PEM newlines escaped as literal "\n".
    priv_pem, pub_pem = mintlib.generate_keypair()
    _use_key(monkeypatch, pub_pem.replace("\n", "\\n"))
    priv = mintlib.load_private_key(priv_pem)
    assert signing.verify(mintlib.mint(patterns=[], catalog_version=1, private_key=priv)) is True


def test_minted_bundle_with_wrong_key_is_rejected(monkeypatch):
    priv_pem, _ = mintlib.generate_keypair()
    _, other_pub = mintlib.generate_keypair()
    _use_key(monkeypatch, other_pub)
    priv = mintlib.load_private_key(priv_pem)
    assert signing.verify(mintlib.mint(patterns=[], catalog_version=1, private_key=priv)) is False
