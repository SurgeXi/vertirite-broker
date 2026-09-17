# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Compliance report Ed25519 signing (production seal on top of the sha256 anchor)."""
import os
import tempfile
import uuid

_db_fd, _db_path = tempfile.mkstemp(suffix="-compliance-sign.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from broker.config import settings  # noqa: E402
from broker.compliance import report  # noqa: E402
from broker.intelligence import signing  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db(); Base.metadata.create_all(bind=engine)


_schema()


def _pem(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def test_unsigned_when_no_key(monkeypatch):
    monkeypatch.setattr(settings, "compliance_signing_key", "")
    monkeypatch.setattr(settings, "compliance_signing_key_path", "")
    r = report.build_signed_report(f"t-{uuid.uuid4().hex[:8]}")
    assert r["seal"] == "sha256-only" and r["signature"] is None
    assert len(r["integrity"]["hash"]) == 64  # anchor always present


def test_ed25519_seal_verifies(monkeypatch):
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(settings, "compliance_signing_key", _pem(key))
    monkeypatch.setattr(settings, "compliance_signing_key_path", "")
    r = report.build_signed_report(f"t-{uuid.uuid4().hex[:8]}")
    assert r["seal"] == "ed25519" and r["signature"]
    # verify the signature with the matching public key over the canonical bytes
    pub = key.public_key()
    pub.verify(bytes.fromhex(r["signature"]), signing.canonical_bytes(r))  # raises if invalid


def test_tampering_breaks_the_seal(monkeypatch):
    from cryptography.exceptions import InvalidSignature
    import pytest
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(settings, "compliance_signing_key", _pem(key))
    r = report.build_signed_report(f"t-{uuid.uuid4().hex[:8]}")
    r["attestation"] = "TAMPERED"
    with pytest.raises(InvalidSignature):
        key.public_key().verify(bytes.fromhex(r["signature"]), signing.canonical_bytes(r))
