# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Offline minting of signed licenses — SurgeXi-INTERNAL. The private license key
lives here and NEVER ships (the broker only verifies)."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import signing
from .license import SCHEMA


def generate_keypair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def load_private_key(pem: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("not an Ed25519 private key")
    return key


def mint(
    *,
    customer: str,
    sku: str,
    features: List[str],
    valid_days: int,
    private_key: Ed25519PrivateKey,
    issued_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    issued = issued_at or datetime.now(timezone.utc)
    payload = {
        "schema": SCHEMA,
        "license_id": str(uuid.uuid4()),
        "customer": customer,
        "sku": sku,
        "features": list(features),
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(days=valid_days)).isoformat(),
    }
    return signing.sign_license(payload, private_key)
