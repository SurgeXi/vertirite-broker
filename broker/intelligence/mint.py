# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Offline minting of signed intelligence catalogs — SurgeXi-INTERNAL tooling.

The PRIVATE mint key lives here, in SurgeXi's secure environment, and NEVER ships
to a broker / customer box — the broker only verifies (intelligence/signing.py).
This module builds a catalog bundle and signs it with the SAME canonical
serialization the broker verifies against, so signatures match exactly.

Exposed to operators via the ``vertirite-intel`` CLI (intelligence/cli.py).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import signing
from .catalog import SCHEMA


def generate_keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem) for a fresh Ed25519 mint keypair.

    The public PEM is embedded in the broker (SURGE_OPERATOR_INTELLIGENCE_PUBLIC_KEY);
    the private PEM stays with SurgeXi and signs catalogs — it never ships.
    """
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return priv_pem, signing.load_public_pem(priv.public_key())


def load_private_key(pem: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("not an Ed25519 private key")
    return key


def _now() -> datetime:
    return datetime.now(timezone.utc)


def build_bundle(
    *,
    patterns: List[Dict[str, Any]],
    catalog_version: int,
    valid_days: int = 30,
    issued_at: Optional[datetime] = None,
    tenant_scope: str = "*",
) -> Dict[str, Any]:
    """Construct an UNSIGNED bundle payload."""
    issued = issued_at or _now()
    expires = issued + timedelta(days=valid_days)
    return {
        "schema": SCHEMA,
        "catalog_version": int(catalog_version),
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "tenant_scope": tenant_scope,
        "patterns": patterns,
    }


def mint(
    *,
    patterns: List[Dict[str, Any]],
    catalog_version: int,
    private_key: Ed25519PrivateKey,
    valid_days: int = 30,
    tenant_scope: str = "*",
) -> Dict[str, Any]:
    """Build + sign a catalog bundle. Returns the signed bundle dict."""
    payload = build_bundle(
        patterns=patterns, catalog_version=catalog_version,
        valid_days=valid_days, tenant_scope=tenant_scope,
    )
    return signing.sign_bundle(payload, private_key)
