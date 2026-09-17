# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Ed25519 verification for license tokens.

SurgeXi signs each license OFFLINE with a private LICENSE key (separate from the
intelligence mint key); the broker embeds only the PUBLIC key and VERIFIES.
Reuses the deterministic canonical serialization from intelligence/signing so the
signed bytes are identical everywhere.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..config import settings
from ..intelligence.signing import canonical_bytes  # pure, deterministic

logger = logging.getLogger("vertirite.licensing.signing")

_cached_public: Optional[Ed25519PublicKey] = None


def _load_public_key() -> Optional[Ed25519PublicKey]:
    global _cached_public
    if _cached_public is not None:
        return _cached_public
    pem = (settings.license_public_key or "").strip()
    if not pem and settings.license_public_key_path:
        try:
            with open(settings.license_public_key_path, "rb") as f:
                pem = f.read().decode()
        except OSError as exc:
            logger.warning("license public key path unreadable: %s", exc)
            return None
    if not pem:
        return None
    if "\\n" in pem:
        pem = pem.replace("\\n", "\n")
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("license_public_key is not an Ed25519 public key")
    _cached_public = key
    return key


def verify(payload: Dict[str, Any]) -> bool:
    """True iff payload['signature'] (hex) is valid under the license public key.
    Unverifiable == untrusted (no key / no signature → False)."""
    sig_hex = payload.get("signature")
    if not sig_hex:
        return False
    key = _load_public_key()
    if key is None:
        logger.warning("no license public key configured — rejecting license")
        return False
    try:
        key.verify(bytes.fromhex(sig_hex), canonical_bytes(payload))
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_license(payload: Dict[str, Any], private_key: Ed25519PrivateKey) -> Dict[str, Any]:
    """Sign a license (tests + the offline mint CLI; the broker never signs)."""
    sig = private_key.sign(canonical_bytes(payload))
    return {**payload, "signature": sig.hex()}


def reset_cache() -> None:
    global _cached_public
    _cached_public = None
