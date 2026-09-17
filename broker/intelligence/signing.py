# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Ed25519 signature verification for the perishable intelligence catalog.

SurgeXi signs each catalog bundle OFFLINE with a private mint key that NEVER
ships. The broker embeds only the PUBLIC key and VERIFIES — it is the trust
anchor for Mechanism #1 (docs/PROTECTION-MODEL.md): a stolen copy cannot forge a
fresher catalog, and an unsigned/tampered bundle is rejected.

Mirrors the ``cryptography`` usage + env-configurable key handling in
``broker/jwt_keys.py``, but inverted — the broker holds no private key here.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..config import settings

logger = logging.getLogger("vertirite.intel.signing")

_cached_public: Optional[Ed25519PublicKey] = None


def canonical_bytes(payload: Dict[str, Any]) -> bytes:
    """Deterministic serialization of the bundle MINUS its ``signature`` field.

    ``sort_keys`` + tight separators so the signed bytes are byte-identical
    across machines and runs — the same canonical-serialization discipline as
    the report fingerprint chain (broker/reports/runs.py).
    """
    body = {k: v for k, v in payload.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_public_key() -> Optional[Ed25519PublicKey]:
    global _cached_public
    if _cached_public is not None:
        return _cached_public
    pem = (settings.intelligence_public_key or "").strip()
    if not pem and settings.intelligence_public_key_path:
        try:
            with open(settings.intelligence_public_key_path, "rb") as f:
                pem = f.read().decode()
        except OSError as exc:
            logger.warning("intelligence public key path unreadable: %s", exc)
            return None
    if not pem:
        return None
    # Tolerate single-line env delivery: a PEM passed via an env var often has
    # its newlines escaped as the literal two chars "\n". Restore them.
    if "\\n" in pem:
        pem = pem.replace("\\n", "\n")
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("intelligence_public_key is not an Ed25519 public key")
    _cached_public = key
    return key


def verify(payload: Dict[str, Any]) -> bool:
    """True iff ``payload['signature']`` (hex) is a valid Ed25519 signature over
    the canonical bytes, under the configured mint public key.

    No key configured or no signature → False. Unverifiable == untrusted: a
    bundle we cannot prove came from SurgeXi is never installed.
    """
    sig_hex = payload.get("signature")
    if not sig_hex:
        return False
    key = _load_public_key()
    if key is None:
        logger.warning("no intelligence mint public key configured — rejecting bundle")
        return False
    try:
        key.verify(bytes.fromhex(sig_hex), canonical_bytes(payload))
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_bundle(payload: Dict[str, Any], private_key: Ed25519PrivateKey) -> Dict[str, Any]:
    """Return a copy of ``payload`` with a hex ``signature`` over its canonical
    bytes. Used ONLY by tests and the offline mint CLI (PR2) — the broker never
    signs in production.
    """
    sig = private_key.sign(canonical_bytes(payload))
    return {**payload, "signature": sig.hex()}


def load_public_pem(public_key: Ed25519PublicKey) -> str:
    """PEM-encode an Ed25519 public key (helper for tests / the mint CLI)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def reset_cache() -> None:
    """Test hook — drop the cached public key so a test can swap mint keys."""
    global _cached_public
    _cached_public = None
