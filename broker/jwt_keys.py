# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Broker JWT signing keys (ES256 / ECDSA P-256).

Generated once and persisted to disk (mounted into the container from the
host). The broker uses the private key to sign JWTs that ride on every
fleet_agent call. The agents' agent-noded verifies signatures against a
copy of the public key placed at install time (see install-prod.sh).

Why ES256:
  - Smaller signatures than RS256 (~64 bytes raw vs ~256 bytes)
  - Fast verification on the agent
  - Native support in Python `cryptography` and Go `golang-jwt/jwt/v5`
  - No extra Python deps beyond what the broker already has

Phase B scope: static keypair, distributed once via the install script.
Phase E follow-up will add a JWKS endpoint and dynamic-rotation flow.

Operator notes:
  - Set `SURGE_OPERATOR_JWT_PRIVATE_KEY` env to override path (default
    /etc/maestro-broker/jwt/private.pem)
  - Mount /srv/vertirite/maestro-broker-jwt:/etc/maestro-broker/jwt:ro
    in the broker compose so keys persist across container recreates
  - Back up the private key. If it's lost, every agent's stored public
    key becomes stale and verification breaks until they're updated.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger("maestro.jwt_keys")

_DEFAULT_DIR = "/etc/maestro-broker/jwt"
_DEFAULT_PRIV = f"{_DEFAULT_DIR}/private.pem"
_DEFAULT_PUB = f"{_DEFAULT_DIR}/public.pem"

# In-process cache so we don't read from disk on every JWT mint
_cached_private: Optional[ec.EllipticCurvePrivateKey] = None
_cached_public_pem: Optional[str] = None


def _paths() -> tuple[str, str]:
    priv = os.environ.get("SURGE_OPERATOR_JWT_PRIVATE_KEY", _DEFAULT_PRIV)
    pub = os.environ.get("SURGE_OPERATOR_JWT_PUBLIC_KEY", _DEFAULT_PUB)
    return priv, pub


def ensure_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    """Load the broker's signing keypair, generating it on first run.

    Returns (private_key_object, public_key_pem_string). The public PEM is
    what the operator copies to each fleet agent's config dir during
    install-prod.sh.
    """
    global _cached_private, _cached_public_pem
    if _cached_private is not None and _cached_public_pem is not None:
        return _cached_private, _cached_public_pem

    priv_path, pub_path = _paths()

    generated_new = False
    if os.path.exists(priv_path):
        with open(priv_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise RuntimeError(f"{priv_path} is not an EC private key")
        logger.info("Loaded broker JWT private key from %s", priv_path)
    else:
        Path(os.path.dirname(priv_path)).mkdir(parents=True, exist_ok=True)
        private_key = ec.generate_private_key(ec.SECP256R1())
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Write atomically: write to temp then rename, so a crashed
        # broker mid-write doesn't leave a half-written key file
        tmp = f"{priv_path}.tmp"
        with open(tmp, "wb") as f:
            f.write(priv_pem)
        os.chmod(tmp, 0o600)
        os.rename(tmp, priv_path)
        generated_new = True
        logger.warning(
            "Generated NEW broker JWT private key at %s — back this up. "
            "Every fleet agent must receive an updated public key.",
            priv_path,
        )

    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    # Only write the public file when we just generated the keypair, OR when
    # the file is genuinely missing. Don't rewrite on every call — operators
    # mount the keypair dir read-only on the broker side because the broker
    # has no business modifying its own keys after first generation.
    if generated_new or not os.path.exists(pub_path):
        try:
            Path(os.path.dirname(pub_path)).mkdir(parents=True, exist_ok=True)
            with open(pub_path, "w") as f:
                f.write(pub_pem)
            os.chmod(pub_path, 0o644)
        except OSError as exc:
            # ro mount is the operator's choice — log and proceed. The
            # private key is the source of truth; an absent public.pem on
            # disk just means operators distribute via /v1/jwt-public-key.
            logger.warning("Could not write public key to %s (%s) — fleet agents must fetch from /v1/jwt-public-key", pub_path, exc)

    _cached_private = private_key
    _cached_public_pem = pub_pem
    return private_key, pub_pem


def public_key_pem() -> str:
    """Return the broker's public key PEM. Surfaced via the
    /v1/jwt-public-key endpoint so operators can fetch it during install."""
    _, pub = ensure_keypair()
    return pub
