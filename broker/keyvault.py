# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""
Maestro AI — Encrypted API Key Vault

Stores API keys (OpenAI, Anthropic, Plaid, etc.) encrypted at rest in SQLite.
Uses Fernet symmetric encryption with a master key derived from settings.keyvault_secret.

NEVER log or expose decrypted key values.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from .config import settings

logger = logging.getLogger("maestro.keyvault")

VALID_KEY_TYPES = (
    "openai", "anthropic", "plaid", "quickbooks", "slack", "maestro", "pushover", "google", "custom",
)

_DB_DIR = Path(".data")
_DB_PATH = _DB_DIR / "maestro_keys.db"

# ---------------------------------------------------------------------------
# Master-key derivation
# ---------------------------------------------------------------------------

_SALT = b"maestro-keyvault-static-salt-v1"  # static salt; secret is in config


def _derive_fernet_key(secret: str) -> bytes:
    """Derive a 32-byte Fernet key from the config secret using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret.encode()))


def _get_fernet() -> Fernet:
    return Fernet(_derive_fernet_key(settings.keyvault_secret))


# ---------------------------------------------------------------------------
# Database initialisation
# ---------------------------------------------------------------------------

def _init_db() -> sqlite3.Connection:
    _DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id            TEXT PRIMARY KEY,
            key_name      TEXT UNIQUE NOT NULL,
            key_type      TEXT NOT NULL,
            encrypted_value TEXT NOT NULL,
            scope         TEXT NOT NULL DEFAULT 'full',
            active        INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT NOT NULL,
            last_used_at  TEXT
        )
    """)
    conn.commit()
    return conn


def _conn() -> sqlite3.Connection:
    return _init_db()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def store_key(key_name: str, key_type: str, value: str, scope: str = "full") -> dict:
    """Encrypt and store a new API key. Returns metadata (no value)."""
    if key_type not in VALID_KEY_TYPES:
        raise ValueError(f"Invalid key_type: {key_type}. Must be one of {VALID_KEY_TYPES}")

    f = _get_fernet()
    encrypted = f.encrypt(value.encode()).decode()
    now = datetime.now(timezone.utc).isoformat()
    key_id = uuid.uuid4().hex[:16]

    conn = _conn()
    try:
        conn.execute(
            "INSERT INTO api_keys (id, key_name, key_type, encrypted_value, scope, active, created_at) "
            "VALUES (?, ?, ?, ?, ?, 1, ?)",
            (key_id, key_name, key_type, encrypted, scope, now),
        )
        conn.commit()
    finally:
        conn.close()

    logger.info("Stored key %r (type=%s, scope=%s)", key_name, key_type, scope)
    return {"id": key_id, "key_name": key_name, "key_type": key_type, "scope": scope, "active": True, "created_at": now}


def get_key(key_type: str) -> Optional[str]:
    """Decrypt and return the first active key of the given type. Returns None if not found."""
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT id, encrypted_value FROM api_keys WHERE key_type = ? AND active = 1 ORDER BY created_at DESC LIMIT 1",
            (key_type,),
        ).fetchone()
        if row is None:
            return None

        f = _get_fernet()
        decrypted = f.decrypt(row["encrypted_value"].encode()).decode()

        # Update last_used_at
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now, row["id"]))
        conn.commit()
        return decrypted
    finally:
        conn.close()


def get_key_by_name(key_name: str) -> Optional[str]:
    """Decrypt and return a key by its name. Returns None if not found."""
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT id, encrypted_value FROM api_keys WHERE key_name = ? AND active = 1 ORDER BY created_at DESC LIMIT 1",
            (key_name,),
        ).fetchone()
        if row is None:
            return None

        f = _get_fernet()
        decrypted = f.decrypt(row["encrypted_value"].encode()).decode()

        now = datetime.now(timezone.utc).isoformat()
        conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now, row["id"]))
        conn.commit()
        return decrypted
    finally:
        conn.close()


def list_keys() -> list[dict]:
    """Return metadata for all keys — NEVER includes decrypted values."""
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT id, key_name, key_type, scope, active, created_at, last_used_at FROM api_keys ORDER BY created_at DESC"
        ).fetchall()
        return [
            {
                "id": r["id"],
                "key_name": r["key_name"],
                "key_type": r["key_type"],
                "scope": r["scope"],
                "active": bool(r["active"]),
                "created_at": r["created_at"],
                "last_used_at": r["last_used_at"],
            }
            for r in rows
        ]
    finally:
        conn.close()


def delete_key(key_name: str) -> bool:
    """Remove a key by name. Returns True if deleted, False if not found."""
    conn = _conn()
    try:
        cursor = conn.execute("DELETE FROM api_keys WHERE key_name = ?", (key_name,))
        conn.commit()
        deleted = cursor.rowcount > 0
        if deleted:
            logger.info("Deleted key %r", key_name)
        return deleted
    finally:
        conn.close()


def rotate_key(key_name: str, new_value: str) -> bool:
    """Update an existing key's encrypted value. Returns True if rotated, False if not found."""
    f = _get_fernet()
    encrypted = f.encrypt(new_value.encode()).decode()
    now = datetime.now(timezone.utc).isoformat()

    conn = _conn()
    try:
        cursor = conn.execute(
            "UPDATE api_keys SET encrypted_value = ?, last_used_at = ? WHERE key_name = ?",
            (encrypted, now, key_name),
        )
        conn.commit()
        rotated = cursor.rowcount > 0
        if rotated:
            logger.info("Rotated key %r", key_name)
        return rotated
    finally:
        conn.close()


def generate_maestro_key(scope: str = "full") -> str:
    """Generate and store a new Maestro API key for external tools. Returns the raw key."""
    raw_key = f"maestro-{uuid.uuid4().hex}"
    key_name = f"maestro-api-{uuid.uuid4().hex[:8]}"
    store_key(key_name=key_name, key_type="maestro", value=raw_key, scope=scope)
    return raw_key
