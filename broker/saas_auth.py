# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""
SaaS authentication for Maestro AI.

Provides registration, login, API key auth, and session token auth
for multi-tenant SaaS operation. Coexists with the existing bootstrap
bearer-token auth for backward compatibility.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from .config import settings
from .tenant import (
    create_tenant,
    create_tenant_user,
    get_tenant,
    get_tenant_user,
    get_tenant_user_by_api_key_hash,
    get_tenant_user_by_email,
    update_user_api_key_hash,
    update_user_login,
)

logger = logging.getLogger("maestro.saas_auth")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Password hashing (using hashlib/hmac — no bcrypt dependency needed)
# ---------------------------------------------------------------------------

def _hash_password(password: str) -> str:
    """Hash a password with a random salt using PBKDF2-HMAC-SHA256."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations=260_000)
    return f"pbkdf2:sha256:260000${salt}${dk.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored PBKDF2 hash."""
    try:
        parts = stored_hash.split("$")
        if len(parts) != 3:
            return False
        _header, salt, dk_hex = parts
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations=260_000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# API key generation
# ---------------------------------------------------------------------------

def generate_api_key(user_id: str, tenant_id: str) -> str:
    """Generate a new API key in mae_<random> format."""
    raw = secrets.token_urlsafe(32)
    return f"mae_{raw}"


def _hash_api_key(api_key: str) -> str:
    """Hash an API key for storage (SHA-256)."""
    return hashlib.sha256(api_key.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Session tokens (short-lived, for web/desktop)
# ---------------------------------------------------------------------------

# In-memory session store. Production would use Redis, but this is
# sufficient for the current scale and survives within process lifetime.
_session_store: Dict[str, Dict[str, Any]] = {}

_SESSION_TTL_HOURS = 24


def _create_session_token(user_id: str, tenant_id: str) -> str:
    """Create a session token and store it."""
    token = f"mse_{secrets.token_urlsafe(48)}"
    _session_store[token] = {
        "user_id": user_id,
        "tenant_id": tenant_id,
        "created_at": _utc_now(),
        "expires_at": _utc_now() + timedelta(hours=_SESSION_TTL_HOURS),
    }
    # Prune expired sessions (keep store clean)
    _prune_expired_sessions()
    return token


def _prune_expired_sessions() -> None:
    """Remove expired session tokens."""
    now = _utc_now()
    expired = [k for k, v in _session_store.items() if v["expires_at"] < now]
    for k in expired:
        del _session_store[k]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def register(
    email: str,
    password: str,
    display_name: str,
    tenant_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Register a new user account.

    If tenant_name is provided, creates a new tenant and makes the user the owner.
    Otherwise, registration requires an existing invite (not implemented yet —
    for now, tenant_name is required).
    """
    # Validate inputs
    if not email or not password:
        raise ValueError("Email and password are required")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")

    # Check for existing user
    existing = get_tenant_user_by_email(email)
    if existing is not None:
        raise ValueError("An account with this email already exists")

    # Create tenant if name provided
    if tenant_name:
        tenant = create_tenant(name=tenant_name, plan="free")
        tenant_id = tenant["id"]
        role = "owner"
    else:
        raise ValueError("tenant_name is required for registration (invite system not yet implemented)")

    # Hash password and generate API key
    pw_hash = _hash_password(password)
    api_key = generate_api_key("pending", tenant_id)
    api_key_hash = _hash_api_key(api_key)

    # Create the user
    user = create_tenant_user(
        tenant_id=tenant_id,
        email=email,
        display_name=display_name,
        password_hash=pw_hash,
        role=role,
        api_key_hash=api_key_hash,
    )

    logger.info("User registered: email=%s tenant=%s", email, tenant_id)
    return {
        "user": {
            "id": user["id"],
            "email": user["email"],
            "display_name": user["display_name"],
            "role": user["role"],
        },
        "tenant": {
            "id": tenant["id"],
            "name": tenant["name"],
            "slug": tenant["slug"],
            "plan": tenant["plan"],
            "token_balance": tenant["token_balance"],
        },
        "api_key": api_key,
    }


async def login(email: str, password: str) -> Dict[str, Any]:
    """
    Authenticate a user with email and password.
    Returns user, tenant, session_token, and api_key.
    """
    user = get_tenant_user_by_email(email)
    if user is None:
        raise ValueError("Invalid email or password")

    if not _verify_password(password, user["password_hash"]):
        raise ValueError("Invalid email or password")

    if user["status"] != "active":
        raise ValueError("Account is disabled")

    # Get tenant
    tenant = get_tenant(user["tenant_id"])
    if tenant is None:
        raise ValueError("Tenant not found")

    if tenant["status"] == "suspended":
        raise ValueError("Your organization's account is suspended")

    # Generate session token
    session_token = _create_session_token(user["id"], user["tenant_id"])

    # Generate a fresh API key
    api_key = generate_api_key(user["id"], user["tenant_id"])
    api_key_hash = _hash_api_key(api_key)
    update_user_api_key_hash(user["id"], api_key_hash)

    # Update last login
    update_user_login(user["id"])

    logger.info("User logged in: email=%s tenant=%s", email, user["tenant_id"])
    return {
        "user": {
            "id": user["id"],
            "email": user["email"],
            "display_name": user["display_name"],
            "role": user["role"],
            "must_change_password": bool(user.get("must_change_password", False)),
        },
        "tenant": {
            "id": tenant["id"],
            "name": tenant["name"],
            "slug": tenant["slug"],
            "plan": tenant["plan"],
            "token_balance": tenant["token_balance"],
        },
        "session_token": session_token,
        "api_key": api_key,
    }


async def authenticate_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """
    Authenticate using an API key (mae_xxx format).
    Returns {user, tenant} or None.
    """
    if not api_key.startswith("mae_"):
        return None

    key_hash = _hash_api_key(api_key)
    user = get_tenant_user_by_api_key_hash(key_hash)
    if user is None:
        return None

    if user["status"] != "active":
        return None

    tenant = get_tenant(user["tenant_id"])
    if tenant is None or tenant["status"] == "suspended":
        return None

    return {
        "user": {
            "id": user["id"],
            "email": user["email"],
            "display_name": user["display_name"],
            "role": user["role"],
        },
        "tenant": tenant,
    }


async def authenticate_session(token: str) -> Optional[Dict[str, Any]]:
    """
    Authenticate using a session token (mse_xxx format).
    Returns {user, tenant} or None.
    """
    if not token.startswith("mse_"):
        return None

    session = _session_store.get(token)
    if session is None:
        return None

    if session["expires_at"] < _utc_now():
        _session_store.pop(token, None)
        return None

    user = get_tenant_user(session["user_id"])
    if user is None or user["status"] != "active":
        return None

    tenant = get_tenant(session["tenant_id"])
    if tenant is None or tenant["status"] == "suspended":
        return None

    return {
        "user": {
            "id": user["id"],
            "email": user["email"],
            "display_name": user["display_name"],
            "role": user["role"],
        },
        "tenant": tenant,
    }


# ── Sync wrappers for use in FastAPI sync dependencies ────────────────

def authenticate_api_key_sync(api_key: str) -> Optional[Dict[str, Any]]:
    """Sync version of authenticate_api_key for use in require_bearer_token."""
    if not api_key.startswith("mae_"):
        return None
    key_hash = _hash_api_key(api_key)
    user = get_tenant_user_by_api_key_hash(key_hash)
    if user is None or user["status"] != "active":
        return None
    tenant = get_tenant(user["tenant_id"])
    if tenant is None or tenant["status"] == "suspended":
        return None
    return {
        "user": {"id": user["id"], "email": user["email"], "display_name": user["display_name"], "role": user["role"]},
        "tenant": tenant,
    }


def authenticate_session_sync(token: str) -> Optional[Dict[str, Any]]:
    """Sync version of authenticate_session for use in require_bearer_token."""
    if not token.startswith("mse_"):
        return None
    session = _session_store.get(token)
    if session is None:
        return None
    if session["expires_at"] < _utc_now():
        _session_store.pop(token, None)
        return None
    user = get_tenant_user(session["user_id"])
    if user is None or user["status"] != "active":
        return None
    tenant = get_tenant(session["tenant_id"])
    if tenant is None or tenant["status"] == "suspended":
        return None
    return {
        "user": {"id": user["id"], "email": user["email"], "display_name": user["display_name"], "role": user["role"]},
        "tenant": tenant,
    }


# ---------------------------------------------------------------------------
# Email Verification
# ---------------------------------------------------------------------------

_verification_tokens: Dict[str, Dict[str, Any]] = {}

def create_verification_token(email: str) -> str:
    """Create a token for email verification."""
    token = secrets.token_urlsafe(32)
    _verification_tokens[token] = {
        "email": email,
        "created_at": _utc_now(),
        "expires_at": _utc_now() + timedelta(hours=24),
    }
    return token


def verify_email_token(token: str) -> Optional[str]:
    """Verify an email token. Returns email if valid, None if expired/invalid."""
    data = _verification_tokens.pop(token, None)
    if data is None:
        return None
    if data["expires_at"] < _utc_now():
        return None
    return data["email"]


# ---------------------------------------------------------------------------
# Password Reset
# ---------------------------------------------------------------------------

_reset_tokens: Dict[str, Dict[str, Any]] = {}

def create_reset_token(email: str) -> Optional[str]:
    """Create a password reset token. Returns None if user not found."""
    user = get_tenant_user_by_email(email)
    if user is None:
        return None
    token = secrets.token_urlsafe(32)
    _reset_tokens[token] = {
        "user_id": user["id"],
        "email": email,
        "created_at": _utc_now(),
        "expires_at": _utc_now() + timedelta(hours=1),
    }
    return token


def reset_password_with_token(token: str, new_password: str) -> bool:
    """Reset password using a reset token. Returns True on success."""
    data = _reset_tokens.pop(token, None)
    if data is None:
        return False
    if data["expires_at"] < _utc_now():
        return False
    if len(new_password) < 8:
        return False

    from .tenant import update_user_password
    pw_hash = _hash_password(new_password)
    update_user_password(data["user_id"], pw_hash)
    logger.info("Password reset for user_id=%s", data["user_id"])

    # Invalidate all sessions for this user
    to_remove = [k for k, v in _session_store.items() if v["user_id"] == data["user_id"]]
    for k in to_remove:
        del _session_store[k]

    return True


def change_password(user_id: str, current_password: str, new_password: str) -> Dict[str, Any]:
    """Change password requiring the current password. Returns {ok, detail}."""
    if len(new_password) < 8:
        return {"ok": False, "detail": "New password must be at least 8 characters"}

    user = get_tenant_user(user_id)
    if user is None:
        return {"ok": False, "detail": "User not found"}

    if not _verify_password(current_password, user["password_hash"]):
        return {"ok": False, "detail": "Current password is incorrect"}

    from .tenant import update_user_password
    pw_hash = _hash_password(new_password)
    update_user_password(user_id, pw_hash)
    logger.info("Password changed for user_id=%s", user_id)

    to_remove = [k for k, v in _session_store.items() if v["user_id"] == user_id]
    for k in to_remove:
        del _session_store[k]

    return {"ok": True}
