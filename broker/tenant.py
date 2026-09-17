# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""
Multi-tenant system for Maestro AI SaaS.

Manages tenants, users, token balances, and usage metering.
"""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text, select, func
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, session_scope

logger = logging.getLogger("maestro.tenant")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Plan definitions
# ---------------------------------------------------------------------------

# Vertirite SKUs (locked in docs/positioning.md 2026-04-27, with Team /
# Business prices as marketed on /pricing). The previous Maestro-era
# tiers ("starter", "professional") were renamed in alembic migration
# 20260520_0006 — "starter" became "team", "professional" became "business".
PLAN_TOKEN_ALLOCATION: Dict[str, int] = {
    "free": 1_000,
    "team": 10_000,
    "business": 200_000,
    "enterprise": 999_999_999,
}

PLAN_LIST = [
    {"plan": "free", "tokens": 1_000, "price_monthly": 0, "audience": "OSS / self-host"},
    {"plan": "team", "tokens": 10_000, "price_monthly": 500, "audience": "small MSPs, consultancies"},
    {"plan": "business", "tokens": 200_000, "price_monthly": 2_500, "audience": "mid-market regional businesses"},
    {"plan": "enterprise", "tokens": 999_999_999, "price_monthly": "custom", "audience": "hospitals, banks, government"},
]

# Token costs per action type
TOKEN_COSTS: Dict[str, int] = {
    "chat": 1,           # quick-match
    "chat_llm": 10,      # LLM inference
    "voice": 20,         # voice transcription
    "search": 5,         # web search
    "document": 3,       # document read
    "automation": 5,     # automation execution
}


# ---------------------------------------------------------------------------
# SQLAlchemy table models
# ---------------------------------------------------------------------------

class TenantTable(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    plan: Mapped[str] = mapped_column(String(64), nullable=False, default="free")
    token_balance: Mapped[int] = mapped_column(Integer, nullable=False, default=1000)
    tokens_used_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


class TenantUserTable(Base):
    __tablename__ = "tenant_users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="member")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    api_key_hash: Mapped[Optional[str]] = mapped_column(String(512), nullable=True, index=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


class TokenUsageTable(Base):
    __tablename__ = "token_usage"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tokens_consumed: Mapped[int] = mapped_column(Integer, nullable=False)
    model_used: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _slugify(name: str) -> str:
    """Convert a tenant name to a URL-safe slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug or "tenant"


def _ensure_unique_slug(slug: str, db) -> str:
    """If slug already exists, append a short suffix."""
    base = slug
    counter = 0
    while True:
        existing = db.scalar(
            select(TenantTable).where(TenantTable.slug == slug)
        )
        if existing is None:
            return slug
        counter += 1
        slug = f"{base}-{counter}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_tenant(name: str, plan: str = "free") -> Dict[str, Any]:
    """Create a new tenant with initial token balance per plan."""
    if plan not in PLAN_TOKEN_ALLOCATION:
        raise ValueError(f"Invalid plan: {plan}. Must be one of: {list(PLAN_TOKEN_ALLOCATION.keys())}")

    tenant_id = str(uuid.uuid4())
    initial_tokens = PLAN_TOKEN_ALLOCATION[plan]
    slug = _slugify(name)

    with session_scope() as db:
        slug = _ensure_unique_slug(slug, db)
        tenant = TenantTable(
            id=tenant_id,
            name=name,
            slug=slug,
            plan=plan,
            token_balance=initial_tokens,
            tokens_used_total=0,
            status="active",
        )
        db.add(tenant)

    logger.info("Tenant created: id=%s name=%s plan=%s tokens=%d", tenant_id, name, plan, initial_tokens)
    return {
        "id": tenant_id,
        "name": name,
        "slug": slug,
        "plan": plan,
        "token_balance": initial_tokens,
        "tokens_used_total": 0,
        "status": "active",
    }


def get_tenant(tenant_id: str) -> Optional[Dict[str, Any]]:
    """Return tenant by ID."""
    with session_scope() as db:
        row = db.get(TenantTable, tenant_id)
        if row is None:
            return None
        return _tenant_to_dict(row)


class TenantSuspended(Exception):
    """Raised when an action is attempted against a non-active tenant.

    The broker enforces this at the policy gate — every action path that
    accrues governance attestations on behalf of a tenant must first call
    assert_tenant_active(). Suspended or archived tenants get a clean
    403 instead of silently growing audit rows that look governed.
    """

    def __init__(self, tenant_id: str, status: str, name: str = ""):
        self.tenant_id = tenant_id
        self.status = status
        self.name = name
        super().__init__(
            f"tenant {tenant_id} (status={status}) is not active — action denied"
        )


def assert_tenant_active(tenant_id: str) -> Dict[str, Any]:
    """Look up the tenant and require status='active'.

    Returns the tenant dict on success. Raises TenantSuspended if the
    tenant is suspended or archived. Raises LookupError if not found.

    Callers (broker endpoints) should translate TenantSuspended → HTTP 403
    with a clear detail message; LookupError → HTTP 404.
    """
    tenant = get_tenant(tenant_id)
    if tenant is None:
        raise LookupError(f"tenant not found: {tenant_id}")
    if tenant.get("status") != "active":
        raise TenantSuspended(
            tenant_id=tenant_id, status=tenant.get("status", "?"), name=tenant.get("name", "")
        )
    return tenant


def get_tenant_by_slug(slug: str) -> Optional[Dict[str, Any]]:
    """Return tenant by slug."""
    with session_scope() as db:
        row = db.scalar(select(TenantTable).where(TenantTable.slug == slug))
        if row is None:
            return None
        return _tenant_to_dict(row)


def consume_tokens(
    tenant_id: str,
    action: str,
    tokens: int,
    user_id: str,
    model: str = "",
    session_id: str = "",
) -> Optional[int]:
    """
    Deduct tokens from tenant balance and record usage.
    Returns remaining balance, or None if insufficient tokens.
    """
    with session_scope() as db:
        tenant = db.get(TenantTable, tenant_id)
        if tenant is None:
            logger.warning("consume_tokens: tenant not found: %s", tenant_id)
            return None
        if tenant.token_balance < tokens:
            logger.warning(
                "consume_tokens: insufficient balance for tenant %s: have=%d need=%d",
                tenant_id, tenant.token_balance, tokens,
            )
            return None

        tenant.token_balance -= tokens
        tenant.tokens_used_total += tokens
        remaining = tenant.token_balance

        db.add(TokenUsageTable(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            user_id=user_id,
            action=action,
            tokens_consumed=tokens,
            model_used=model,
            session_id=session_id,
        ))

    logger.info(
        "Tokens consumed: tenant=%s action=%s tokens=%d remaining=%d",
        tenant_id, action, tokens, remaining,
    )
    return remaining


def add_tokens(tenant_id: str, amount: int) -> Optional[int]:
    """Add tokens to tenant balance. Returns new balance or None if tenant not found."""
    with session_scope() as db:
        tenant = db.get(TenantTable, tenant_id)
        if tenant is None:
            return None
        tenant.token_balance += amount
        new_balance = tenant.token_balance

    logger.info("Tokens added: tenant=%s amount=%d new_balance=%d", tenant_id, amount, new_balance)
    return new_balance


def update_tenant_status(tenant_id: str, status: str) -> Optional[Dict[str, Any]]:
    """Change a tenant's status (active | suspended | archived).

    Returns the updated tenant dict, or None if the tenant is not found.
    Raises ValueError on an unknown status value.
    """
    if status not in ("active", "suspended", "archived"):
        raise ValueError(
            f"Invalid status: {status}. Must be one of: active, suspended, archived"
        )
    with session_scope() as db:
        tenant = db.get(TenantTable, tenant_id)
        if tenant is None:
            return None
        tenant.status = status
        return _tenant_to_dict(tenant)


def update_tenant_plan(tenant_id: str, plan: str) -> Optional[Dict[str, Any]]:
    """Change a tenant's plan and refresh their token balance to the new plan's allocation.

    Returns the updated tenant dict, or None if the tenant is not found.
    Raises ValueError if the plan name is invalid.
    """
    if plan not in PLAN_TOKEN_ALLOCATION:
        raise ValueError(f"Invalid plan: {plan}. Must be one of: {list(PLAN_TOKEN_ALLOCATION.keys())}")

    new_allocation = PLAN_TOKEN_ALLOCATION[plan]
    with session_scope() as db:
        tenant = db.get(TenantTable, tenant_id)
        if tenant is None:
            return None
        previous_plan = tenant.plan
        tenant.plan = plan
        tenant.token_balance = new_allocation
        result = _tenant_to_dict(tenant)

    logger.info(
        "Tenant plan updated: tenant=%s previous=%s new=%s tokens=%d",
        tenant_id, previous_plan, plan, new_allocation,
    )
    return result


def get_usage(tenant_id: str, days: int = 30) -> Dict[str, Any]:
    """Return usage statistics for the tenant over the given number of days."""
    cutoff = _utc_now() - timedelta(days=days)
    with session_scope() as db:
        # Total consumed in period
        total = db.scalar(
            select(func.coalesce(func.sum(TokenUsageTable.tokens_consumed), 0))
            .where(TokenUsageTable.tenant_id == tenant_id)
            .where(TokenUsageTable.created_at >= cutoff)
        ) or 0

        # Breakdown by action
        rows = db.execute(
            select(
                TokenUsageTable.action,
                func.sum(TokenUsageTable.tokens_consumed).label("total"),
                func.count(TokenUsageTable.id).label("count"),
            )
            .where(TokenUsageTable.tenant_id == tenant_id)
            .where(TokenUsageTable.created_at >= cutoff)
            .group_by(TokenUsageTable.action)
        ).all()

        breakdown = [
            {"action": row.action, "tokens": int(row.total), "count": int(row.count)}
            for row in rows
        ]

        # Get current balance
        tenant = db.get(TenantTable, tenant_id)
        balance = tenant.token_balance if tenant else 0

    return {
        "tenant_id": tenant_id,
        "period_days": days,
        "total_consumed": int(total),
        "current_balance": balance,
        "breakdown": breakdown,
    }


def check_token_balance(tenant_id: str) -> int:
    """Return the current token balance for a tenant. Returns 0 if not found."""
    with session_scope() as db:
        tenant = db.get(TenantTable, tenant_id)
        if tenant is None:
            return 0
        return tenant.token_balance


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _tenant_to_dict(row: TenantTable) -> Dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "slug": row.slug,
        "plan": row.plan,
        "token_balance": row.token_balance,
        "tokens_used_total": row.tokens_used_total,
        "status": row.status,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def get_tenant_user(user_id: str) -> Optional[Dict[str, Any]]:
    """Return a tenant user by ID."""
    with session_scope() as db:
        row = db.get(TenantUserTable, user_id)
        if row is None:
            return None
        return _user_to_dict(row)


def get_tenant_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Return a tenant user by email."""
    with session_scope() as db:
        row = db.scalar(
            select(TenantUserTable).where(TenantUserTable.email == email)
        )
        if row is None:
            return None
        return _user_to_dict(row)


def get_tenant_user_by_api_key_hash(key_hash: str) -> Optional[Dict[str, Any]]:
    """Return a tenant user by API key hash."""
    with session_scope() as db:
        row = db.scalar(
            select(TenantUserTable).where(TenantUserTable.api_key_hash == key_hash)
        )
        if row is None:
            return None
        return _user_to_dict(row)


def create_tenant_user(
    *,
    tenant_id: str,
    email: str,
    display_name: str,
    password_hash: str,
    role: str = "member",
    api_key_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new tenant user."""
    user_id = str(uuid.uuid4())
    with session_scope() as db:
        user = TenantUserTable(
            id=user_id,
            tenant_id=tenant_id,
            email=email,
            display_name=display_name,
            password_hash=password_hash,
            role=role,
            status="active",
            api_key_hash=api_key_hash,
        )
        db.add(user)

    logger.info("Tenant user created: id=%s email=%s tenant=%s role=%s", user_id, email, tenant_id, role)
    return {
        "id": user_id,
        "tenant_id": tenant_id,
        "email": email,
        "display_name": display_name,
        "role": role,
        "status": "active",
    }


def update_user_login(user_id: str) -> None:
    """Update last_login_at for a user."""
    with session_scope() as db:
        row = db.get(TenantUserTable, user_id)
        if row:
            row.last_login_at = _utc_now()


VALID_ROLES = ("member", "owner", "platform_admin")


def update_user_role(user_id: str, role: str) -> Optional[Dict[str, Any]]:
    """Set a user's role. Returns updated user dict or None if not found."""
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role}. Must be one of: {VALID_ROLES}")
    with session_scope() as db:
        row = db.get(TenantUserTable, user_id)
        if row is None:
            return None
        row.role = role
        result = _user_to_dict(row)
    logger.info("User role updated: user=%s role=%s", user_id, role)
    return result


def list_platform_admins() -> List[Dict[str, Any]]:
    """Return all users with role=platform_admin."""
    with session_scope() as db:
        rows = db.execute(
            select(TenantUserTable).where(TenantUserTable.role == "platform_admin")
        ).scalars().all()
        return [_user_to_dict(r) for r in rows]


def list_all_users() -> List[Dict[str, Any]]:
    """Return all users across all tenants (admin use only)."""
    with session_scope() as db:
        rows = db.execute(select(TenantUserTable)).scalars().all()
        return [_user_to_dict(r) for r in rows]


def update_user_api_key_hash(user_id: str, api_key_hash: str) -> None:
    """Update the API key hash for a user."""
    with session_scope() as db:
        row = db.get(TenantUserTable, user_id)
        if row:
            row.api_key_hash = api_key_hash


def _user_to_dict(row: TenantUserTable) -> Dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "email": row.email,
        "display_name": row.display_name,
        "password_hash": row.password_hash,
        "role": row.role,
        "status": row.status,
        "api_key_hash": row.api_key_hash,
        "must_change_password": bool(getattr(row, "must_change_password", False)),
        "last_login_at": row.last_login_at.isoformat() if row.last_login_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def set_must_change_password(user_id: str, flag: bool) -> None:
    """Set/clear the force-change-on-next-login flag for a user."""
    with session_scope() as db:
        row = db.get(TenantUserTable, user_id)
        if row is not None:
            row.must_change_password = bool(flag)


def update_user_password(user_id: str, password_hash: str):
    """Update a user's password hash and clear any force-change flag."""
    with session_scope() as db:
        row = db.get(TenantUserTable, user_id)
        if row is not None:
            row.password_hash = password_hash
            row.must_change_password = False
