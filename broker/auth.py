# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
from __future__ import annotations

import hmac
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Header, HTTPException

from .config import settings

logger = logging.getLogger("maestro.auth")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class AuthContext:
    user_id: str
    token_label: str
    created_at: datetime
    role: str = "member"  # member | owner | platform_admin | service | demo


def require_bearer_token(authorization: str = Header(default="")) -> AuthContext:
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        logger.warning("Auth rejected: missing bearer token")
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = authorization[len(prefix):].strip()
    if token == settings.broker_api_token:
        logger.info("Auth success: user=%s label=broker-admin", settings.bootstrap_user_id)
        return AuthContext(
            user_id=settings.bootstrap_user_id,
            token_label="broker-admin",
            created_at=utc_now(),
            role="platform_admin",
        )
    if token == settings.bridge_api_token:
        logger.info("Auth success: user=openwebui-bridge label=bridge-service")
        return AuthContext(
            user_id="openwebui-bridge",
            token_label="bridge-service",
            created_at=utc_now(),
            role="service",
        )
    # Public-demo token (try.vertirite.com). Only active when explicitly
    # configured; an empty demo_api_token means no demo role exists and the
    # behavior is identical to before this token was introduced. Constant-time
    # compare so the public demo key can't be probed via timing.
    if settings.demo_api_token and hmac.compare_digest(token, settings.demo_api_token):
        logger.info("Auth success: user=%s label=demo role=demo", settings.bootstrap_user_id)
        return AuthContext(
            user_id=settings.bootstrap_user_id,
            token_label="demo",
            created_at=utc_now(),
            role="demo",
        )

    # Try SaaS authentication (API keys and session tokens)
    try:
        from .saas_auth import authenticate_api_key_sync, authenticate_session_sync
        if token.startswith("mae_"):
            result = authenticate_api_key_sync(token)
            if result:
                logger.info("Auth success (SaaS API key): user=%s tenant=%s", result["user"]["email"], result["tenant"]["name"])
                return AuthContext(
                    user_id=result["user"]["id"],
                    token_label=f"saas-{result['tenant']['slug']}",
                    created_at=utc_now(),
                    role=result["user"].get("role", "member"),
                )
        elif token.startswith("mse_"):
            result = authenticate_session_sync(token)
            if result:
                logger.info("Auth success (SaaS session): user=%s tenant=%s", result["user"]["email"], result["tenant"]["name"])
                return AuthContext(
                    user_id=result["user"]["id"],
                    token_label=f"saas-{result['tenant']['slug']}",
                    created_at=utc_now(),
                    role=result["user"].get("role", "member"),
                )
    except Exception as e:
        logger.debug("SaaS auth attempt failed: %s", e)

    logger.warning("Auth rejected: invalid bearer token")
    raise HTTPException(status_code=403, detail="Invalid bearer token")


def require_platform_admin(authorization: str = Header(default="")) -> AuthContext:
    """FastAPI dependency that enforces platform_admin role.

    Accepts either a real user with role='platform_admin' (attributable) or
    the broker-admin service token (used by the PayPal webhook and internal
    tooling). Everyone else gets 403.
    """
    actor = require_bearer_token(authorization)
    if actor.role != "platform_admin":
        logger.warning(
            "Admin access denied: user=%s label=%s role=%s",
            actor.user_id, actor.token_label, actor.role,
        )
        raise HTTPException(status_code=403, detail="Platform admin access required")
    return actor


def require_operator_or_demo(authorization: str = Header(default="")) -> AuthContext:
    """FastAPI dependency for the demo's read + govern product surface.

    Authenticates like require_bearer_token, then allows ONLY the
    platform_admin and demo roles (everyone else → 403, mirroring how
    require_platform_admin excludes non-admins).

    The public-demo (try.vertirite.com) is a read+govern operator on
    synthetic data: it sees discovery/coverage/exposure and agent
    integrity, shows the deterministic identity and license tier, and can
    bring a finding under governance. It CANNOT inject findings, change
    licensing/identity, arm containment, or touch infrastructure — those
    stay on require_platform_admin (or require_not_demo). This dependency
    is exactly the overlap: the product surface the "Try live" demo must
    show, granted to the demo without any admin/infra power.
    """
    actor = require_bearer_token(authorization)
    if actor.role not in ("platform_admin", "demo"):
        logger.warning(
            "Operator/demo access denied: user=%s label=%s role=%s",
            actor.user_id, actor.token_label, actor.role,
        )
        raise HTTPException(
            status_code=403,
            detail="Operator or demo access required",
        )
    return actor


def require_governor(authorization: str = Header(default="")) -> AuthContext:
    """Gate 01 — the GOVERNOR trust domain, authenticated in isolation.

    This is a SEPARATE trust domain from ``broker_api_token`` /
    ``bridge_api_token`` / ``demo_api_token`` / SaaS keys. It authorizes the
    LOCAL mode-authority set-path (POST /v1/mode). Only a bearer equal to
    ``settings.governor_token`` is accepted; EVERY other caller — operator,
    platform_admin, agent/service, demo, bridge, and unauthenticated — is
    refused with 403. Because the agent plane never holds this credential,
    mode authority stays out-of-band: an agent (or anything it can reach)
    cannot loosen or lift its own containment.

    When ``governor_token`` is empty (the shipped default) the local set-path
    is not provisioned, so this dependency returns 503 for everyone — no one
    can set mode until a governor credential exists. Constant-time compare so
    the governor key can't be probed via timing.
    """
    if not settings.governor_token:
        raise HTTPException(status_code=503, detail="local mode authority not configured")

    prefix = "Bearer "
    if authorization.startswith(prefix):
        token = authorization[len(prefix):].strip()
        if hmac.compare_digest(token, settings.governor_token):
            logger.info("Governor auth success: label=governor")
            return AuthContext(
                user_id="governor",
                token_label="governor",
                created_at=utc_now(),
                role="governor",
            )

    logger.warning("Governor access denied: caller lacks the governor credential")
    raise HTTPException(status_code=403, detail="Governor credential required")


def require_not_demo(authorization: str = Header(default="")) -> AuthContext:
    """FastAPI dependency for infrastructure/dangerous endpoints.

    Authenticates like require_bearer_token, then REFUSES the public-demo
    role (try.vertirite.com console) with 403. Every non-demo caller
    (platform_admin, owner/member SaaS users, the bridge service) is
    unaffected — this only carves the demo out of the dangerous surface
    (command/terminal execution, filesystem access, the key vault, agent/
    fleet/self-heal runs). The demo keeps the read/govern product surface,
    which stays on require_bearer_token.
    """
    actor = require_bearer_token(authorization)
    if actor.role == "demo":
        logger.warning(
            "Demo access denied to restricted endpoint: user=%s label=%s",
            actor.user_id, actor.token_label,
        )
        raise HTTPException(
            status_code=403,
            detail="This action is not available in the demo",
        )
    return actor
