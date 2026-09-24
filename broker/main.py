# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
from __future__ import annotations

import collections
import logging
import time
from typing import Optional

import uvicorn
from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.responses import StreamingResponse

import os
from logging.handlers import RotatingFileHandler

# Log directory
_log_dir = os.path.join(os.path.dirname(__file__), "..", "..", ".data", "logs")
os.makedirs(_log_dir, exist_ok=True)
_log_file = os.path.join(_log_dir, "maestro.log")

# Console handler
_console = logging.StreamHandler()
_console.setLevel(logging.INFO)
_console.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s", datefmt="%H:%M:%S"))

# File handler — rotates at 5MB, keeps 5 backups
_file_handler = RotatingFileHandler(_log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
_file_handler.setLevel(logging.DEBUG)  # file gets EVERYTHING
_file_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
))

logging.basicConfig(level=logging.DEBUG, handlers=[_console, _file_handler])

# Quiet down noisy libraries
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.INFO)
logging.getLogger("hpack").setLevel(logging.WARNING)

logger = logging.getLogger("maestro")
logger.info("Logging to file: %s", _log_file)

from fastapi import File, Form, UploadFile

from .auth import (
    AuthContext,
    require_bearer_token,
    require_governor,
    require_not_demo,
    require_operator_or_demo,
    require_platform_admin,
)
from .plugins import get_all_plugins, get_plugin, load_plugins
from .config import settings
from .db import init_db
from .models import (
    AdminCreateTenantRequest,
    AdminDeclareHostRequest,
    AdminDismissFindingRequest,
    AdminGovernFindingRequest,
    AdminGrantRoleRequest,
    AdminUpdateHostRequest,
    AdminUpdatePlanRequest,
    AdminUpdateTenantRequest,
    AgentReportWitnessedRequest,
    ApprovalDecisionRequest,
    ApprovalRecord,
    AuthWhoAmIResponse,
    ChatMessageRecord,
    ChatRequest,
    ChatResponse,
    DiscoveryFlowIngestRequest,
    HealthResponse,
    ProjectCreateRequest,
    ProjectRecord,
    AuditEventRecord,
    SessionCreateRequest,
    SessionResponse,
    SurgeMode,
)
from .repository import (
    create_project_record,
    create_session_record,
    ensure_api_token_record,
    get_chat_history,
    get_session_or_none,
    list_approvals,
    list_audit_events,
    list_projects_records,
    update_approval_status,
    write_audit_event,
)
from .scheduler import (
    acknowledge_alert,
    get_alerts,
    start_scheduler,
    stop_scheduler,
)
from .dashboard import get_dashboard
from .keyvault import delete_key, get_key, list_keys, rotate_key, store_key
from .llm_connectors import PAID_MODELS_CATALOG, test_external_key
from .core_client import fetch_mode, is_surge_core_reachable, last_surge_core_mode, submit_approval_decision
from .tenant import (
    PLAN_LIST,
    PLAN_TOKEN_ALLOCATION,
    TOKEN_COSTS,
    VALID_ROLES,
    add_tokens,
    check_token_balance,
    consume_tokens,
    get_tenant,
    get_tenant_user_by_email,
    get_usage,
    list_all_users,
    list_platform_admins,
    update_tenant_plan,
    update_user_role,
)
from .saas_auth import (
    authenticate_api_key,
    authenticate_session,
    login as saas_login,
    register as saas_register,
)

_startup_time: float = 0.0

app = FastAPI(title="Vertirite Broker", version="0.2.0", docs_url=None, openapi_url=None, redoc_url=None)

# ---------------------------------------------------------------------------
# CORS — allow localhost origins for direct web shell access
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Served web console — the broker serves the operator UI as static files at
# /console, so any device on the customer's LAN (desktop, Mac, iPad/Galaxy
# tablet) reaches Vertirite in a browser with no install — the same renderer the
# desktop app uses, wrapped by a same-origin fetch bridge (web-bridge.js). This
# rides the broker's own port, so Vertirite places ONE configurable port on a
# customer machine, not a separate web server. See docs/DEPLOY-CUSTOMER-NODE.md.
# ---------------------------------------------------------------------------
_webconsole_dir = os.path.join(os.path.dirname(__file__), "webconsole")
if os.path.isdir(_webconsole_dir):
    app.mount("/console", StaticFiles(directory=_webconsole_dir, html=True), name="console")

    @app.get("/", include_in_schema=False)
    async def _root_to_console():
        return RedirectResponse(url="/console/")

# ---------------------------------------------------------------------------
# Surge agent platform — capability registry, dispatcher, /v1/surge/*
# Design: internal agent-node platform roadmap
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# In-memory rate limiter for chat endpoint (10 requests/min per session)
# ---------------------------------------------------------------------------
_RATE_LIMIT_MAX = 60  # increased from 10 — was too aggressive
_RATE_LIMIT_WINDOW = 60.0  # seconds
_chat_rate: dict[str, collections.deque] = {}


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    elapsed = time.time() - start
    if request.url.path != "/health":
        logger.info("%s %s → %d (%.2fs)", request.method, request.url.path, response.status_code, elapsed)
    return response


@app.exception_handler(Exception)
async def global_error_handler(request: Request, exc: Exception):
    logger.error("Unhandled error on %s %s: %s", request.method, request.url.path, exc, exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


def _redact_database_target(url: str) -> str:
    if "@" not in url:
        return url
    scheme, rest = url.split("://", 1)
    _, host_part = rest.split("@", 1)
    return f"{scheme}://***@{host_part}"


# Known placeholder values for the platform_admin token — the code default, the
# (now-removed) Docker ENV default, and the .env.example samples. A published
# image must never serve with any of these; auth.py maps broker_api_token ->
# platform_admin / full admin.
_PLACEHOLDER_ADMIN_TOKENS = frozenset({
    "", "change-me-in-production", "surge-operator-dev-token",
    "change-me-token", "change-me-broker-token",
})


def _assert_admin_token_configured() -> None:
    """Fail CLOSED in production if the platform_admin token is unset or a known
    placeholder. The Dockerfile ships NO default; the operator supplies one at
    runtime. Non-production keeps the code default so local runs work unchanged."""
    if settings.environment == "production" and (
        not settings.broker_api_token
        or settings.broker_api_token in _PLACEHOLDER_ADMIN_TOKENS
    ):
        raise RuntimeError(
            "Refusing to start: SURGE_OPERATOR_BROKER_API_TOKEN is unset or a known "
            "placeholder. It is the platform_admin credential — set it to a unique "
            "secret per deployment. In production the broker fails closed rather than "
            "serve a value that is public knowledge."
        )


@app.on_event("startup")
async def startup() -> None:
    global _startup_time
    _startup_time = time.time()
    _assert_admin_token_configured()
    init_db()
    # Gate 01 provisioning visibility — never let an ungoverned box look governed.
    if settings.governor_token:
        logger.info(
            "Gate 01: mode authority OPERATIONAL (governor credential provisioned)."
        )
    else:
        logger.warning(
            "Gate 01: mode authority NOT operational — no governor credential "
            "(SURGE_OPERATOR_GOVERNOR_TOKEN) provisioned. Running UNGOVERNED at "
            "default CONTROLLED; the local set-path (POST /v1/mode) returns 503 "
            "until a governor credential is provisioned out-of-band."
        )
    ensure_api_token_record(
        user_id=settings.bootstrap_user_id,
        token_label="broker-admin",
        token_hash=settings.broker_api_token,
    )
    ensure_api_token_record(
        user_id="openwebui-bridge",
        token_label="bridge-service",
        token_hash=settings.bridge_api_token,
    )
    start_scheduler()
    # Connected-tier intelligence metabolism — no-op unless a feed is configured.
    from .intelligence.feed import start_feed_refresher
    start_feed_refresher()
    # Context provisioning visibility — warn if serving sanitized fixtures.
    from .context import warn_if_fixtures
    warn_if_fixtures()
    load_plugins()


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    mode = await fetch_mode()
    uptime = time.time() - _startup_time if _startup_time else 0.0
    return HealthResponse(
        environment=settings.environment,
        database_target=_redact_database_target(settings.database_url),
        surge_core_mode=mode,
        surge_core_reachable=is_surge_core_reachable(),
        tunnel_alive=False,
        ollama_reachable=False,
        uptime_seconds=round(uptime, 1),
    )




@app.get("/v1/jwt-public-key")
async def jwt_public_key() -> Response:
    """Return the broker's JWT signing public key in PEM format.

    Fleet operators fetch this during agent install so each agent-noded
    can verify JWTs minted by the
    broker. Public material — no auth required."""
    from .jwt_keys import public_key_pem
    return Response(content=public_key_pem(), media_type="application/x-pem-file")


@app.get("/v1/me", response_model=AuthWhoAmIResponse)
async def whoami(actor: AuthContext = Depends(require_bearer_token)) -> AuthWhoAmIResponse:
    return AuthWhoAmIResponse(
        user_id=actor.user_id,
        token_label=actor.token_label,
        created_at=actor.created_at,
    )


class SetModeRequest(BaseModel):
    mode: str
    reason: Optional[str] = None


@app.get("/v1/mode")
async def get_mode(actor: AuthContext = Depends(require_bearer_token)) -> dict:
    """Read the current governance mode (gate 01).

    Any authenticated caller can READ the mode. Returns the effective mode (what
    the gate enforces), the local authoritative mode, surge-core reachability,
    and — when surge-core is reachable — the mode it reports. Setting the mode
    is a separate, auth-isolated path (POST /v1/mode, governor credential only).
    """
    from .governor_store import get_local_mode
    effective = await fetch_mode()
    local = get_local_mode()
    reachable = is_surge_core_reachable()
    governed = bool(settings.governor_token)
    out = {
        "effective": effective.value,
        "local": local.value,
        "surge_core_reachable": reachable,
        # Ungoverned must NOT look like a deliberate CONTROLLED. A reader can tell
        # "mode authority is not yet operating" (no governor credential) from
        # "operating and set to CONTROLLED" via these two fields.
        "governed": governed,
        "mode_authority": "operational" if governed else "unprovisioned",
    }
    sc_mode = last_surge_core_mode()
    if reachable and sc_mode is not None:
        out["surge_core_mode"] = sc_mode.value
    return out


@app.post("/v1/mode", dependencies=[Depends(require_governor)])
async def set_mode(
    body: SetModeRequest,
    actor: AuthContext = Depends(require_governor),
) -> dict:
    """Set the LOCAL authoritative governance mode (gate 01).

    Authorized ONLY through the governor trust domain (require_governor) — a
    credential the agent plane can never hold, keeping mode authority
    out-of-band. The change persists across restarts and is audit-logged.
    surge-core can still TIGHTEN the effective mode above what is set here, but
    can never loosen it.
    """
    from .governor_store import set_local_mode
    try:
        mode = SurgeMode(body.mode)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"invalid mode {body.mode!r}; must be one of {[m.value for m in SurgeMode]}",
        )
    set_local_mode(mode, actor=actor.user_id)
    summary = f"local governance mode set to {mode.value}"
    if body.reason:
        summary += f" — {body.reason.strip()[:200]}"
    write_audit_event(
        actor_id=actor.user_id,
        action="governor.set_mode",
        entity_type="surge_mode",
        entity_id="local",
        summary=summary,
    )
    effective = await fetch_mode()
    return {"effective": effective.value, "local": mode.value}


@app.get("/v1/entitlements")
async def get_entitlements(actor: AuthContext = Depends(require_bearer_token)):
    """What premium MODULES this node is licensed for. The broker (including the full
    governance surface) is BSL-open and free — governance is never gated; the license
    gates only the four premium modules (intelligence/enforcement/federation/
    vertical-packs). The console/web read this to show which modules are active."""
    from .licensing.license import KNOWN_FEATURES, entitled, license_state
    from .context import context_source

    st = license_state()
    features = {feat: entitled(feat) for feat in KNOWN_FEATURES}
    governed = bool(settings.governor_token)
    return {
        "features": features,
        "modules_active": [f for f, on in features.items() if on],
        "license_state": st.get("state") if isinstance(st, dict) else st,
        # Gate 01 provisioning visibility: false = mode authority is NOT yet
        # operational (no governor credential), so a CONTROLLED mode is a default,
        # not a deliberate posture. The console renders an "ungoverned" indicator.
        "governed": governed,
        "mode_authority": "operational" if governed else "unprovisioned",
        # Context provisioning visibility: "fixtures" = running on the sanitized
        # shipped placeholders, not real host-local operational context (set
        # SURGE_OPERATOR_CONTEXT_DIR). Same discipline as `governed` above.
        "context_source": context_source(),
    }


@app.get("/v1/audit/me", response_model=list[AuditEventRecord])
async def my_audit_events(
    limit: int = 100,
    action_prefix: Optional[str] = None,
    actor: AuthContext = Depends(require_bearer_token),
) -> list[AuditEventRecord]:
    """Per-tenant audit feed — every action surge or maestro took on this user's
    behalf. Differentiator from PR #19 launch-readiness Day 3.1.

    Filters by `actor.user_id`. Customers get full visibility into "what did
    the AI do for me this week" — surface this in the dashboard's Activity tab.
    """
    return list_audit_events(
        limit=min(limit, 500),
        action_prefix=action_prefix,
        actor_id=actor.user_id,
    )


@app.delete("/v1/me")
async def gdpr_delete_me(
    confirm: str = "",
    actor: AuthContext = Depends(require_bearer_token),
) -> dict:
    """GDPR-style cascade delete — wipes everything stored about the calling user.

    Targets: chat_messages, sessions, audit_events, approvals, execution_*,
    api_tokens, plus the corresponding tenant qdrant collection (best effort).

    Requires `?confirm=DELETE_MY_DATA` to prevent accidental wipes. Idempotent.

    Audit-doc Day 3.2 (launch-readiness PR #19).
    """
    if confirm != "DELETE_MY_DATA":
        raise HTTPException(
            status_code=400,
            detail="Add ?confirm=DELETE_MY_DATA to proceed; this is irreversible.",
        )
    from .repository import gdpr_delete_user_data
    summary = gdpr_delete_user_data(actor.user_id)
    write_audit_event(
        actor_id=actor.user_id,
        action="gdpr.delete",
        entity_type="user",
        entity_id=actor.user_id,
        summary=f"GDPR delete cascade: {summary}",
    )
    return {"ok": True, "user_id": actor.user_id, "deleted": summary}


# ---------------------------------------------------------------------------
# Peer-stream — surge speaks unprompted (full SSE design).
# /v1/peer-stream      GET  — SSE feed of unprompted messages for the user
# /v1/peer-stream/post POST — Brain pushes new messages here (internal auth)
# ---------------------------------------------------------------------------

@app.get("/v1/peer-stream")
async def peer_stream(
    actor: AuthContext = Depends(require_bearer_token),
):
    """SSE stream of unprompted Surge messages for the calling user.
    Replays any undelivered messages first, then live-tails new ones."""
    from .peer_stream import stream_for_user
    return StreamingResponse(
        stream_for_user(actor.user_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


_BRAIN_PEER_TOKEN = os.environ.get("SURGE_OPERATOR_BRAIN_PEER_TOKEN", "")


@app.post("/v1/peer-stream/post")
async def peer_stream_post(request: Request):
    """Brain (or any internal pusher) sends an unprompted message here.
    Auth: bearer token must equal SURGE_OPERATOR_BRAIN_PEER_TOKEN env var."""
    auth = request.headers.get("authorization", "")
    if not _BRAIN_PEER_TOKEN or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing brain peer token")
    if auth.split(None, 1)[1].strip() != _BRAIN_PEER_TOKEN:
        raise HTTPException(status_code=401, detail="invalid brain peer token")

    body = await request.json()
    user_id = body.get("user_id")
    tenant_id = body.get("tenant_id", "creator")
    content = (body.get("content") or "").strip()
    trigger_kind = body.get("trigger_kind", "manual")

    if not user_id or not content:
        raise HTTPException(status_code=400, detail="user_id and content required")
    if len(content) > 4000:
        raise HTTPException(status_code=400, detail="content > 4000 chars")
    if trigger_kind not in {"escalation", "anomaly", "fleet_drift", "manual"}:
        raise HTTPException(status_code=400, detail="invalid trigger_kind")

    from .peer_stream import post_unprompted
    result = await post_unprompted(
        user_id=user_id,
        tenant_id=tenant_id,
        content=content,
        trigger_kind=trigger_kind,
    )
    return result


# ---------------------------------------------------------------------------
# Customer support tickets
# The `surge-support` persona is used by triage.
# ---------------------------------------------------------------------------
class TicketCreateReq(BaseModel):
    product: str = "general"
    subject: str
    body: str
    priority: str = "medium"


class TicketReplyReq(BaseModel):
    reply: str
    new_status: str = "resolved"


@app.post("/v1/tickets")
async def tickets_create(
    req: TicketCreateReq,
    actor: AuthContext = Depends(require_bearer_token),
) -> dict:
    """User-facing: customer reports an issue. Triage runs in background."""
    from .support import create_ticket
    return await create_ticket(
        user_id=actor.user_id,
        tenant_id="creator",  # multi-tenant rollout will fill this from actor
        product=req.product,
        subject=req.subject,
        body=req.body,
        priority=req.priority,
    )


@app.get("/v1/tickets/me")
async def tickets_me(
    actor: AuthContext = Depends(require_bearer_token),
) -> dict:
    """User-facing: list this user's own tickets."""
    from .support import list_tickets
    rows = await list_tickets(user_id=actor.user_id, limit=100)
    return {"tickets": rows, "count": len(rows)}


@app.get("/v1/tickets/{ticket_id}")
async def tickets_get(
    ticket_id: str,
    actor: AuthContext = Depends(require_bearer_token),
) -> dict:
    from .support import get_ticket
    t = await get_ticket(ticket_id)
    if not t:
        raise HTTPException(status_code=404, detail="ticket not found")
    if t["user_id"] != actor.user_id and getattr(actor, "role", "member") != "platform_admin":
        raise HTTPException(status_code=403, detail="not your ticket")
    return t


@app.get("/v1/admin/tickets")
async def tickets_admin_list(
    status: Optional[str] = None,
    limit: int = 50,
    actor: AuthContext = Depends(require_platform_admin),
) -> dict:
    from .support import list_tickets
    rows = await list_tickets(status=status, limit=min(limit, 200))
    return {"tickets": rows, "count": len(rows)}


@app.post("/v1/admin/tickets/{ticket_id}/reply")
async def tickets_admin_reply(
    ticket_id: str,
    req: TicketReplyReq,
    actor: AuthContext = Depends(require_platform_admin),
) -> dict:
    from .support import operator_reply
    t = await operator_reply(ticket_id, req.reply, req.new_status)
    if not t:
        raise HTTPException(status_code=404, detail="ticket not found")
    return t


# ---------------------------------------------------------------------------
# Fallback ticket channels — used WHEN AI / in-app path is broken.
# These are unauthenticated by design: if a user can't log in, they still
# need a way to reach us. Rate-limited per source IP inside support_inbound.
# Cross-repo: node-01 mail-watcher posts to /v1/tickets/inbound-email;
# Twilio webhook (when provisioned) posts to /v1/tickets/inbound-sms.
# ---------------------------------------------------------------------------
class PublicTicketReq(BaseModel):
    email: str = ""
    product: str = "general"
    subject: str
    body: str


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.post("/v1/tickets/public")
async def tickets_public(req: PublicTicketReq, request: Request) -> dict:
    """Unauthenticated web-form ticket. Lives at /status's no-JS form."""
    from .support_inbound import inbound_create_ticket
    return await inbound_create_ticket(
        channel="web_form",
        sender_identity=req.email,
        source_ip=_client_ip(request),
        product=req.product,
        subject=req.subject,
        body=req.body,
    )


@app.post("/v1/tickets/inbound-email")
async def tickets_inbound_email(request: Request) -> dict:
    """Called by node-01 mail-watcher with raw RFC822 in the body."""
    from .support_inbound import parse_email_to_ticket_args, inbound_create_ticket
    raw = (await request.body()).decode("utf-8", errors="replace")
    if not raw.strip():
        raise HTTPException(status_code=400, detail="empty email body")
    args = parse_email_to_ticket_args(raw)
    return await inbound_create_ticket(
        source_ip=_client_ip(request),
        **args,
    )


@app.post("/v1/tickets/inbound-sms")
async def tickets_inbound_sms(request: Request) -> dict:
    """Twilio webhook — application/x-www-form-urlencoded with From + Body."""
    from .support_inbound import inbound_create_ticket
    form = await request.form()
    sender = str(form.get("From") or "").strip()
    body = str(form.get("Body") or "").strip()
    if not sender or not body:
        raise HTTPException(status_code=400, detail="missing From or Body")
    return await inbound_create_ticket(
        channel="sms",
        sender_identity=sender,
        source_ip=_client_ip(request),
        subject=f"SMS from {sender}",
        body=body,
    )




def _check_chat_rate_limit(session_id: str) -> None:
    """Enforce max 10 chat requests per minute per session."""
    now = time.time()
    if session_id not in _chat_rate:
        _chat_rate[session_id] = collections.deque()
    window = _chat_rate[session_id]
    # Evict entries older than the window
    while window and window[0] <= now - _RATE_LIMIT_WINDOW:
        window.popleft()
    if len(window) >= _RATE_LIMIT_MAX:
        logger.warning("Rate limit hit for session %s (%d requests in window)", session_id, len(window))
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: max {_RATE_LIMIT_MAX} chat requests per minute per session.",
        )
    window.append(now)


def _resolve_tenant_id_from_actor(actor: AuthContext) -> Optional[str]:
    """Resolve tenant_id for a given actor. Returns None for bootstrap users."""
    from .tenant import get_tenant_user
    # Bootstrap tokens don't have tenant context — skip metering
    if actor.token_label in ("broker-admin", "bridge-service"):
        return None
    # For SaaS users the user_id maps to a TenantUser
    user = get_tenant_user(actor.user_id)
    if user:
        return user["tenant_id"]
    return None


def _check_tenant_active_or_raise(tenant_id: Optional[str], action_label: str = "action") -> None:
    """Enforce tenant suspension at the policy gate.

    Raises 403 if the tenant exists and is not active. Skips silently
    for bootstrap users (tenant_id is None — no tenant scope). Writes a
    tenant.action_denied audit row on denial so the ledger shows what
    was attempted.

    action_label is included in the audit summary so each denied path
    is distinguishable (chat / agent / search / voice / document / etc.).
    """
    if tenant_id is None:
        return  # bootstrap/dev user — no tenant scope
    from .tenant import assert_tenant_active, TenantSuspended
    try:
        assert_tenant_active(tenant_id)
    except LookupError:
        # Tenant referenced but not found — leave the original endpoint
        # to surface this; suspension check shouldn't 404 a path that
        # might still reach a non-tenant-scoped result.
        return
    except TenantSuspended as exc:
        write_audit_event(
            actor_id=f"tenant:{tenant_id}",
            action="tenant.action_denied",
            entity_type="tenant",
            entity_id=tenant_id,
            summary=f"{action_label} denied — tenant is {exc.status} (not active)",
            tenant_id=tenant_id,
        )
        raise HTTPException(
            status_code=403,
            detail=f"Tenant {tenant_id} is {exc.status}; {action_label} not accepted",
        )


def _check_token_balance_or_raise(tenant_id: Optional[str]) -> None:
    """Check tenant active + token balance.

    Suspension takes precedence over balance: a suspended tenant gets a
    403 explaining the suspension, not a 402 that would mislead them
    into thinking they need to buy tokens.

    Skips if no tenant context.
    """
    _check_tenant_active_or_raise(tenant_id, action_label="action")
    if tenant_id is None:
        return  # bootstrap/dev user — no metering
    balance = check_token_balance(tenant_id)
    if balance <= 0:
        raise HTTPException(
            status_code=402,
            detail="Token balance exhausted. Please upgrade your plan or purchase more tokens.",
        )


def _consume_chat_tokens(
    tenant_id: Optional[str],
    user_id: str,
    session_id: str,
    used_llm: bool = False,
    model: str = "",
) -> None:
    """Consume tokens for a chat action. Skips if no tenant context."""
    if tenant_id is None:
        return
    action = "chat_llm" if used_llm else "chat"
    cost = TOKEN_COSTS.get(action, 1)
    consume_tokens(
        tenant_id=tenant_id,
        action=action,
        tokens=cost,
        user_id=user_id,
        model=model,
        session_id=session_id,
    )















class AgentRequest(BaseModel):
    """Mirrors app-service `app.py:AgentRequest` — 1:1 passthrough plus
    the 2026-05-03 disable_tools field (app-service#4)."""
    goal: str
    persona: str = "operator"
    tier: str = "surge-operator"
    max_turns: int = 10
    max_tool_calls: int = 20
    max_seconds: int = 90
    disable_tools: bool = False




@app.get("/v1/alerts/settings")
async def alert_settings(actor: AuthContext = Depends(require_bearer_token)):
    from .notifications import get_alert_settings_full
    return await get_alert_settings_full()


@app.post("/v1/alerts/test")
async def alert_test(actor: AuthContext = Depends(require_bearer_token)):
    from .notifications import send_test_alert
    return await send_test_alert()


@app.get("/v1/alerts/delivery-log")
async def alert_delivery_log(actor: AuthContext = Depends(require_bearer_token)):
    from .notifications import get_delivery_log
    return get_delivery_log()


@app.get("/v1/slash-commands")
async def list_slash_commands(q: str = "", actor: AuthContext = Depends(require_bearer_token)):
    from .slash_commands import filter_slash_commands, get_slash_commands
    if q:
        return filter_slash_commands(q, role=actor.role)
    return get_slash_commands(role=actor.role)




@app.get("/v1/context")
async def get_context_info(actor: AuthContext = Depends(require_bearer_token)):
    from .context import get_context_files, load_context
    ctx = load_context()
    return {
        "files": get_context_files(),
        "total_chars": len(ctx),
    }


@app.post("/v1/context/reload")
async def reload_context_endpoint(actor: AuthContext = Depends(require_bearer_token)):
    from .context import reload_context
    ctx = reload_context()
    return {"status": "reloaded", "total_chars": len(ctx)}


@app.get("/v1/projects", response_model=list[ProjectRecord])
async def list_projects(actor: AuthContext = Depends(require_bearer_token)) -> list[ProjectRecord]:
    return list_projects_records()


@app.post("/v1/projects", response_model=ProjectRecord, status_code=201)
async def create_project(
    project: ProjectCreateRequest,
    actor: AuthContext = Depends(require_bearer_token),
) -> ProjectRecord:
    return create_project_record(project)


@app.get("/v1/audit-events", response_model=list[AuditEventRecord])
async def get_audit_events(
    limit: int = 50,
    actor: AuthContext = Depends(require_bearer_token),
) -> list[AuditEventRecord]:
    return list_audit_events(limit=min(limit, 200))


@app.get("/v1/approvals", response_model=list[ApprovalRecord])
async def get_approvals(
    limit: int = 50,
    actor: AuthContext = Depends(require_bearer_token),
) -> list[ApprovalRecord]:
    return list_approvals(limit=min(limit, 200))


@app.post("/v1/approvals/{approval_id}/approve", response_model=ApprovalRecord)
async def approve_request(
    approval_id: str,
    body: ApprovalDecisionRequest,
    actor: AuthContext = Depends(require_bearer_token),
) -> ApprovalRecord:
    # Record-only: the broker authorizes, records, and audits the decision;
    # it does NOT execute. Executing an approved action is the integrating
    # system's responsibility. update_approval_status persists the decision
    # (status + notes) and writes the "approval.approved" audit event.
    record = update_approval_status(
        approval_id,
        status="approved",
        decision_notes=body.decision_notes,
    )
    if record is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    if record.surge_task_id:
        await submit_approval_decision(record.surge_task_id)
    return record


@app.post("/v1/approvals/{approval_id}/deny", response_model=ApprovalRecord)
async def deny_request(
    approval_id: str,
    body: ApprovalDecisionRequest,
    actor: AuthContext = Depends(require_bearer_token),
) -> ApprovalRecord:
    record = update_approval_status(
        approval_id,
        status="denied",
        decision_notes=body.decision_notes,
    )
    if record is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    return record


# ---------------------------------------------------------------------------
# Fleet Health & Alerts endpoints
# ---------------------------------------------------------------------------

@app.get("/v1/fleet/alerts")
async def fleet_alerts(actor: AuthContext = Depends(require_bearer_token)):
    return get_alerts(acknowledged=False)


@app.post("/v1/fleet/alerts/{alert_id}/acknowledge")
async def fleet_acknowledge_alert(
    alert_id: str,
    actor: AuthContext = Depends(require_bearer_token),
):
    if not acknowledge_alert(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "acknowledged", "alert_id": alert_id}


# ---------------------------------------------------------------------------
# Dashboard / Mission Control endpoint
# ---------------------------------------------------------------------------

@app.get("/v1/dashboard")
async def dashboard(actor: AuthContext = Depends(require_bearer_token)):
    return await get_dashboard(startup_time=_startup_time)


# ---------------------------------------------------------------------------
# Key Vault endpoints
# ---------------------------------------------------------------------------

@app.get("/v1/keys")
async def vault_list_keys(actor: AuthContext = Depends(require_not_demo)):
    """List all stored API keys — metadata only, no decrypted values."""
    return list_keys()


@app.post("/v1/keys", status_code=201)
async def vault_store_key(
    request: Request,
    actor: AuthContext = Depends(require_not_demo),
):
    """Store a new API key in the encrypted vault.

    Accepts BYOK-style: {"provider": "openai", "api_key": "sk-...", "label": "My Key"}
    Or legacy-style: {"key_name": ..., "key_type": ..., "value": ...}
    """
    body = await request.json()

    # BYOK-style payload
    provider = body.get("provider")
    api_key = body.get("api_key")
    if provider and api_key:
        label = body.get("label", provider)
        key_name = f"byok-{provider}"
        # Delete existing key for this provider first (upsert behavior)
        delete_key(key_name)
        try:
            result = store_key(key_name=key_name, key_type=provider, value=api_key, scope="byok")
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        masked = _mask_api_key(api_key)
        return {"status": "saved", "provider": provider, "label": label, "masked_key": masked}

    # Legacy-style payload
    key_name = body.get("key_name")
    key_type = body.get("key_type")
    value = body.get("value")
    scope = body.get("scope", "full")
    if not key_name or not key_type or not value:
        raise HTTPException(status_code=400, detail="key_name, key_type, and value are required (or use provider + api_key)")
    try:
        result = store_key(key_name=key_name, key_type=key_type, value=value, scope=scope)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result


@app.delete("/v1/keys/{key_name}")
async def vault_delete_key(
    key_name: str,
    actor: AuthContext = Depends(require_not_demo),
):
    """Delete a key from the vault."""
    if not delete_key(key_name):
        raise HTTPException(status_code=404, detail="Key not found")
    return {"status": "deleted", "key_name": key_name}


@app.post("/v1/keys/{key_name}/rotate")
async def vault_rotate_key(
    key_name: str,
    request: Request,
    actor: AuthContext = Depends(require_not_demo),
):
    """Rotate (update) an existing key's value."""
    body = await request.json()
    new_value = body.get("value")
    if not new_value:
        raise HTTPException(status_code=400, detail="value is required")
    if not rotate_key(key_name, new_value):
        raise HTTPException(status_code=404, detail="Key not found")
    return {"status": "rotated", "key_name": key_name}


@app.delete("/v1/keys/byok/{provider}")
async def vault_delete_byok_key(
    provider: str,
    actor: AuthContext = Depends(require_not_demo),
):
    """Delete a BYOK key by provider name (openai, anthropic, google)."""
    key_name = f"byok-{provider}"
    if not delete_key(key_name):
        raise HTTPException(status_code=404, detail=f"No BYOK key found for {provider}")
    return {"status": "deleted", "provider": provider}


@app.post("/v1/keys/{provider}/test")
async def vault_test_key(
    provider: str,
    actor: AuthContext = Depends(require_not_demo),
):
    """Test if the stored BYOK key for a provider works."""
    api_key = get_key(provider)
    if not api_key:
        raise HTTPException(status_code=404, detail=f"No key stored for {provider}")
    result = await test_external_key(provider, api_key)
    return result


# ---------------------------------------------------------------------------
# Plugin endpoints
# ---------------------------------------------------------------------------

@app.get("/v1/plugins")
async def list_plugins(actor: AuthContext = Depends(require_bearer_token)):
    """List all loaded plugins with their commands."""
    plugins = get_all_plugins()
    return {
        "status": "ok",
        "count": len(plugins),
        "plugins": plugins,
    }


@app.get("/v1/plugins/{name}")
async def get_plugin_details(
    name: str,
    actor: AuthContext = Depends(require_bearer_token),
):
    """Get details for a specific plugin by name."""
    plugin = get_plugin(name)
    if plugin is None:
        raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found")
    return {"status": "ok", "plugin": plugin}


# ---------------------------------------------------------------------------
# Voice endpoints
# ---------------------------------------------------------------------------

# In-memory store for audio blobs (for /v1/voice/audio/{id} retrieval)
_voice_audio_cache: dict[str, bytes] = {}
















# ---------------------------------------------------------------------------
# Document endpoints
# ---------------------------------------------------------------------------

@app.post("/v1/documents/read")
async def documents_read(
    request: Request,
    actor: AuthContext = Depends(require_bearer_token),
):
    """Read any supported document format (PDF, DOCX, XLSX, PPTX, CSV, etc.)."""
    from .documents import read_document
    body = await request.json()
    path = body.get("path", "").strip()
    if not path:
        raise HTTPException(status_code=400, detail="path is required")
    result = await read_document(path)
    if result["status"] != "ok":
        raise HTTPException(status_code=400, detail=result.get("content", "Could not read file"))

    # Token metering for document read
    tenant_id = _resolve_tenant_id_from_actor(actor)
    if tenant_id:
        consume_tokens(
            tenant_id=tenant_id,
            action="document",
            tokens=TOKEN_COSTS["document"],
            user_id=actor.user_id,
            model="",
        )

    return result


@app.get("/v1/documents/formats")
async def documents_formats(actor: AuthContext = Depends(require_bearer_token)):
    """Return supported document formats and which libraries are available."""
    from .documents import get_supported_formats
    return get_supported_formats()


# ---------------------------------------------------------------------------
# SaaS Auth endpoints (public — no auth required)
# ---------------------------------------------------------------------------

@app.post("/v1/auth/register")
async def auth_register(request: Request):
    """Create a new account and tenant."""
    body = await request.json()
    email = body.get("email", "").strip()
    password = body.get("password", "")
    display_name = body.get("display_name", "").strip()
    tenant_name = body.get("tenant_name", "").strip()

    if not email or not password or not display_name:
        raise HTTPException(status_code=400, detail="email, password, and display_name are required")
    if not tenant_name:
        raise HTTPException(status_code=400, detail="tenant_name is required")

    try:
        result = await saas_register(
            email=email,
            password=password,
            display_name=display_name,
            tenant_name=tenant_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


@app.post("/v1/auth/login")
async def auth_login(request: Request):
    """Login with email and password."""
    body = await request.json()
    email = body.get("email", "").strip()
    password = body.get("password", "")

    if not email or not password:
        raise HTTPException(status_code=400, detail="email and password are required")

    try:
        result = await saas_login(email=email, password=password)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    return result


@app.get("/v1/plans")
async def list_plans():
    """List available plans and pricing (public endpoint)."""
    return {"plans": PLAN_LIST}


@app.post("/v1/admin/update-plan")
async def admin_update_plan(
    request: AdminUpdatePlanRequest,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Change a tenant's plan by user email. Platform-admin only.

    Invoked by the PayPal billing webhook on subscription activation/cancellation,
    by platform admins through the Ops Center plans page, and via slash commands.
    """
    if request.plan not in PLAN_TOKEN_ALLOCATION:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan: {request.plan}. Valid plans: {list(PLAN_TOKEN_ALLOCATION.keys())}",
        )

    user = get_tenant_user_by_email(request.email)
    if user is None:
        raise HTTPException(status_code=404, detail=f"No user with email {request.email}")

    previous = get_tenant(user["tenant_id"])
    previous_plan = previous["plan"] if previous else "unknown"

    updated = update_tenant_plan(user["tenant_id"], request.plan)
    if updated is None:
        raise HTTPException(status_code=404, detail="Tenant not found")

    paypal_note = f" paypal_subscription_id={request.paypal_subscription_id}" if request.paypal_subscription_id else ""
    write_audit_event(
        actor_id=actor.user_id,
        action="plan.updated",
        entity_type="tenant",
        entity_id=updated["id"],
        summary=f"Plan changed for {request.email}: {previous_plan} → {request.plan}{paypal_note}",
    )
    return {"tenant": updated, "previous_plan": previous_plan}


@app.get("/v1/admin/tenants")
async def admin_list_tenants(
    actor: AuthContext = Depends(require_platform_admin),
):
    """List all tenants with plan and token balance. Platform-admin only."""
    from .tenant import TenantTable, TenantUserTable
    from .db import session_scope
    from sqlalchemy import select

    with session_scope() as db:
        tenant_rows = db.execute(select(TenantTable)).scalars().all()
        user_rows = db.execute(select(TenantUserTable)).scalars().all()
        users_by_tenant: dict[str, list[dict]] = {}
        for u in user_rows:
            users_by_tenant.setdefault(u.tenant_id, []).append({"email": u.email, "role": u.role})

        tenants = [
            {
                "id": t.id,
                "name": t.name,
                "slug": t.slug,
                "plan": t.plan,
                "token_balance": t.token_balance,
                "tokens_used_total": t.tokens_used_total,
                "status": t.status,
                "users": users_by_tenant.get(t.id, []),
                "created_at": t.created_at.isoformat() if t.created_at else None,
            }
            for t in tenant_rows
        ]
    return {"tenants": tenants}


@app.post("/v1/admin/tenants", status_code=201)
async def admin_create_tenant(
    request: AdminCreateTenantRequest,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Create a new tenant. Platform-admin only.

    Body: {name, plan?}
    Returns 201 with the created tenant record.
    """
    from .tenant import create_tenant, PLAN_TOKEN_ALLOCATION

    plan = (request.plan or "free").lower()
    if plan not in PLAN_TOKEN_ALLOCATION:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan: {plan}. Must be one of: {sorted(PLAN_TOKEN_ALLOCATION.keys())}",
        )

    name = (request.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required and must be non-empty")

    try:
        tenant = create_tenant(name=name, plan=plan)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    write_audit_event(
        actor_id=actor.user_id,
        action="tenant.create",
        entity_type="tenant",
        entity_id=tenant["id"],
        summary=f"Tenant created: {name} (plan={plan})",
        tenant_id=tenant["id"],
    )
    return tenant


@app.get("/v1/admin/tenants/{tenant_id}")
async def admin_get_tenant(
    tenant_id: str,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Fetch a single tenant by ID. Platform-admin only."""
    from .tenant import TenantTable, TenantUserTable
    from .db import session_scope
    from sqlalchemy import select

    with session_scope() as db:
        row = db.get(TenantTable, tenant_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"Tenant not found: {tenant_id}")
        users = db.execute(
            select(TenantUserTable).where(TenantUserTable.tenant_id == tenant_id)
        ).scalars().all()
        return {
            "id": row.id,
            "name": row.name,
            "slug": row.slug,
            "plan": row.plan,
            "token_balance": row.token_balance,
            "tokens_used_total": row.tokens_used_total,
            "status": row.status,
            "users": [{"email": u.email, "role": u.role, "status": u.status} for u in users],
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }


@app.patch("/v1/admin/tenants/{tenant_id}")
async def admin_update_tenant(
    tenant_id: str,
    request: AdminUpdateTenantRequest,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Update tenant fields. Platform-admin only.

    Mutable: name, plan, status, token_balance (operator override).
    Slug is immutable once set.
    """
    from .tenant import TenantTable, PLAN_TOKEN_ALLOCATION
    from .db import session_scope

    if request.plan is not None and request.plan not in PLAN_TOKEN_ALLOCATION:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan: {request.plan}. Must be one of: {sorted(PLAN_TOKEN_ALLOCATION.keys())}",
        )
    if request.status is not None and request.status not in ("active", "suspended", "archived"):
        raise HTTPException(
            status_code=400,
            detail="status must be one of: active, suspended, archived",
        )

    changes: list[str] = []
    with session_scope() as db:
        row = db.get(TenantTable, tenant_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"Tenant not found: {tenant_id}")
        if request.name is not None and request.name.strip() and request.name != row.name:
            changes.append(f"name: {row.name!r} -> {request.name!r}")
            row.name = request.name.strip()
        if request.plan is not None and request.plan != row.plan:
            changes.append(f"plan: {row.plan} -> {request.plan}")
            row.plan = request.plan
        if request.status is not None and request.status != row.status:
            changes.append(f"status: {row.status} -> {request.status}")
            row.status = request.status
        if request.token_balance is not None and request.token_balance != row.token_balance:
            changes.append(f"token_balance: {row.token_balance} -> {request.token_balance}")
            row.token_balance = int(request.token_balance)

        updated = {
            "id": row.id,
            "name": row.name,
            "slug": row.slug,
            "plan": row.plan,
            "token_balance": row.token_balance,
            "tokens_used_total": row.tokens_used_total,
            "status": row.status,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }

    if changes:
        write_audit_event(
            actor_id=actor.user_id,
            action="tenant.update",
            entity_type="tenant",
            entity_id=tenant_id,
            summary=f"Tenant updated ({', '.join(changes)})",
            tenant_id=tenant_id,
        )
    return updated


@app.delete("/v1/admin/tenants/{tenant_id}", status_code=200)
async def admin_archive_tenant(
    tenant_id: str,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Soft-delete a tenant by setting status=archived. Platform-admin only.

    Records remain in the database to preserve audit-chain integrity. To
    fully delete a tenant (e.g. GDPR right-to-erasure), run the
    data-deletion script documented in docs/SECURITY.md — it tombstones
    audit rows rather than truncating them.
    """
    from .tenant import TenantTable
    from .db import session_scope

    with session_scope() as db:
        row = db.get(TenantTable, tenant_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"Tenant not found: {tenant_id}")
        if row.status == "archived":
            return {"id": tenant_id, "status": "archived", "already_archived": True}
        previous_status = row.status
        row.status = "archived"

    write_audit_event(
        actor_id=actor.user_id,
        action="tenant.archive",
        entity_type="tenant",
        entity_id=tenant_id,
        summary=f"Tenant archived (was {previous_status})",
        tenant_id=tenant_id,
    )
    return {"id": tenant_id, "status": "archived", "previous_status": previous_status}


# ─── Fleet manifest (Pillar A: declared coverage) ──────────────────────────
#
# Endpoints under /v1/admin/fleet/hosts let platform admins manage the
# persisted inventory of customer fleet hosts. Lifecycle is declared →
# governed → archived. See broker/fleet_manifest.py for the model.

@app.get("/v1/admin/fleet/hosts")
async def admin_list_fleet_hosts(
    actor: AuthContext = Depends(require_platform_admin),
    include_archived: bool = False,
):
    """List declared fleet hosts. Platform-admin only."""
    from .fleet_manifest import list_hosts
    hosts = list_hosts(tenant_id=None, include_archived=include_archived)
    return {"hosts": hosts}


@app.post("/v1/admin/fleet/hosts", status_code=201)
async def admin_declare_fleet_host(
    request: AdminDeclareHostRequest,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Declare a new fleet host (lifecycle=declared).

    Body: {hostname, role?, tags?, notes?, tenant_id?}
    Returns 201 + the new host record.
    """
    from .fleet_manifest import declare_host

    tenant_id = request.tenant_id
    if not tenant_id:
        # Platform admins manage cross-tenant; require explicit scoping.
        raise HTTPException(
            status_code=400,
            detail="tenant_id is required in the request body (platform admin must scope explicitly)",
        )
    try:
        host = declare_host(
            tenant_id=tenant_id,
            hostname=request.hostname,
            role=(request.role or "production-core"),
            tags=request.tags or [],
            notes=request.notes or "",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    write_audit_event(
        actor_id=actor.user_id,
        action="fleet.host_declared",
        entity_type="fleet_host",
        entity_id=host["id"],
        summary=f"Fleet host declared: {host['hostname']} (role={host['role']}, tenant={tenant_id})",
        tenant_id=tenant_id,
    )
    return host


@app.get("/v1/admin/fleet/hosts/{host_id}")
async def admin_get_fleet_host(
    host_id: str,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Fetch a single fleet host."""
    from .fleet_manifest import get_host
    host = get_host(host_id)
    if host is None:
        raise HTTPException(status_code=404, detail=f"Fleet host not found: {host_id}")
    return host


@app.patch("/v1/admin/fleet/hosts/{host_id}")
async def admin_update_fleet_host(
    host_id: str,
    request: AdminUpdateHostRequest,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Update a fleet host (role, tags, notes, or lifecycle_status)."""
    from .fleet_manifest import update_host, get_host

    before = get_host(host_id)
    if before is None:
        raise HTTPException(status_code=404, detail=f"Fleet host not found: {host_id}")

    changes: list[str] = []
    if request.role is not None and request.role != before["role"]:
        changes.append(f"role: {before['role']} -> {request.role}")
    if request.tags is not None and request.tags != before["tags"]:
        changes.append(f"tags: {before['tags']} -> {request.tags}")
    if request.notes is not None and (request.notes or "") != (before["notes"] or ""):
        changes.append("notes updated")
    if request.lifecycle_status is not None and request.lifecycle_status != before["lifecycle_status"]:
        changes.append(f"lifecycle: {before['lifecycle_status']} -> {request.lifecycle_status}")

    try:
        updated = update_host(
            host_id,
            role=request.role,
            tags=request.tags,
            notes=request.notes,
            lifecycle_status=request.lifecycle_status,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if updated is None:
        raise HTTPException(status_code=404, detail=f"Fleet host not found: {host_id}")

    if changes:
        write_audit_event(
            actor_id=actor.user_id,
            action="fleet.host_updated",
            entity_type="fleet_host",
            entity_id=host_id,
            summary=f"Fleet host {before['hostname']} updated ({', '.join(changes)})",
            tenant_id=before["tenant_id"],
        )
    return updated


@app.delete("/v1/admin/fleet/hosts/{host_id}", status_code=200)
async def admin_archive_fleet_host(
    host_id: str,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Soft-archive a fleet host (lifecycle_status=archived). Audit row preserved."""
    from .fleet_manifest import archive_host, get_host

    before = get_host(host_id)
    if before is None:
        raise HTTPException(status_code=404, detail=f"Fleet host not found: {host_id}")
    if before["lifecycle_status"] == "archived":
        return {"id": host_id, "status": "archived", "already_archived": True}

    archived = archive_host(host_id)
    write_audit_event(
        actor_id=actor.user_id,
        action="fleet.host_archived",
        entity_type="fleet_host",
        entity_id=host_id,
        summary=f"Fleet host {before['hostname']} archived (was {before['lifecycle_status']})",
        tenant_id=before["tenant_id"],
    )
    return {"id": host_id, "status": "archived", "previous_status": before["lifecycle_status"]}


@app.get("/v1/admin/fleet/coverage")
async def admin_fleet_coverage(
    actor: AuthContext = Depends(require_platform_admin),
):
    """Coverage Map summary.

    Returns counts (total_declared, governed, declared_not_governed,
    archived, coverage_pct) plus the full host list, each annotated with
    a category. This is the data the dashboard Coverage Map renders.
    """
    from .fleet_manifest import coverage_summary
    return coverage_summary()


@app.post("/v1/agent/heartbeat/{host_id}", status_code=200)
async def agent_heartbeat(
    host_id: str,
    actor: AuthContext = Depends(require_bearer_token),
):
    """agent-noded posts here every ~30s.

    First successful heartbeat flips lifecycle declared→governed. We don't
    require platform_admin here — any bearer-authenticated caller can
    heartbeat (the assumption is the agent's mTLS-bound cert IS its
    identity; this endpoint validates the bearer JWT minted from the cert).

    Suspended/archived tenants are 403'd here — a suspended tenant should
    not accrue governance attestations.
    """
    from .fleet_manifest import record_heartbeat, get_host
    from .tenant import assert_tenant_active, TenantSuspended

    # Look up the host first to find its tenant, then gate.
    host = get_host(host_id)
    if host is None:
        raise HTTPException(status_code=404, detail=f"Fleet host not found: {host_id}")
    try:
        assert_tenant_active(host["tenant_id"])
    except TenantSuspended as exc:
        write_audit_event(
            actor_id=actor.user_id or f"agent:{host_id}",
            action="tenant.action_denied",
            entity_type="fleet_host",
            entity_id=host_id,
            summary=(
                f"Heartbeat denied for {host['hostname']} — tenant {exc.tenant_id} "
                f"is {exc.status} (not active)"
            ),
            tenant_id=host["tenant_id"],
        )
        raise HTTPException(
            status_code=403,
            detail=f"Tenant {exc.tenant_id} is {exc.status}; heartbeats are not accepted",
        )

    row = record_heartbeat(host_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Fleet host not found: {host_id}")
    # Only write an audit event on the FIRST heartbeat (lifecycle transition).
    # Subsequent heartbeats are pure liveness pings — auditing every one
    # would flood the ledger.
    if row["governed_at"] and (
        row["governed_at"] == row["agentd_last_heartbeat"]
    ):
        write_audit_event(
            actor_id=actor.user_id or f"agent:{host_id}",
            action="fleet.host_governed",
            entity_type="fleet_host",
            entity_id=host_id,
            summary=f"Fleet host {row['hostname']} promoted to governed (first agent heartbeat)",
            tenant_id=host["tenant_id"],
        )
    return {"id": host_id, "lifecycle_status": row["lifecycle_status"], "heartbeat_recorded_at": row["agentd_last_heartbeat"]}


# ─── Discovery — Witnessed but unsanctioned (Pillar B) ─────────────────────
#
# agent-noded posts findings to POST /v1/agent/witnessed. Operators
# review them on /dashboard/admin → Witnessed and can:
#   • acknowledge  — "I see it, decision pending"
#   • declare-host — "bring it under governance" (creates fleet_hosts row)
#   • dismiss      — false positive or out of scope

@app.post("/v1/agent/witnessed", status_code=201)
async def agent_report_witnessed(
    request: AgentReportWitnessedRequest,
    actor: AuthContext = Depends(require_bearer_token),
):
    """agent-noded posts each discovery match here.

    The broker verifies the source_host_id is a real fleet host, looks up
    the pattern_id in the catalog, and upserts the finding. Repeated
    witnesses of the same (source_host, target, pattern) increment
    occurrence_count.

    We don't write an audit event per witness — that would flood the
    ledger on a busy fleet. Audit events fire on operator actions
    (acknowledge, dismiss, declare-host).
    """
    from .discovery.findings import report_finding
    from .fleet_manifest import get_host
    from .tenant import assert_tenant_active, TenantSuspended

    src = get_host(request.source_host_id)
    if src is None:
        raise HTTPException(status_code=404, detail=f"source_host_id not found: {request.source_host_id}")

    try:
        assert_tenant_active(src["tenant_id"])
    except TenantSuspended as exc:
        write_audit_event(
            actor_id=actor.user_id or f"agent:{request.source_host_id}",
            action="tenant.action_denied",
            entity_type="witnessed_finding",
            entity_id=request.source_host_id,
            summary=(
                f"Witnessed report denied — tenant {exc.tenant_id} is {exc.status} "
                f"(source_host={src['hostname']}, pattern={request.pattern_id})"
            ),
            tenant_id=src["tenant_id"],
        )
        raise HTTPException(
            status_code=403,
            detail=f"Tenant {exc.tenant_id} is {exc.status}; witnessed reports are not accepted",
        )

    try:
        finding = report_finding(
            tenant_id=src["tenant_id"],
            source_host_id=request.source_host_id,
            target_hostname=request.target_hostname.strip(),
            signal_type=request.signal_type,
            pattern_id=request.pattern_id,
            evidence=request.evidence or {},
            confidence_override=request.confidence,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return finding


@app.get("/v1/admin/witnessed")
async def admin_list_witnessed(
    actor: AuthContext = Depends(require_platform_admin),
    status: Optional[str] = None,
    limit: int = 200,
):
    """List witnessed findings. Optionally filter by status (comma-separated)."""
    from .discovery.findings import list_findings
    status_filter = [s.strip() for s in status.split(",")] if status else None
    findings = list_findings(tenant_id=None, status_filter=status_filter, limit=limit)
    return {"findings": findings}


@app.get("/v1/admin/witnessed/summary")
async def admin_witnessed_summary(
    actor: AuthContext = Depends(require_platform_admin),
):
    """Counts by status — for the dashboard header pill."""
    from .discovery.findings import summary
    return summary()


@app.get("/v1/discovery/coverage")
async def discovery_coverage(
    actor: AuthContext = Depends(require_operator_or_demo),
    tenant_id: Optional[str] = None,
):
    """Coverage Map — SEEN minus GOVERNED.

    Rolls witnessed findings into a coverage ratio + the ungoverned worklist
    (AI services first). The day-one exposure map; see docs/STRATEGY.md.
    """
    from .discovery.coverage import coverage_map
    return coverage_map(tenant_id=tenant_id)


@app.post("/v1/discovery/coverage/snapshot")
async def discovery_coverage_snapshot(
    actor: AuthContext = Depends(require_platform_admin),
    tenant_id: Optional[str] = None,
):
    """Capture ONE coverage snapshot for the exposure-over-time trend (Wave A #2)."""
    from .discovery.coverage_trend import capture_coverage_snapshot
    return capture_coverage_snapshot(tenant_id or "default")


@app.get("/v1/discovery/coverage/trend")
async def discovery_coverage_trend(
    actor: AuthContext = Depends(require_bearer_token),
    tenant_id: Optional[str] = None,
    limit: int = 90,
):
    """The tenant's coverage snapshots oldest->newest for the trend chart (Wave A #2)."""
    from .discovery.coverage_trend import get_coverage_trend
    return get_coverage_trend(tenant_id or "default", limit)


@app.get("/v1/discovery/exposure.json")
async def discovery_exposure_json(
    actor: AuthContext = Depends(require_operator_or_demo),
    tenant_id: Optional[str] = None,
):
    """FREE-TIER exposure report (§8.1) — canonical JSON body (fingerprint source).

    NOT gated by 'govern': seeing and exporting your exposure is always free."""
    from .discovery.coverage import coverage_map
    from .reports.exposure import build_exposure_payload
    coverage = coverage_map(tenant_id=tenant_id)
    return build_exposure_payload(coverage, tenant_label=tenant_id, generated_by=actor.user_id)


@app.get("/v1/discovery/exposure.pdf")
async def discovery_exposure_pdf(
    actor: AuthContext = Depends(require_operator_or_demo),
    tenant_id: Optional[str] = None,
):
    """FREE-TIER exposure report (§8.1) — the exportable PDF a CISO/board/auditor reads.

    NOT gated by 'govern': seeing and exporting your exposure is always free."""
    from .discovery.coverage import coverage_map
    from .reports.exposure import build_and_render_exposure
    coverage = coverage_map(tenant_id=tenant_id)
    pdf = build_and_render_exposure(coverage, tenant_label=tenant_id, generated_by=actor.user_id)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="vertirite-exposure-report.pdf"'},
    )


@app.get("/v1/compliance/pack")
async def compliance_pack(
    actor: AuthContext = Depends(require_platform_admin),
    tenant_id: Optional[str] = None,
    framework: str = "soc2",
    days: int = 90,
):
    """Framework-mapped, tamper-evident compliance evidence bundle (Wave A #3)."""
    from .reports.compliance import generate_compliance_pack
    return generate_compliance_pack(tenant_id or "default", framework, days)


@app.post("/v1/containment/classify")
async def containment_classify(
    payload: dict,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Explain containment: which chokepoints (egress / irreversible /
    credential) a (capability, params) crosses, and the floor it imposes.
    The gate applies this automatically; this endpoint makes it inspectable.
    See docs/STRATEGY.md + docs/CONTAINMENT.md.
    """
    from .containment import classify, contained_class
    cap = (payload or {}).get("capability", "")
    params = (payload or {}).get("params", {}) or {}
    chokepoints = classify(cap, params)
    floor = contained_class(chokepoints)
    return {
        "capability": cap,
        "chokepoints": sorted(c.value for c in chokepoints),
        "contained_class": floor.value if floor else None,
    }


# ---------------------------------------------------------------------------
# Break Detection (P1) — agent behavioral integrity.
# docs/FEATURE-break-detection.md + docs/PR-break-detection-p1.md
# ---------------------------------------------------------------------------

@app.get("/v1/integrity/breaks")
async def integrity_list_breaks(
    actor: AuthContext = Depends(require_operator_or_demo),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    tenant_id: Optional[str] = None,
    limit: int = 200,
):
    """List detected agent breaks. Filter by status (comma-separated) / severity."""
    from .protection.breaks import events
    status_filter = [s.strip() for s in status.split(",")] if status else None
    return {"breaks": events.list_breaks(tenant_id=tenant_id, status_filter=status_filter,
                                         severity=severity, limit=limit)}


@app.get("/v1/integrity/summary")
async def integrity_summary(
    actor: AuthContext = Depends(require_operator_or_demo),
    tenant_id: Optional[str] = None,
):
    """Break counts by status + open-by-severity — the dashboard header."""
    from .protection.breaks import events
    return events.summary(tenant_id=tenant_id)


@app.get("/v1/integrity/agents/{actor_id}/baseline")
async def integrity_agent_baseline(
    actor_id: str,
    actor: AuthContext = Depends(require_operator_or_demo),
    tenant_id: str = "default",
):
    """The learned-normal behavioral profile for one agent (404 if never seen)."""
    from .protection.breaks import baseline
    bl = baseline.get(tenant_id, actor_id)
    if bl is None:
        raise HTTPException(status_code=404,
                            detail=f"No baseline for agent {actor_id!r} in tenant {tenant_id!r}")
    return bl


@app.post("/v1/integrity/breaks/{break_id}/acknowledge")
async def integrity_ack_break(
    break_id: str,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Expected/benign — folds the behavior into the baseline (confirm-and-learn)."""
    from .protection.breaks import events
    updated = events.acknowledge_break(break_id, actor.user_id)
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Break not found: {break_id}")
    write_audit_event(actor_id=actor.user_id, action="break.acknowledged",
                      entity_type="break_event", entity_id=break_id,
                      summary=f"Break acknowledged: {updated['reason']} ({updated['actor_id']})",
                      tenant_id=updated["tenant_id"])
    return updated


@app.post("/v1/integrity/breaks/{break_id}/dismiss")
async def integrity_dismiss_break(
    break_id: str,
    payload: dict,
    actor: AuthContext = Depends(require_platform_admin),
):
    """False positive — also folds so it stops re-firing. Body: {reason}."""
    from .protection.breaks import events
    updated = events.dismiss_break(break_id, actor.user_id, (payload or {}).get("reason", ""))
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Break not found: {break_id}")
    write_audit_event(actor_id=actor.user_id, action="break.dismissed",
                      entity_type="break_event", entity_id=break_id,
                      summary=f"Break dismissed: {updated['reason']} ({updated['actor_id']})",
                      tenant_id=updated["tenant_id"])
    return updated


@app.post("/v1/integrity/breaks/{break_id}/confirm")
async def integrity_confirm_break(
    break_id: str,
    payload: dict = Body(default=None),
    actor: AuthContext = Depends(require_platform_admin),
):
    """Confirm the break is real — NOT folded (P3 would trigger containment). Body: {note}."""
    from .protection.breaks import events
    updated = events.confirm_break(break_id, actor.user_id, (payload or {}).get("note", ""))
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Break not found: {break_id}")
    write_audit_event(actor_id=actor.user_id, action="break.confirmed",
                      entity_type="break_event", entity_id=break_id,
                      summary=f"Break CONFIRMED real: {updated['reason']} ({updated['actor_id']})",
                      tenant_id=updated["tenant_id"])
    return updated


@app.post("/v1/integrity/classify")
async def integrity_classify(
    payload: dict,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Dry-run the break rules against a hypothetical action, recording nothing.
    Body: {tenant_id, actor_id, capability, params}. Inspectable, like
    /v1/containment/classify."""
    from .protection.breaks import detector
    from .protection.breaks.baseline import Baseline, get as baseline_get
    from .containment import classify, external_destinations
    tenant_id = (payload or {}).get("tenant_id") or "default"
    actor_id = (payload or {}).get("actor_id") or "unknown"
    capability = (payload or {}).get("capability", "")
    params = (payload or {}).get("params", {}) or {}
    raw = baseline_get(tenant_id, actor_id)  # read-only; does not create a row
    if raw:
        bl = Baseline(tenant_id, actor_id, set(raw["capabilities"]),
                      set(raw["egress_destinations"]), set(raw["active_hours"]),
                      raw["credential_seen"], raw["irreversible_seen"],
                      raw["action_count"], raw["state"])
    else:
        bl = Baseline(tenant_id, actor_id)
    cps = sorted(c.value for c in classify(capability, params))
    dests = external_destinations(capability, params)
    breaks = detector.evaluate_attempt(bl, capability, cps, dests)
    return {
        "capability": capability,
        "chokepoints": cps,
        "baseline_state": bl.state,
        "would_break": [{"reason": b.reason, "severity": b.severity,
                         "title": b.title, "target": b.target} for b in breaks],
    }


# --- Runtime toggles (operator interface; override wins over env, no restart) ---

@app.get("/v1/integrity/config")
async def integrity_get_config(actor: AuthContext = Depends(require_platform_admin)):
    """Runtime state of the break-detection toggles (enabled + source override|env)."""
    from .protection.breaks import runtime_config
    return runtime_config.status()


@app.post("/v1/integrity/config")
async def integrity_set_config(payload: dict, actor: AuthContext = Depends(require_platform_admin)):
    """Operator toggle: body {break_detection?: bool, detect_contain?: bool}. The
    override wins over the env default and takes effect within seconds — no restart."""
    from .protection.breaks import runtime_config
    changed = []
    for key in ("break_detection", "detect_contain"):
        if key in (payload or {}):
            runtime_config.set_flag(key, bool(payload[key]), actor=actor.user_id)
            changed.append(f"{key}={bool(payload[key])}")
    if changed:
        write_audit_event(actor_id=actor.user_id, action="integrity.config",
                          entity_type="runtime_flag", entity_id=",".join(changed)[:64],
                          summary=f"Break-detection toggle set: {', '.join(changed)}", tenant_id=None)
    return runtime_config.status()


# --- Detect -> contain (P3) ---

@app.get("/v1/integrity/agents/{actor_id}/containment")
async def integrity_get_containment(
    actor_id: str,
    actor: AuthContext = Depends(require_platform_admin),
    tenant_id: str = "default",
):
    """The agent's active containment override (P3), or null if none."""
    from .protection.breaks import containment_state as cs
    return {"containment": cs.get_state(tenant_id, actor_id)}


@app.post("/v1/integrity/agents/{actor_id}/containment")
async def integrity_set_containment(
    actor_id: str,
    payload: dict,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Operator sets/raises an agent's containment override. Body:
    {tenant_id, mode, reason}. mode: elevated_gated | elevated_high_stakes | quarantined."""
    from .protection.breaks import containment_state as cs
    tenant_id = (payload or {}).get("tenant_id") or "default"
    mode = (payload or {}).get("mode", "")
    reason = (payload or {}).get("reason", "")
    if mode not in cs.MODES or mode == "none":
        raise HTTPException(status_code=400,
            detail="mode must be one of: elevated_gated, elevated_high_stakes, quarantined")
    st = cs.set_state(tenant_id, actor_id, mode, reason, set_by=actor.user_id)
    write_audit_event(actor_id=actor.user_id, action="containment.set",
                      entity_type="agent_containment", entity_id=actor_id,
                      summary=f"Agent {actor_id} containment -> {mode}: {reason[:80]}",
                      tenant_id=tenant_id)
    return st


@app.post("/v1/integrity/agents/{actor_id}/containment/clear")
async def integrity_clear_containment(
    actor_id: str,
    payload: dict = Body(default=None),
    actor: AuthContext = Depends(require_platform_admin),
):
    """Lift an agent's containment override."""
    from .protection.breaks import containment_state as cs
    tenant_id = (payload or {}).get("tenant_id") or "default"
    st = cs.clear_state(tenant_id, actor_id, cleared_by=actor.user_id)
    if st is None:
        raise HTTPException(status_code=404, detail=f"No containment state for agent {actor_id}")
    write_audit_event(actor_id=actor.user_id, action="containment.cleared",
                      entity_type="agent_containment", entity_id=actor_id,
                      summary=f"Agent {actor_id} containment lifted",
                      tenant_id=tenant_id)
    return st


# --- Compliance evidence (pillar 3) ---

@app.get("/v1/compliance/controls")
async def compliance_controls(actor: AuthContext = Depends(require_platform_admin)):
    """The control-mapping catalog: each Vertirite primitive -> framework controls
    (OWASP LLM Top-10, MITRE ATLAS, HIPAA, SOX, NIST 800-82, IEC 62443)."""
    from .compliance import frameworks
    return frameworks.catalog()


@app.get("/v1/compliance/report")
async def compliance_report(
    actor: AuthContext = Depends(require_platform_admin),
    tenant_id: str = "default",
    since: Optional[str] = None,
    until: Optional[str] = None,
):
    """On-node compliance-evidence report for a tenant + window, mapped to controls
    and sealed with a content hash. `since`/`until` are ISO-8601 timestamps."""
    from datetime import datetime
    from .compliance import report as creport

    def _parse(s):
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            raise HTTPException(status_code=400, detail=f"bad timestamp: {s!r}")

    return creport.build_signed_report(tenant_id, since=_parse(since), until=_parse(until))


@app.post("/v1/discovery/ingest/egress")
async def discovery_ingest_egress(
    payload: dict,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Ingest egress observations (or a raw squid/proxy log) -> network findings
    that flow into the Coverage Map. The on-prem egress/DNS sensor tier.
    Body: {observations: [{destination, source}], tenant_id} OR {raw_log, tenant_id}.
    """
    from .discovery import network_sensor as ns
    tenant_id = (payload or {}).get("tenant_id") or "default"
    obs = (payload or {}).get("observations")
    raw = (payload or {}).get("raw_log")
    if raw and not obs:
        obs = ns.parse_squid_log(raw)
    return ns.analyze_egress(obs or [], tenant_id=tenant_id)


@app.post("/v1/discovery/ingest/dns")
async def discovery_ingest_dns(
    payload: dict,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Ingest DNS queries (or a raw resolver log) -> network findings.
    Body: {queries: [{domain, source}], tenant_id} OR {raw_log, tenant_id}.
    """
    from .discovery import network_sensor as ns
    tenant_id = (payload or {}).get("tenant_id") or "default"
    q = (payload or {}).get("queries")
    raw = (payload or {}).get("raw_log")
    if raw and not q:
        q = ns.parse_dns_log(raw)
    return ns.analyze_dns(q or [], tenant_id=tenant_id)


@app.get("/v1/discovery/sources")
async def discovery_sources(
    tenant_id: Optional[str] = None,
    actor: AuthContext = Depends(require_operator_or_demo),
):
    """The sensor catalog (where Vertirite can be pointed, across all three
    network planes) + derived status: which feeds are live, which planes are
    covered, whether the current view is partial, and what to add next. Powers
    the onboarding 'where do I point you?' panel + the partial-view banner.

    Also carries ``intelligence`` — the perishable-catalog freshness/decay state
    (Mechanism #1) so the desktop can show how fresh the brain is."""
    from .discovery import sensors
    from .intelligence.catalog import catalog_status
    out = sensors.discovery_sources(tenant_id=tenant_id)
    out["intelligence"] = catalog_status(tenant_id)
    return out


@app.post("/v1/discovery/ingest/flow")
async def discovery_ingest_flow(
    payload: DiscoveryFlowIngestRequest,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Ingest connection FLOWS — the east-west / internal tier the egress + DNS
    sensors are blind to (PLC<->PLC, server<->server, internal inference boxes,
    loopback IPC). Fed by a NetFlow/IPFIX/sFlow collector, a switch SPAN/TAP via
    Zeek (conn.log), or an on-host eBPF agent. Each flow is recorded with its
    network plane (north-south | east-west | host-local).
    Body: {flows: [{src, dst, dst_port, proto}], tenant_id} OR
          {raw_log, format: "zeek", tenant_id}.

    The body is a typed model: a non-numeric `dst_port` or a mistyped `flows`
    field is rejected with 422 rather than crashing (500) or being silently
    ingested as a junk finding.
    """
    from .discovery import network_sensor as ns
    tenant_id = payload.tenant_id or "default"
    # Emit canonical field names (src/dst/dst_port) that analyze_flow reads,
    # preserving any extra collector keys; alias inputs are already normalized.
    flows = (
        [f.model_dump(exclude_none=True) for f in payload.flows]
        if payload.flows is not None
        else None
    )
    if payload.raw_log and not flows:
        flows = ns.parse_zeek_conn(payload.raw_log)
    return ns.analyze_flow(flows or [], tenant_id=tenant_id)


@app.post("/v1/discovery/findings/{finding_id}/govern")
async def discovery_govern_finding(
    finding_id: str,
    payload: dict | None = None,
    actor: AuthContext = Depends(require_operator_or_demo),
):
    """Bring a discovered artifact under Vertirite's watch — universal for any
    finding type (network / process / dns). Marks it governed; it leaves the
    ungoverned gap and joins the governed registry (GET /v1/discovery/governed).
    """
    from .discovery.findings import get_finding, mark_governed
    finding = get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")
    if finding["status"] == "governed":
        return finding
    ref = (payload or {}).get("governed_host_id") or finding.get("target_hostname") or finding_id
    updated = mark_governed(finding_id, governed_host_id=ref)
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")
    return updated


@app.get("/v1/discovery/findings/{finding_id}/remediation")
async def discovery_finding_remediation(
    finding_id: str,
    actor: AuthContext = Depends(require_operator_or_demo),
):
    """"Show me HOW" — the exact, copy-paste BLOCK + ROUTE change for this
    finding, tailored to its network plane (docs/GOVERNANCE-ENFORCEMENT.md
    Stage 1). Advisory: we generate the change; the operator/connector applies
    it. Vertirite is the brain, not the wire."""
    from .discovery.findings import get_finding
    from .discovery.remediation import guidance_for
    finding = get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")
    return guidance_for(finding)


@app.get("/v1/discovery/governed")
async def discovery_list_governed(
    actor: AuthContext = Depends(require_operator_or_demo),
    tenant_id: Optional[str] = None,
    limit: int = 200,
):
    """The governed registry — artifacts now under Vertirite's watch."""
    from .discovery.findings import list_findings
    return {"governed": list_findings(tenant_id=tenant_id,
                                      status_filter=["governed"], limit=limit)}


# --- Mechanism #1: the perishable intelligence catalog ---
# docs/PROTECTION-MODEL.md. Install a signed catalog (Sovereign/air-gap path) and
# inspect its freshness/decay state. Bundles are minted offline by `vertirite-intel`.


@app.post("/v1/intelligence/catalog/install")
async def intelligence_install(
    payload: dict,
    tenant_id: str = "default",
    actor: AuthContext = Depends(require_platform_admin),
):
    """Install a SIGNED intelligence catalog bundle. Verified against the
    configured mint public key + must be a strictly newer version than the
    installed one; otherwise 400 (the prior catalog is retained). Body = the
    signed bundle JSON produced by `vertirite-intel mint`."""
    from .intelligence import catalog as cat
    from .licensing.license import entitled
    if not entitled("intelligence"):
        raise HTTPException(status_code=403, detail="intelligence not licensed (no valid license grants 'intelligence')")
    try:
        installed = cat.install(tenant_id, payload or {})
    except cat.CatalogError as e:
        raise HTTPException(status_code=400, detail=f"catalog rejected: {e}")
    write_audit_event(
        actor_id=actor.user_id, action="intelligence.catalog.install",
        entity_type="intelligence", entity_id=str(installed.catalog_version),
        tenant_id=tenant_id,
        summary=(f"installed catalog v{installed.catalog_version} "
                 f"({len(installed.patterns)} patterns) expires {installed.expires_at.isoformat()}"),
    )
    return cat.catalog_status(tenant_id)


@app.get("/v1/intelligence/catalog")
async def intelligence_status(
    tenant_id: Optional[str] = None,
    actor: AuthContext = Depends(require_platform_admin),
):
    """The current freshness/decay state of the tenant's intelligence catalog —
    FRESH / STALE / EXPIRED / TAMPERED / baseline-only, with version + age."""
    from .intelligence.catalog import catalog_status
    return catalog_status(tenant_id)


@app.get("/v1/protection/identity")
async def protection_identity(
    actor: AuthContext = Depends(require_operator_or_demo),
):
    """This broker's install identity + the health of its phone-home channel
    (Mechanism #2, docs/PROTECTION-MODEL.md). ``suppressed: true`` means the
    governance feed has been unreachable past the threshold — a sign the
    instance is being hidden from governance."""
    from .config import settings
    from .protection import binding, identity
    rec = identity.get_instance()
    canary = rec.get("canary", "")
    return {
        "instance_id": rec["instance_id"],
        "canary_masked": (canary[:6] + "…") if canary else "",
        "created_at": rec["created_at"].isoformat() if rec.get("created_at") else None,
        "beacon": identity.beacon_state(settings.protection_suppression_threshold),
        "binding": binding.binding_state(),  # Mechanism #3 — behavioral binding
    }


@app.get("/v1/license")
async def license_status(
    actor: AuthContext = Depends(require_operator_or_demo),
):
    """The installed license: state (valid/expired/none), SKU, granted features,
    expiry. Gates premium features (docs/PROTECTION-MODEL.md §3)."""
    from .licensing.license import license_state
    return license_state()


@app.post("/v1/license/install")
async def license_install(
    payload: dict,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Install a SIGNED license (minted by `vertirite-license`). Verified against
    the configured license public key; rejected → 400, prior license retained."""
    from .licensing import license as lic
    try:
        return lic.install(payload or {})
    except lic.LicenseError as e:
        raise HTTPException(status_code=400, detail=f"license rejected: {e}")


@app.post("/v1/protection/rebind")
async def protection_rebind(
    actor: AuthContext = Depends(require_platform_admin),
):
    """Re-bind this install to its CURRENT environment fingerprint (Mechanism #3).
    Use after a legitimate migration to clear a foreign-environment state."""
    from .protection import binding
    return binding.rebind()


@app.post("/v1/protection/beacon")
async def protection_send_beacon(
    tenant_id: str = "default",
    actor: AuthContext = Depends(require_platform_admin),
):
    """Send the metadata-only fleet beacon NOW (Mechanism #2 PR2). Same payload
    the Connected cadence sends; exposed for on-demand + verification. Returns the
    send result (sent / disabled / unreachable / rejected) + any signals the
    control plane raised."""
    from .protection.beacon import send_beacon
    return send_beacon(tenant_id)


@app.post("/v1/intelligence/catalog/refresh")
async def intelligence_refresh(
    tenant_id: str = "default",
    actor: AuthContext = Depends(require_platform_admin),
):
    """Connected-tier metabolism: pull the latest signed catalog from the feed
    NOW and install it if newer (PR3). Same draw-down the background refresher
    runs on a cadence; exposed for on-demand refresh + verification. Returns the
    pull result (installed / up_to_date / unreachable / rejected / disabled)."""
    from .intelligence.feed import pull_once
    return pull_once(tenant_id)


# --- Stage 2 enforcement: ROUTE (forward-proxy) + BLOCK (connectors) ---
# docs/GOVERNANCE-ENFORCEMENT.md. These make govern actually enforceable instead
# of advisory. The proxy is OFF by default (settings.proxy_enabled, fail-safe).


@app.api_route("/v1/proxy/openai/{path:path}", methods=["POST"])
async def proxy_openai(
    path: str,
    request: Request,
    actor: AuthContext = Depends(require_bearer_token),
):
    """Stage 2 ROUTE primitive — OpenAI-compatible forward-proxy.

    Point an app's SDK ``base_url`` at ``http://<broker>/v1/proxy/openai/v1``;
    every call is policy-gated + audited, then forwarded to the real provider.
    Blocked calls never leave the building (403). Disabled by default (503 until
    an operator enables it). See docs/GOVERNANCE-ENFORCEMENT.md Stage 2.
    """
    from .enforcement import proxy as fwd
    body = await request.body()
    try:
        status, headers, content = await fwd.forward_openai(
            path=path, method=request.method, headers=dict(request.headers),
            body=body, actor_id=actor.user_id, tenant_id=None,
        )
    except fwd.ProxyDisabled as e:
        raise HTTPException(status_code=503, detail=str(e))
    except fwd.ProxyBlocked as e:
        raise HTTPException(status_code=403, detail={
            "error": "blocked_by_vertirite",
            "reason": e.decision.reason,
            "decision": e.decision.action,
        })
    return Response(content=content, status_code=status, headers=headers)


@app.get("/v1/enforcement/policy")
async def enforcement_policy(
    destination: str,
    model: str = "",
    actor: AuthContext = Depends(require_platform_admin),
):
    """Inspect the ROUTE/BLOCK decision for a (destination, model) without making
    a call — makes Stage 2 policy auditable, like /v1/containment/classify."""
    from .enforcement.policy import decide
    d = decide(destination=destination, model=model)
    return {
        "destination": destination, "model": model, "action": d.action,
        "allowed": d.allowed, "sanctioned": d.sanctioned,
        "is_threat": d.is_threat, "reason": d.reason,
    }


@app.get("/v1/enforcement/connectors")
async def enforcement_connectors(
    actor: AuthContext = Depends(require_platform_admin),
):
    """The registered BLOCK appliers. Default posture is advisory (dry-run)."""
    from .enforcement import connectors
    return {"connectors": connectors.list_connectors(), "default_posture": "advisory"}


@app.post("/v1/enforcement/connectors/{name}/apply")
async def enforcement_connector_apply(
    name: str,
    payload: dict,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Apply (or dry-run) a BLOCK via a connector. ``dry_run`` defaults TRUE — the
    advisory connector never mutates a device; real connectors require explicit
    ``dry_run=false`` AND operator authorization."""
    from .enforcement import connectors
    c = connectors.get(name)
    if c is None:
        raise HTTPException(status_code=404, detail=f"Unknown connector: {name}")
    target = (payload or {}).get("target", "")
    plane = (payload or {}).get("plane", "north-south")
    dry_run = (payload or {}).get("dry_run", True)
    if not target:
        raise HTTPException(status_code=422, detail="target is required")
    result = c.apply(target=target, plane=plane, dry_run=bool(dry_run))
    write_audit_event(
        actor_id=actor.user_id, action="enforcement.connector.apply",
        entity_type="enforcement", entity_id=target,
        summary=f"connector={name} applied={result.applied} change={result.change}",
    )
    return {
        "connector": result.connector, "applied": result.applied,
        "change": result.change, "detail": result.detail,
    }


@app.get("/v1/admin/witnessed/{finding_id}")
async def admin_get_witnessed(
    finding_id: str,
    actor: AuthContext = Depends(require_platform_admin),
):
    from .discovery.findings import get_finding
    f = get_finding(finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")
    return f


@app.post("/v1/admin/witnessed/{finding_id}/acknowledge")
async def admin_acknowledge_witnessed(
    finding_id: str,
    actor: AuthContext = Depends(require_platform_admin),
):
    from .discovery.findings import acknowledge_finding, get_finding
    if get_finding(finding_id) is None:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")
    updated = acknowledge_finding(finding_id, actor.user_id)
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")
    write_audit_event(
        actor_id=actor.user_id,
        action="witnessed.acknowledged",
        entity_type="witnessed_finding",
        entity_id=finding_id,
        summary=f"Witnessed finding acknowledged: {updated['pattern_name']} on {updated['target_hostname']}",
        tenant_id=updated["tenant_id"],
    )
    return updated


@app.post("/v1/admin/witnessed/{finding_id}/dismiss")
async def admin_dismiss_witnessed(
    finding_id: str,
    request: AdminDismissFindingRequest,
    actor: AuthContext = Depends(require_platform_admin),
):
    from .discovery.findings import dismiss_finding, get_finding
    before = get_finding(finding_id)
    if before is None:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")
    if not request.reason.strip():
        raise HTTPException(status_code=400, detail="dismissal requires a written reason")
    updated = dismiss_finding(finding_id, actor.user_id, request.reason)
    write_audit_event(
        actor_id=actor.user_id,
        action="witnessed.dismissed",
        entity_type="witnessed_finding",
        entity_id=finding_id,
        summary=f"Dismissed: {before['pattern_name']} on {before['target_hostname']} — reason: {request.reason.strip()[:80]}",
        tenant_id=before["tenant_id"],
    )
    return updated


@app.post("/v1/admin/witnessed/{finding_id}/declare-host", status_code=201)
async def admin_govern_witnessed(
    finding_id: str,
    request: AdminGovernFindingRequest,
    actor: AuthContext = Depends(require_platform_admin),
):
    """One-click: create a fleet_hosts row for the witnessed target.

    Resolves the witnessed finding's `target_hostname` into a new
    declared fleet host. The operator can then install the node agent
    on that host (see the node-agent install guide) and the next
    heartbeat will flip lifecycle declared → governed.
    """
    from .discovery.findings import get_finding, mark_governed
    from .fleet_manifest import declare_host

    finding = get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")
    if finding["status"] in ("governed", "dismissed"):
        raise HTTPException(
            status_code=409,
            detail=f"Finding is already {finding['status']}; cannot declare a host from it again",
        )

    try:
        host = declare_host(
            tenant_id=finding["tenant_id"],
            hostname=finding["target_hostname"],
            role=(request.role or "production-core"),
            tags=(request.tags or []),
            notes=request.notes or f"Declared from witnessed finding {finding_id} (pattern={finding['pattern_name']})",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    mark_governed(finding_id, host["id"])

    write_audit_event(
        actor_id=actor.user_id,
        action="witnessed.governed",
        entity_type="witnessed_finding",
        entity_id=finding_id,
        summary=(
            f"Witnessed finding brought under governance: {finding['pattern_name']} "
            f"on {finding['target_hostname']} → fleet host {host['id']}"
        ),
        tenant_id=finding["tenant_id"],
    )
    write_audit_event(
        actor_id=actor.user_id,
        action="fleet.host_declared",
        entity_type="fleet_host",
        entity_id=host["id"],
        summary=f"Fleet host {host['hostname']} declared from witnessed finding (auto-create)",
        tenant_id=host["tenant_id"],
    )
    return {"finding": get_finding(finding_id), "host": host}


# ─── Inventory Report (Pillar D) ────────────────────────────────────────────
#
# Combines Coverage Map (Pillar A) + Witnessed findings (Pillar B) + an
# audit-chain summary into a tamper-evident PDF. Each report carries a
# SHA-256 fingerprint of its canonical JSON body and a pointer to the
# previous report's fingerprint, forming a verifiable chain.
#
# Endpoints:
#   GET /v1/admin/reports/inventory.json — canonical JSON body (what gets hashed)
#   GET /v1/admin/reports/inventory.pdf  — rendered PDF, returns application/pdf
#   GET /v1/admin/reports/runs           — chain of all generated reports

@app.get("/v1/admin/reports/inventory.json")
async def admin_inventory_json(
    actor: AuthContext = Depends(require_platform_admin),
    period_days: int = 30,
    tenant_id: Optional[str] = None,
):
    """Return the canonical JSON body that the inventory PDF would render.

    Useful for programmatic verification — auditors can recompute the
    SHA-256 of this body and confirm the PDF fingerprint matches.
    """
    from datetime import datetime, timezone, timedelta
    from .fleet_manifest import coverage_summary
    from .discovery.findings import list_findings
    from .repository import list_audit_events
    from .reports.inventory import build_inventory_payload, fingerprint

    period_end = datetime.now(timezone.utc)
    period_start = period_end - timedelta(days=max(1, int(period_days)))

    cov = coverage_summary(tenant_id=tenant_id)
    findings = list_findings(tenant_id=tenant_id, status_filter=None, limit=10000)
    # list_audit_events returns recent-first; filter to the period in Python.
    # v1 OK for small fleets; if event count grows past ~5k/period, add a
    # period-aware DB query in repository.py.
    # SQLite stores datetimes as naive — coerce to UTC-aware for comparison.
    def _aware(dt):
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt
    raw_events = list_audit_events(limit=10000, tenant_id=tenant_id)
    audit_events = [
        {
            "id": e.id,
            "actor_id": e.actor_id,
            "action": e.action,
            "entity_type": e.entity_type,
            "entity_id": e.entity_id,
            "summary": e.summary,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in raw_events
        if e.created_at and period_start <= _aware(e.created_at) <= period_end
    ]

    tenant_label = None
    if tenant_id:
        from .tenant import get_tenant
        t = get_tenant(tenant_id)
        if t:
            tenant_label = f"{t['name']} ({t['slug']})"

    payload = build_inventory_payload(
        coverage=cov,
        findings=findings,
        audit_events=audit_events,
        period_start=period_start,
        period_end=period_end,
        tenant_label=tenant_label,
        generated_by=actor.user_id,
    )
    payload["fingerprint"] = fingerprint(payload)
    return payload


@app.get("/v1/admin/reports/inventory.pdf")
async def admin_inventory_pdf(
    actor: AuthContext = Depends(require_platform_admin),
    period_days: int = 30,
    tenant_id: Optional[str] = None,
):
    """Render the inventory PDF and record a chain entry."""
    from datetime import datetime, timezone, timedelta
    from fastapi.responses import Response
    from .fleet_manifest import coverage_summary
    from .discovery.findings import list_findings
    from .repository import list_audit_events
    from .reports.inventory import build_inventory_payload, fingerprint, render_inventory_pdf
    from .reports.runs import get_previous_fingerprint, record_report_run

    period_end = datetime.now(timezone.utc)
    period_start = period_end - timedelta(days=max(1, int(period_days)))

    cov = coverage_summary(tenant_id=tenant_id)
    findings = list_findings(tenant_id=tenant_id, status_filter=None, limit=10000)
    # list_audit_events returns recent-first; filter to the period in Python.
    # v1 OK for small fleets; if event count grows past ~5k/period, add a
    # period-aware DB query in repository.py.
    # SQLite stores datetimes as naive — coerce to UTC-aware for comparison.
    def _aware(dt):
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt
    raw_events = list_audit_events(limit=10000, tenant_id=tenant_id)
    audit_events = [
        {
            "id": e.id,
            "actor_id": e.actor_id,
            "action": e.action,
            "entity_type": e.entity_type,
            "entity_id": e.entity_id,
            "summary": e.summary,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in raw_events
        if e.created_at and period_start <= _aware(e.created_at) <= period_end
    ]

    tenant_label = None
    if tenant_id:
        from .tenant import get_tenant
        t = get_tenant(tenant_id)
        if t:
            tenant_label = f"{t['name']} ({t['slug']})"

    payload = build_inventory_payload(
        coverage=cov,
        findings=findings,
        audit_events=audit_events,
        period_start=period_start,
        period_end=period_end,
        tenant_label=tenant_label,
        generated_by=actor.user_id,
    )
    fp = fingerprint(payload)
    prev_fp = get_previous_fingerprint(report_type="inventory", tenant_id=tenant_id)

    pdf_bytes = render_inventory_pdf(payload=payload, fingerprint_hex=fp, previous_fingerprint=prev_fp)

    run = record_report_run(
        report_type="inventory",
        tenant_id=tenant_id,
        period_start=period_start,
        period_end=period_end,
        fingerprint=fp,
        previous_fingerprint=prev_fp,
        generated_by=actor.user_id,
        summary=(
            f"Inventory: governed={cov['governed']}/{cov['governed']+cov['declared_not_governed']} "
            f"({cov['coverage_pct']:.1f}%), witnessed={len(findings)}, audit_events={len(audit_events)}"
        ),
    )
    write_audit_event(
        actor_id=actor.user_id,
        action="report.generated",
        entity_type="report_run",
        entity_id=run["id"],
        summary=f"Inventory report generated (fingerprint {fp[:16]}…, period {period_days}d)",
        tenant_id=tenant_id,
    )

    filename = f"vertirite-inventory-{period_end.strftime('%Y%m%d')}-{fp[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Vertirite-Fingerprint": fp,
            "X-Vertirite-Previous-Fingerprint": prev_fp or "",
        },
    )


@app.get("/v1/admin/reports/runs")
async def admin_list_report_runs(
    actor: AuthContext = Depends(require_platform_admin),
    report_type: Optional[str] = None,
    tenant_id: Optional[str] = None,
):
    """List all report runs (the chain). Most-recent first."""
    from .reports.runs import list_report_runs
    runs = list_report_runs(report_type=report_type, tenant_id=tenant_id)
    return {"runs": runs}


@app.get("/v1/admin/users")
async def admin_list_users(
    actor: AuthContext = Depends(require_platform_admin),
):
    """Cross-tenant user list. Platform-admin only."""
    users = list_all_users()
    # Strip password_hash and api_key_hash from the response
    safe_users = [
        {k: v for k, v in u.items() if k not in ("password_hash", "api_key_hash")}
        for u in users
    ]
    return {"users": safe_users}


@app.post("/v1/admin/grant-role")
async def admin_grant_role(
    request: AdminGrantRoleRequest,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Grant or change a user's role. Platform-admin only.

    Guard: a platform admin cannot demote themselves if they are the last remaining
    platform admin — prevents operator lockout.
    """
    if request.role not in VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role: {request.role}. Valid roles: {list(VALID_ROLES)}",
        )

    user = get_tenant_user_by_email(request.email)
    if user is None:
        raise HTTPException(status_code=404, detail=f"No user with email {request.email}")

    previous_role = user["role"]

    # Self-demotion lockout guard
    if (
        user["id"] == actor.user_id
        and previous_role == "platform_admin"
        and request.role != "platform_admin"
    ):
        admins = list_platform_admins()
        if len(admins) <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot demote yourself — you are the last platform admin. Grant another user first.",
            )

    updated = update_user_role(user["id"], request.role)
    if updated is None:
        raise HTTPException(status_code=404, detail="User not found")

    write_audit_event(
        actor_id=actor.user_id,
        action="admin.role_granted" if request.role == "platform_admin" else "admin.role_changed",
        entity_type="user",
        entity_id=updated["id"],
        summary=f"Role changed for {request.email}: {previous_role} → {request.role}",
    )
    # Return a safe subset
    return {
        "user": {
            "id": updated["id"],
            "email": updated["email"],
            "display_name": updated["display_name"],
            "role": updated["role"],
            "tenant_id": updated["tenant_id"],
        },
        "previous_role": previous_role,
    }


@app.get("/v1/admin/audit")
async def admin_audit_log(
    limit: int = 100,
    admin_only: bool = True,
    tenant_id: Optional[str] = None,
    actor: AuthContext = Depends(require_platform_admin),
):
    """Audit feed. Platform-admin only.

    Defaults to admin-action-only events (`action LIKE 'admin.%'` or `plan.%`).
    Set admin_only=false to see all events.
    When `tenant_id` is given, restricts to events tagged with that tenant
    (the compliance-reviewer drill-down: "show me every event for tenant X").
    """
    if admin_only:
        # The update-plan endpoint logs 'plan.updated', so include both prefixes
        admin_events = list_audit_events(limit=limit, action_prefix="admin.", tenant_id=tenant_id)
        plan_events = list_audit_events(limit=limit, action_prefix="plan.", tenant_id=tenant_id)
        combined = sorted(
            admin_events + plan_events,
            key=lambda e: e.created_at,
            reverse=True,
        )[:limit]
        events = combined
    else:
        events = list_audit_events(limit=limit, tenant_id=tenant_id)

    return {
        "events": [
            {
                "id": e.id,
                "actor_id": e.actor_id,
                "action": e.action,
                "entity_type": e.entity_type,
                "entity_id": e.entity_id,
                "summary": e.summary,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in events
        ],
        "filter": {
            "tenant_id": tenant_id,
            "admin_only": admin_only,
            "limit": limit,
        },
    }


# ---------------------------------------------------------------------------
# SaaS Account endpoints (authenticated)
# ---------------------------------------------------------------------------

async def _resolve_saas_auth(request: Request) -> Optional[dict]:
    """
    Try SaaS auth (API key or session token) from Authorization header.
    Returns {user, tenant} or None if not a SaaS token.
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[7:].strip()

    # Try API key auth (mae_xxx)
    if token.startswith("mae_"):
        return await authenticate_api_key(token)

    # Try session token auth (mse_xxx)
    if token.startswith("mse_"):
        return await authenticate_session(token)

    return None


@app.get("/v1/account")
async def get_account(request: Request):
    """Get current user account, tenant info, and token balance."""
    ctx = await _resolve_saas_auth(request)
    if ctx is None:
        raise HTTPException(status_code=401, detail="Valid SaaS authentication required (mae_ or mse_ token)")
    tenant = ctx["tenant"]
    return {
        "user": ctx["user"],
        "tenant": tenant,
        "token_balance": tenant.get("token_balance", 0),
    }


@app.get("/v1/account/usage")
async def get_account_usage(request: Request, days: int = 30):
    """Get token usage statistics for the current tenant."""
    ctx = await _resolve_saas_auth(request)
    if ctx is None:
        raise HTTPException(status_code=401, detail="Valid SaaS authentication required")
    tenant_id = ctx["tenant"]["id"]
    usage = get_usage(tenant_id, days=min(days, 365))
    return usage


@app.post("/v1/account/tokens/purchase")
async def purchase_tokens(request: Request):
    """Add tokens to account (placeholder for Stripe integration)."""
    ctx = await _resolve_saas_auth(request)
    if ctx is None:
        raise HTTPException(status_code=401, detail="Valid SaaS authentication required")

    body = await request.json()
    amount = body.get("amount", 0)
    if not isinstance(amount, int) or amount <= 0:
        raise HTTPException(status_code=400, detail="amount must be a positive integer")

    # Placeholder: In production, this would create a Stripe checkout session
    # and only add tokens after payment confirmation.
    tenant_id = ctx["tenant"]["id"]
    new_balance = add_tokens(tenant_id, amount)
    if new_balance is None:
        raise HTTPException(status_code=404, detail="Tenant not found")

    logger.info(
        "Token purchase (placeholder): tenant=%s amount=%d new_balance=%d",
        tenant_id, amount, new_balance,
    )
    return {
        "status": "ok",
        "message": "Tokens added (Stripe integration pending)",
        "amount_added": amount,
        "new_balance": new_balance,
    }


# --------------- Desktop Download Endpoints ---------------

_DESKTOP_DIST = os.environ.get(
    "MAESTRO_DIST_DIR",
    os.path.join(os.path.dirname(__file__), "..", "..", "desktop", "dist"),
)

_INSTALLERS = {
    "win-x64": "Maestro-AI-0.2.0-win-x64.exe",
    "win-arm64": "Maestro-AI-0.2.0-win-arm64.exe",
}


@app.get("/download/maestro")
async def download_maestro(platform: str = "win-x64"):
    """Serve the Maestro desktop installer. Default: Windows x64."""
    filename = _INSTALLERS.get(platform)
    if not filename:
        raise HTTPException(400, f"Unknown platform '{platform}'. Options: {list(_INSTALLERS.keys())}")
    filepath = os.path.join(_DESKTOP_DIST, filename)
    if not os.path.isfile(filepath):
        raise HTTPException(404, f"Installer not found on server: {filename}")
    return FileResponse(
        filepath,
        media_type="application/octet-stream",
        filename=filename,
    )


@app.get("/download/maestro/list")
async def list_maestro_downloads():
    """List available Maestro installers."""
    available = {}
    for platform, filename in _INSTALLERS.items():
        filepath = os.path.join(_DESKTOP_DIST, filename)
        if os.path.isfile(filepath):
            size_mb = round(os.path.getsize(filepath) / (1024 * 1024), 1)
            available[platform] = {"filename": filename, "size_mb": size_mb}
    return {"installers": available}



def _mask_api_key(key: str) -> str:
    """Mask an API key for display."""
    if not key or len(key) < 8:
        return "***"
    return key[:6] + "..." + key[-4:]


def _model_tier(name: str) -> str:
    """Classify model into pricing tier."""
    free = ("phi:latest", "phi3:mini", "qwen2.5:3b", "llama3.2:latest")
    pro = ("llama3:latest", "mistral:latest")
    if name in free:
        return "free"
    if name in pro:
        return "pro"
    return "premium"


@app.get("/v1/models")
async def list_models():
    """List models available via customer BYOK connectors (no bundled model)."""
    paid_only = []
    try:
        user_keys = {k["key_type"] for k in list_keys() if k.get("active")}
        for pm in PAID_MODELS_CATALOG:
            if pm["provider"] in user_keys:
                paid_only.append(pm)
    except Exception:
        pass
    return {"models": paid_only, "default": None}




@app.on_event("shutdown")
async def shutdown() -> None:
    stop_scheduler()
    from .intelligence.feed import stop_feed_refresher
    stop_feed_refresher()


def run() -> None:
    uvicorn.run(
        "broker.main:app",
        host="0.0.0.0",
        port=8220,
        reload=False,
    )


if __name__ == "__main__":
    run()


# ---------------------------------------------------------------------------
# Email Verification + Password Reset Endpoints
# ---------------------------------------------------------------------------

@app.post("/v1/auth/forgot-password")
async def auth_forgot_password(request: Request):
    """Request a password reset email."""
    body = await request.json()
    email = body.get("email", "").strip()
    if not email:
        raise HTTPException(status_code=400, detail="email is required")

    from broker.saas_auth import create_reset_token
    token = create_reset_token(email)

    # Always return success (don't reveal if email exists). The publishable
    # broker does NOT execute: it does not shell out or send mail itself.
    # A reset token is minted and recorded; delivering it (email/SMS) is the
    # integrating deployment's responsibility via its own notification path.
    if token:
        logger.info("Password reset token minted for a matching account; delivery is deployment-configured.")

    return {"message": "If an account exists with that email, a reset link has been sent."}


@app.post("/v1/auth/reset-password")
async def auth_reset_password(request: Request):
    """Reset password using a token."""
    body = await request.json()
    token = body.get("token", "")
    new_password = body.get("password", "")

    if not token or not new_password:
        raise HTTPException(status_code=400, detail="token and password are required")
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    from broker.saas_auth import reset_password_with_token
    success = reset_password_with_token(token, new_password)
    if not success:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    return {"message": "Password has been reset. Please log in with your new password."}


@app.post("/v1/auth/change-password")
async def auth_change_password(request: Request):
    body = await request.json()
    user_id = body.get("user_id", "").strip()
    current_password = body.get("current_password", "")
    new_password = body.get("new_password", "")
    if not user_id or not current_password or not new_password:
        raise HTTPException(status_code=400, detail="user_id, current_password and new_password are required")
    from broker.saas_auth import change_password as _cp
    result = _cp(user_id, current_password, new_password)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("detail", "Unable to change password"))
    return {"message": "Password updated successfully."}


@app.post("/v1/auth/verify-email")
async def auth_verify_email(request: Request):
    """Verify email address using a token."""
    body = await request.json()
    token = body.get("token", "")

    if not token:
        raise HTTPException(status_code=400, detail="token is required")

    from broker.saas_auth import verify_email_token
    email = verify_email_token(token)
    if email is None:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")

    # Mark user as verified
    from broker.tenant import get_tenant_user_by_email
    user = get_tenant_user_by_email(email)
    if user:
        # Update status to active if it was pending
        pass  # Already active on registration for now

    return {"message": "Email verified successfully.", "email": email}


# === NO RUNTIME ROUTE FILTER ===
# The publishable vertirite-broker defines ONLY governance control-plane
# routes. There is no inference/chat/voice/session/node-exec surface to
# filter out at runtime — those modules are absent from the source tree.
# This property is enforced at build time by the CI import-guard
# (broker/import_guard_test.py), which fails the build if any model, exec,
# or topology import re-enters the tree. Enforce at the source, not at
# request time.
# === END DIST ALLOWLIST ROUTE FILTER ===
