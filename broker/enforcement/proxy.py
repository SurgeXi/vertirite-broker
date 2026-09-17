# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Stage 2 forward-proxy — the ROUTE primitive made real.

An OpenAI-compatible endpoint. An app points its SDK ``base_url`` at the broker;
every chat/completions call is policy-gated (``policy.py``), audited, and — if
allowed — forwarded to the real upstream provider. Blocked calls never leave the
building; the caller gets a 403 with the policy reason.

Here Vertirite is the brain AND the wire, which is why it is opt-in
(``settings.proxy_enabled``, default OFF): carrying live traffic is a
higher-blast-radius posture than passive discovery, so it stays inert until an
operator deliberately enables it. See docs/GOVERNANCE-ENFORCEMENT.md Stage 2.
"""
from __future__ import annotations

import json
import logging

import httpx

from ..config import settings
from ..repository import write_audit_event
from . import policy

logger = logging.getLogger(__name__)

# Hop-by-hop headers (RFC 7230 §6.1) must not be forwarded. We also drop the
# caller's Authorization here and re-set it for the upstream below.
_STRIP_REQ_HEADERS = {
    "host", "content-length", "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade",
    "authorization",
}
_STRIP_RESP_HEADERS = {
    "content-length", "content-encoding", "connection", "keep-alive",
    "transfer-encoding", "trailers", "upgrade",
}


class ProxyDisabled(Exception):
    """Raised when the forward-proxy is not enabled (fail-safe default)."""


class ProxyBlocked(Exception):
    """Raised when policy denies a call; carries the Decision for the 403 body."""

    def __init__(self, decision: "policy.Decision"):
        self.decision = decision
        super().__init__(decision.reason)


def _model_of(body: bytes) -> str:
    if not body:
        return ""
    try:
        return str(json.loads(body).get("model", "") or "")
    except (ValueError, TypeError):
        return ""


def _upstream_headers(incoming: dict[str, str]) -> dict[str, str]:
    out = {k: v for k, v in incoming.items() if k.lower() not in _STRIP_REQ_HEADERS}
    # Secure posture: inject the server-side provider key so the calling app
    # never holds the provider secret. When no server key is configured, pass
    # the caller's own Authorization through verbatim.
    if settings.proxy_openai_api_key:
        out["Authorization"] = f"Bearer {settings.proxy_openai_api_key}"
    else:
        for k, v in incoming.items():
            if k.lower() == "authorization":
                out["Authorization"] = v
                break
    return out


async def forward_openai(
    *,
    path: str,
    method: str,
    headers: dict[str, str],
    body: bytes,
    actor_id: str,
    tenant_id: str | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Gate + forward one OpenAI-compatible call. Returns (status, headers, body).

    Raises ProxyDisabled (-> 503) or ProxyBlocked (-> 403). Every call — allowed
    or blocked — writes an audit event, so the proxy is its own evidence trail.
    """
    if not settings.proxy_enabled:
        raise ProxyDisabled("forward-proxy disabled (set SURGE_OPERATOR_PROXY_ENABLED=true)")
    # License gate (commercial keystone): ROUTE enforcement is a premium feature.
    from ..licensing.license import entitled
    if not entitled("enforcement"):
        raise ProxyDisabled("enforcement not licensed (no valid license grants 'enforcement')")

    upstream = settings.proxy_openai_upstream.rstrip("/")
    model = _model_of(body)
    decision = policy.decide(destination=upstream, model=model)

    if not decision.allowed:
        write_audit_event(
            actor_id=actor_id, action="ai.proxy.blocked", entity_type="ai_call",
            entity_id=upstream, tenant_id=tenant_id,
            summary=f"BLOCKED model={model or '?'} -> {upstream}: {decision.reason}",
        )
        raise ProxyBlocked(decision)

    write_audit_event(
        actor_id=actor_id, action="ai.proxy.forward", entity_type="ai_call",
        entity_id=upstream, tenant_id=tenant_id,
        summary=(f"ROUTE model={model or '?'} -> {upstream} "
                 f"({'sanctioned' if decision.sanctioned else 'unsanctioned'}): {decision.reason}"),
    )

    url = f"{upstream}/{path.lstrip('/')}"
    async with httpx.AsyncClient(timeout=settings.proxy_request_timeout_s) as client:
        resp = await client.request(
            method, url, content=body or None, headers=_upstream_headers(headers),
        )

    out_headers = {k: v for k, v in resp.headers.items()
                   if k.lower() not in _STRIP_RESP_HEADERS}
    out_headers["X-Vertirite-Decision"] = decision.action
    out_headers["X-Vertirite-Sanctioned"] = "true" if decision.sanctioned else "false"
    return resp.status_code, out_headers, resp.content
