# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Async HTTP client for Surge invocation. See docstring in __init__.py."""
from __future__ import annotations

import dataclasses
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

log = logging.getLogger("surgexi.products_sdk")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class SurgeError(Exception):
    """Base for SDK errors."""


class SurgeUnreachable(SurgeError):
    """Broker can't be reached."""


class AwaitingApproval(SurgeError):
    """The invocation hit a gated capability and is waiting for an
    operator. The approval_id can be polled, or the caller can resume
    UX flow elsewhere. Carries the original DispatchResult-like payload."""

    def __init__(self, approval_id: str, summary: str, payload: dict):
        super().__init__(summary)
        self.approval_id = approval_id
        self.payload = payload


class AwaitingCapability(SurgeError):
    """Surge needs a capability that doesn't exist. The product can either
    surface a 'feature in progress' message to the user, or invoke
    `surge.propose_new_tool` to draft it."""

    def __init__(self, summary: str, payload: dict):
        super().__init__(summary)
        self.payload = payload


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class DispatchResult:
    outcome: str  # "success" | "denied" | "error" | "awaiting_approval" | "awaiting_capability"
    summary: str
    data: Any | None = None
    audit_id: Optional[str] = None
    approval_id: Optional[str] = None
    capability: Optional[str] = None
    raw: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.outcome == "success"

    @classmethod
    def from_response(cls, body: dict) -> "DispatchResult":
        return cls(
            outcome=body.get("outcome", "error"),
            summary=body.get("summary", ""),
            data=body.get("data"),
            audit_id=body.get("audit_id"),
            approval_id=body.get("approval_id"),
            capability=body.get("capability"),
            raw=body,
        )


@dataclass
class InvokeResult:
    matched: str  # "playbook" | "single_capability" | "brain" | "needs_clarification" | "needs_new_capability"
    request_id: str
    summary: str
    raw: dict = field(default_factory=dict)
    # When matched in a way that produced a dispatch result, also carry it.
    dispatch: Optional[DispatchResult] = None

    @classmethod
    def from_response(cls, body: dict) -> "InvokeResult":
        # If the body looks like a DispatchResult (matched as
        # single_capability or brain_dispatch), carry it through.
        dispatch = None
        if body.get("outcome"):
            dispatch = DispatchResult.from_response(body)
        return cls(
            matched=body.get("matched", "unknown"),
            request_id=body.get("request_id", ""),
            summary=body.get("summary") or (dispatch.summary if dispatch else ""),
            raw=body,
            dispatch=dispatch,
        )


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class SurgeClient:
    """Async client for the Maestro broker's /v1/surge/* surface.

    Construct with `from_env()` for the common case, or directly with
    `SurgeClient(base_url, token)` for tests / multi-broker setups.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout_s: float = 30.0,
        default_tenant_id: Optional[str] = None,
        product: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout_s = timeout_s
        self.default_tenant_id = default_tenant_id
        self.product = product or "unknown"

    @classmethod
    def from_env(cls) -> "SurgeClient":
        base = (
            os.environ.get("SURGE_BROKER_URL")
            or os.environ.get("BROKER_URL")
            or "http://127.0.0.1:8220"
        )
        token = (
            os.environ.get("SURGE_TOKEN")
            or os.environ.get("BROKER_API_TOKEN")
            or "surge-operator-dev-token"
        )
        return cls(
            base, token,
            default_tenant_id=os.environ.get("SURGE_DEFAULT_TENANT_ID"),
            product=os.environ.get("SURGE_PRODUCT_NAME"),
        )

    # -------------------------------------------------------------- private

    def _headers(self, tenant_id: Optional[str] = None) -> dict:
        h = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "X-Surge-Product": self.product,
        }
        tid = tenant_id or self.default_tenant_id
        if tid:
            h["X-Surge-Tenant"] = tid
        return h

    async def _post(self, path: str, body: dict, *,
                    tenant_id: Optional[str] = None) -> dict:
        url = f"{self.base_url}{path}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_s) as client:
                r = await client.post(url, json=body, headers=self._headers(tenant_id))
        except httpx.HTTPError as e:
            raise SurgeUnreachable(f"surge broker unreachable at {url}: {e}") from e
        if r.status_code >= 500:
            raise SurgeUnreachable(f"surge broker {r.status_code}: {r.text[:200]}")
        try:
            return r.json()
        except Exception:
            return {"outcome": "error", "summary": f"non-json response: {r.text[:300]}"}

    async def _get(self, path: str, *, tenant_id: Optional[str] = None) -> dict:
        url = f"{self.base_url}{path}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_s) as client:
                r = await client.get(url, headers=self._headers(tenant_id))
        except httpx.HTTPError as e:
            raise SurgeUnreachable(f"surge broker unreachable at {url}: {e}") from e
        if r.status_code >= 500:
            raise SurgeUnreachable(f"surge broker {r.status_code}: {r.text[:200]}")
        return r.json() if r.status_code < 400 else {"error": r.status_code, "body": r.text[:300]}

    # -------------------------------------------------------------- public

    async def invoke(
        self,
        intent: str,
        *,
        tenant_id: Optional[str] = None,
        context: Optional[dict] = None,
    ) -> InvokeResult:
        """Send a free-form intent. Surge resolves to a playbook,
        capability, clarifying question, or proposal."""
        body = {"intent": intent, "context": context or {}}
        tid = tenant_id or self.default_tenant_id
        if tid:
            body["tenant_id"] = tid
        resp = await self._post("/v1/surge/invoke", body, tenant_id=tid)
        return InvokeResult.from_response(resp)

    async def dispatch(
        self,
        capability: str,
        params: Optional[dict] = None,
        *,
        tenant_id: Optional[str] = None,
        raise_on_awaiting: bool = False,
    ) -> DispatchResult:
        """Call a named capability directly (skips intent matching)."""
        body = {"capability": capability, "params": params or {}}
        tid = tenant_id or self.default_tenant_id
        if tid:
            body["tenant_id"] = tid
        resp = await self._post("/v1/surge/dispatch", body, tenant_id=tid)
        result = DispatchResult.from_response(resp)
        if raise_on_awaiting:
            if result.outcome == "awaiting_approval":
                raise AwaitingApproval(result.approval_id or "", result.summary, resp)
            if result.outcome == "awaiting_capability":
                raise AwaitingCapability(result.summary, resp)
        return result

    async def list_capabilities(self) -> list[dict]:
        """What can Surge do right now? Returns the registry."""
        resp = await self._get("/v1/surge/capabilities")
        return resp.get("capabilities", [])

    async def list_playbooks(self) -> list[dict]:
        """What recipes does Surge know? Returns the playbook index."""
        resp = await self._get("/v1/surge/playbooks")
        return resp.get("playbooks", [])

    async def list_pending_approvals(self) -> list[dict]:
        """For operator UI — pending actions awaiting approval."""
        resp = await self._get("/v1/surge/approvals/pending")
        return resp.get("pending", [])

    async def approve(self, approval_id: str) -> DispatchResult:
        """Operator approves a pending action (post-resume dispatch)."""
        resp = await self._post(f"/v1/surge/approvals/{approval_id}/approve", {})
        return DispatchResult.from_response(resp)

    async def deny(self, approval_id: str) -> dict:
        return await self._post(f"/v1/surge/approvals/{approval_id}/deny", {})


# ---------------------------------------------------------------------------
# Convenience: synchronous wrappers for non-async callers
# ---------------------------------------------------------------------------

def invoke_sync(intent: str, **kwargs) -> InvokeResult:
    """Sync convenience for scripts. Don't use from inside an async loop."""
    import asyncio
    client = SurgeClient.from_env()
    return asyncio.run(client.invoke(intent, **kwargs))


def dispatch_sync(capability: str, params: Optional[dict] = None, **kwargs) -> DispatchResult:
    import asyncio
    client = SurgeClient.from_env()
    return asyncio.run(client.dispatch(capability, params or {}, **kwargs))
