# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company.
# Licensed under the Apache License, Version 2.0 (see sdk/LICENSE).
"""Minimal client for the Vertirite governance API (approval gate + audit read + mode).

Matches docs/openapi-governance.json. Only dependency: httpx (pip install httpx).

    from vertirite_client import Vertirite
    vr = Vertirite("https://vertirite.example.internal", token="...")
    req = vr.request_approval("payments.release", "Release batch 2026-10-13 ($41,200)", timeout_s=1800)
    decision = vr.wait_for_decision(req["id"])
    # {"status": "approved" | "denied", "decided_by": "<person>" or "vertirite-timeout"}
    if decision["status"] == "approved":
        ...  # your system executes the action; Vertirite records, it does not execute

    # Or, fail-closed in one call: True ONLY when a person approved. Anything else (denied,
    # timed out, governance refused because no paid license covers the node, auth or network
    # errors) is False, so the action does not run.
    if vr.gate("payments.release", "Release batch 2026-10-13 ($41,200)", timeout_s=1800):
        ...

An unanswered request is denied at its deadline: the safe default is always "no".
"""
from __future__ import annotations

import time
from typing import Any, Optional

import httpx

DECIDED = {"approved", "denied"}
TIMEOUT_ACTOR = "vertirite-timeout"  # decided_by when nobody answered in time (always a deny)


class Vertirite:
    def __init__(self, base_url: str, token: str, timeout: float = 15.0,
                 client: Optional[httpx.Client] = None):
        self._c = client or httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout,
                                         headers={"Authorization": f"Bearer {token}"})
        if client is not None:
            self._c.headers["Authorization"] = f"Bearer {token}"

    def request_approval(self, tool_name: str, summary: str, payload: Optional[dict] = None,
                         timeout_s: Optional[int] = None) -> dict[str, Any]:
        """Ask a human before a gated action. Returns the PENDING approval record."""
        body: dict[str, Any] = {"tool_name": tool_name, "summary": summary, "payload": payload or {}}
        if timeout_s is not None:
            body["timeout_s"] = timeout_s
        r = self._c.post("/v1/approvals", json=body)
        r.raise_for_status()
        return r.json()

    def gate(self, tool_name: str, summary: str, payload: Optional[dict] = None,
             timeout_s: Optional[int] = None, poll_s: float = 5.0, max_wait_s: float = 86400) -> bool:
        """FAIL-CLOSED: True only when a person APPROVED this request. Denied, timed out,
        governance refused (HTTP 403, e.g. no paid license for this node), authentication or
        network errors, or anything unexpected: False. Never let an action through on an error."""
        try:
            req = self.request_approval(tool_name, summary, payload, timeout_s)
            return self.wait_for_decision(req["id"], poll_s, max_wait_s).get("status") == "approved"
        except Exception:  # noqa: BLE001 — every failure is a "no"
            return False

    def approvals(self, status: Optional[str] = None, limit: int = 50) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": limit}
        if status:
            params["status"] = status
        r = self._c.get("/v1/approvals", params=params)
        r.raise_for_status()
        return r.json()

    def wait_for_decision(self, approval_id: str, poll_s: float = 5.0, max_wait_s: float = 86400) -> dict[str, Any]:
        """Poll until the request is decided; returns {"status", "decided_by", "decision_notes"}."""
        end = time.monotonic() + max_wait_s
        while time.monotonic() < end:
            for a in self.approvals(limit=200):
                if a["id"] == approval_id and a["status"] in DECIDED:
                    return {k: a.get(k) for k in ("status", "decided_by", "decision_notes")}
            time.sleep(poll_s)
        raise TimeoutError(f"approval {approval_id} not decided within {max_wait_s}s")

    def my_audit(self, limit: int = 100, action_prefix: Optional[str] = None) -> list[dict[str, Any]]:
        """Audit events recorded for the calling identity."""
        params: dict[str, Any] = {"limit": limit}
        if action_prefix:
            params["action_prefix"] = action_prefix
        r = self._c.get("/v1/audit/me", params=params)
        r.raise_for_status()
        return r.json()

    def mode(self) -> dict[str, Any]:
        """The node's mode: {"effective", "local", ...}; values AUTONOMOUS / CONTROLLED /
        ESCALATION_REQUIRED / LOCKDOWN. "effective" is the one in force."""
        r = self._c.get("/v1/mode")
        r.raise_for_status()
        return r.json()
