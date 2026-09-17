# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Stage 2 enforcement connectors — the BLOCK primitive.

BLOCK is applied at the customer's OWN in-path device (NGFW / proxy / DNS / NAC)
via that device's API — Vertirite is the brain, not an inline all-traffic
chokepoint (docs/GOVERNANCE-ENFORCEMENT.md, "brain not the wire"). A connector
turns a remediation into an applied change on one such device.

Default posture is ADVISORY: a connector returns the exact change it WOULD make
and applies nothing. Real auto-apply connectors (DNS RPZ writer, Squid ACL, NGFW
API, ...) plug into this same interface behind explicit operator approval; none
auto-apply in this slice, keeping blast radius at zero until a connector is
deliberately wired AND authorized.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class ApplyResult:
    connector: str
    applied: bool            # False = advisory / dry-run (nothing changed)
    change: str              # the concrete change (a config line / an API call)
    detail: str = ""


@runtime_checkable
class EnforcementConnector(Protocol):
    name: str

    def supports(self, plane: str) -> bool: ...

    def apply(self, *, target: str, plane: str, dry_run: bool = True) -> ApplyResult: ...


class AdvisoryConnector:
    """Default connector: emits the change, applies nothing. Always safe."""

    name = "advisory"

    def supports(self, plane: str) -> bool:
        return True

    def apply(self, *, target: str, plane: str, dry_run: bool = True) -> ApplyResult:
        if plane == "east-west":
            change = (f"switch ACL: deny ip any host {target}  "
                      f"(segment at the VLAN; do NOT inline a box)")
        elif plane == "host-local":
            change = f"host firewall: block egress to {target} on the originating host"
        else:  # north-south
            change = f"DNS RPZ: {target}  CNAME  .   (sinkhole at the resolver)"
        return ApplyResult(
            connector=self.name, applied=False, change=change,
            detail="advisory — Vertirite generated this change; the operator/connector applies it",
        )


def _why_not_applied(dry_run: bool, configured: bool) -> str:
    from ..config import settings
    if dry_run:
        return "dry-run — nothing applied"
    if not settings.enforcement_apply_enabled:
        return "apply disabled (set SURGE_OPERATOR_ENFORCEMENT_APPLY_ENABLED=true to permit real changes)"
    if not configured:
        return "connector not configured"
    return ""


class WebhookConnector:
    """Apply a BLOCK by POSTing it to the customer's automation webhook — the
    most universal real connector (the customer's side does the actual blocking).
    """
    name = "webhook"

    def supports(self, plane: str) -> bool:
        return True

    def apply(self, *, target: str, plane: str, dry_run: bool = True) -> ApplyResult:
        from ..config import settings
        url = settings.enforcement_webhook_url
        change = f'POST {{"action":"block","target":"{target}","plane":"{plane}"}} -> {url or "<unset>"}'
        if dry_run or not settings.enforcement_apply_enabled or not url:
            return ApplyResult(self.name, False, change, _why_not_applied(dry_run, bool(url)))
        import httpx
        headers = {}
        if settings.enforcement_webhook_token:
            headers["Authorization"] = f"Bearer {settings.enforcement_webhook_token}"
        try:
            with httpx.Client(timeout=8.0) as c:
                r = c.post(url, json={"action": "block", "target": target, "plane": plane}, headers=headers)
            ok = r.status_code // 100 == 2
            return ApplyResult(self.name, ok, change,
                               f"webhook accepted (HTTP {r.status_code})" if ok else f"webhook HTTP {r.status_code}")
        except Exception as exc:
            return ApplyResult(self.name, False, change, f"webhook unreachable: {exc}")


class DnsRpzConnector:
    """Apply a north-south BLOCK by sinkholing the name in a DNS Response-Policy-
    Zone file (the resolver then refuses to answer it). File-based — point it at
    the RPZ zone your resolver loads."""
    name = "dns-rpz"

    def supports(self, plane: str) -> bool:
        return plane == "north-south"

    def apply(self, *, target: str, plane: str, dry_run: bool = True) -> ApplyResult:
        from ..config import settings
        path = settings.enforcement_dns_rpz_path
        rule = f"{target}\tCNAME\t.\t; vertirite block"
        change = f"DNS RPZ append: {rule}   (file: {path or '<unset>'})"
        if dry_run or not settings.enforcement_apply_enabled or not path:
            return ApplyResult(self.name, False, change, _why_not_applied(dry_run, bool(path)))
        try:
            with open(path, "a") as f:
                f.write(rule + "\n")
            return ApplyResult(self.name, True, change, "appended to the RPZ zone (reload the resolver to take effect)")
        except OSError as exc:
            return ApplyResult(self.name, False, change, f"could not write RPZ file: {exc}")


_REGISTRY: dict[str, EnforcementConnector] = {}


def register(connector: EnforcementConnector) -> None:
    _REGISTRY[connector.name] = connector


def get(name: str) -> EnforcementConnector | None:
    return _REGISTRY.get(name)


def list_connectors() -> list[str]:
    return sorted(_REGISTRY)


register(AdvisoryConnector())
register(WebhookConnector())
register(DnsRpzConnector())
