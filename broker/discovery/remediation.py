# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Remediation guidance — "show me HOW to bring this under governance."

Stage 1 of the enforcement roadmap (docs/GOVERNANCE-ENFORCEMENT.md): we don't
auto-enforce yet, but we turn the abstract `remediation` string each pattern
carries into the EXACT, copy-paste change for the two enforcement primitives,
tailored to the finding's network plane:

  - BLOCK (cut the direct path) — available TODAY at the customer's existing
    chokepoint (DNS / proxy / firewall / switch ACL / host firewall).
  - ROUTE (send it through the broker for live policy + audit) — the target
    state; honestly flagged as requiring the broker forward-proxy (Stage 2),
    and not applicable to internal device/process traffic.

Deterministic + inference-free, like the rest of discovery. The operator (or a
VAR, or SurgeXi-managed setup, or a connector once granted access) applies the
change; Vertirite is the brain, not the wire.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .patterns import lookup_pattern

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# Broker address shown in snippets — a placeholder the operator fills with their
# instance's reachable address (never a secret).
_BROKER = "<vertirite-broker>:8230"

# AI SaaS patterns whose client SDK exposes a base_url we can repoint.
_BASEURL_HINTS = {
    "net-openai-saas": 'OpenAI SDK: client = OpenAI(base_url="http://%s/v1")' % _BROKER,
    "net-anthropic-saas": 'Anthropic SDK: client = Anthropic(base_url="http://%s")' % _BROKER,
    "net-azure-openai": "Azure OpenAI: set the endpoint to the Vertirite broker.",
    "net-cohere-saas": "Cohere client: set base_url to the Vertirite broker.",
    "net-bedrock-saas": "Bedrock: route InvokeModel via the broker (it IAM-assumes the role).",
}


def _snip(target: str, code: str) -> Dict[str, str]:
    return {"target": target, "code": code}


def _block_guidance(host: str, plane: str, port: Optional[Any]) -> Dict[str, Any]:
    is_ip = bool(_IPV4.match(host or ""))
    if plane == "host-local":
        return {
            "what": "Block on the host itself — loopback/IPC is only reachable to "
                    "an on-host agent (eBPF/auditd) or the host firewall.",
            "snippets": [
                _snip("host firewall (iptables)",
                      "iptables -A OUTPUT -o lo -p tcp --dport %s -j REJECT" % (port or "<port>")),
                _snip("agent", "Vertirite host agent: deny the local listener for this process."),
            ],
            "note": "No network device can see same-host traffic — this must be enforced on the host.",
        }
    if plane == "east-west":
        return {
            "what": "Block INSIDE the network (this never reaches the egress edge). "
                    "Use a switch ACL / segmentation / NAC on the control segment.",
            "snippets": [
                _snip("switch ACL", "deny ip any host %s   ! apply on the segment SVI/port" % host),
                _snip("microsegmentation/NAC",
                      "Restrict the talker's segment so it can no longer reach %s." % host),
            ],
            "note": "Do NOT inline a box between the endpoints — drive the existing "
                    "switch/NAC. (See GOVERNANCE-ENFORCEMENT.md: brain, not the wire.)",
        }
    # north-south (egress)
    snippets = [
        _snip("DNS RPZ (sinkhole the name)", "%s   CNAME   ." % host),
        _snip("Squid proxy", "acl vrt_block dstdomain %s\nhttp_access deny vrt_block" % host),
        _snip("NGFW (Palo Alto / Fortinet)",
              "Security rule: dest %s, service any, action DENY, log at session-end." % host),
    ]
    if is_ip:
        snippets.append(_snip("iptables (by IP)", "iptables -A OUTPUT -d %s -j REJECT" % host))
    return {
        "what": "Cut the direct path at your existing egress chokepoint. No traffic "
                "routes through Vertirite for a block.",
        "snippets": snippets,
        "note": "Apply at the proxy/DNS/firewall you already run — Vertirite generated "
                "the rule; you (or a connector, once granted access) apply it.",
    }


def _route_guidance(host: str, plane: str, pattern_id: Optional[str]) -> Dict[str, Any]:
    if plane in ("east-west", "host-local"):
        return {
            "applicable": False,
            "what": "Routing through the broker does not apply to internal "
                    "device/process traffic — govern it via BLOCK (segmentation / "
                    "host firewall) instead.",
            "snippets": [],
            "note": "",
        }
    steps = [
        _snip("egress proxy env",
              "HTTPS_PROXY=http://%s   # send this app's egress through policy+audit" % _BROKER),
    ]
    hint = _BASEURL_HINTS.get(pattern_id or "")
    if hint:
        steps.append(_snip("repoint the client", hint))
    steps.append(_snip("then block the direct path",
                       "After routing works, BLOCK direct %s so the app can't bypass." % host))
    return {
        "applicable": True,
        "what": "Send calls THROUGH the Vertirite broker so every call is "
                "policy-gated + audited.",
        "snippets": steps,
        "note": "Route-through requires the Vertirite broker forward-proxy "
                "(enforcement Stage 2). Until it ships, BLOCK is the available "
                "control today.",
    }


def guidance_for(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Turn one finding into copy-paste BLOCK + ROUTE guidance for its plane."""
    host = finding.get("target_hostname") or finding.get("destination") or "?"
    ev = finding.get("evidence") or {}
    plane = (ev.get("plane") if isinstance(ev, dict) else None) or "north-south"
    port = ev.get("dst_port") if isinstance(ev, dict) else None
    pattern_id = finding.get("pattern_id")
    pat = lookup_pattern(pattern_id) if pattern_id else None
    summary = (pat or {}).get("remediation") or (
        "Review this destination. If it carries AI/automation traffic, bring it "
        "under governance; otherwise dismiss it as baseline.")
    return {
        "finding_id": finding.get("id"),
        "target": host,
        "plane": plane,
        "summary": summary,
        "block": _block_guidance(host, plane, port),
        "route": _route_guidance(host, plane, pattern_id),
    }


def remediation_summary(finding: Dict[str, Any]) -> str:
    """The one-line advice for the coverage list (full guidance via the endpoint)."""
    pat = lookup_pattern(finding.get("pattern_id")) if finding.get("pattern_id") else None
    return (pat or {}).get("remediation") or "Review and govern, or dismiss as baseline."
