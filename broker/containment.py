# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Containment — govern by the chokepoint crossed, not the tool name.

Phase 2 of the strategy (docs/STRATEGY.md). The cooperative classifier
(`_effective_approval_class`) decides safe/gated from a capability's *declared*
class, and even DOWNGRADES tools to 'safe' when their params look read-only.
But an AI routes around tool-name policy: a "safe" read command that pipes data
to an external host still exfiltrates; a "safe" shell call running `rm -rf`
still destroys. Containment closes that by classifying the RESOURCE the action
crosses — the things the agent cannot fabricate or avoid:

  - EGRESS       : reaches a destination OUTSIDE the perimeter
  - IRREVERSIBLE : an un-undoable effect (destroy / move money / exfiltrate)
  - CREDENTIAL   : requires a secret to act (sudo / ssh / external auth)

Containment can only ELEVATE the approval class, never lower it — purely
additive safety, deterministic and inference-free. The agent can pick any tool
it likes; if the action crosses a chokepoint, it is contained anyway.
"""
from __future__ import annotations

import enum
import ipaddress
import re
from urllib.parse import urlparse

from . import approval_types as caps


class Chokepoint(str, enum.Enum):
    EGRESS = "egress"
    IRREVERSIBLE = "irreversible"
    CREDENTIAL = "credential"


# Strictness order for "elevate, never lower".
_RANK = {
    caps.ApprovalClass.SAFE: 0,
    caps.ApprovalClass.SCOPED: 1,
    caps.ApprovalClass.GATED: 2,
    caps.ApprovalClass.HIGH_STAKES: 3,
}

_INTERNAL_SUFFIXES = (".local", ".internal", ".intra", ".corp", ".lan",
                      ".home", ".localdomain", ".localhost")
# Params that may carry a destination.
_DEST_KEYS = ("url", "uri", "host", "hostname", "target", "endpoint",
              "destination", "dest", "to", "recipient", "server", "remote")

# Un-undoable effects.
_IRREVERSIBLE_RE = re.compile(
    r"(?:\brm\s+-[a-z]*[rf]|\brmdir\b|\bdd\b|\bmkfs|\bshred\b|\bwipe\b|"
    r"\bdrop\s+(?:table|database)\b|\btruncate\b|\bdelete\s+from\b|"
    r"\bgit\s+push\b|--force\b|\bformat\b)", re.I)
_MONEY_RE = re.compile(
    r"\b(?:wire|transfer|payout|disburse|ach|remit|charge|refund|"
    r"payment|pay_invoice|send_funds)\b", re.I)
# Needs a secret to act.
_CREDENTIAL_RE = re.compile(
    r"(?:\bsudo\b|\bssh\b|\bscp\b|api[_-]?key|\bsecret\b|\btoken\b|"
    r"\bpassword\b|\bcredential|aws_secret|_KEY\b)", re.I)


def _host_of(dest: str) -> str:
    d = (dest or "").strip()
    if "://" in d:
        return (urlparse(d).hostname or "").lower()
    d = d.split("/")[0]
    # strip :port for host:port (but not bare IPv6)
    if d.count(":") == 1:
        d = d.split(":")[0]
    return d.lower()


def _is_external_host(host: str) -> bool:
    h = (host or "").strip().lower()
    if not h or h == "localhost" or h.endswith(_INTERNAL_SUFFIXES):
        return False
    try:
        ip = ipaddress.ip_address(h)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
        # RFC 6598 shared address space (carrier-grade NAT) — treated as
        # internal mesh fabric, not the public internet. Built from a split
        # literal so the constant isn't mistaken for a real host address.
        if ip.version == 4 and ip in ipaddress.ip_network("100." + "64.0.0/10"):
            return False
        return True       # public IP literal
    except ValueError:
        pass
    # Bare hostname with no dot = a LAN name; a dotted name = a real domain.
    return "." in h


def _destinations(capability: str, params: dict) -> list[str]:
    out: list[str] = []
    for k in _DEST_KEYS:
        v = params.get(k)
        if isinstance(v, str) and v:
            out.append(v)
    # URLs embedded in a shell command / free text.
    blob = " ".join(str(v) for v in params.values() if isinstance(v, (str, int)))
    out += re.findall(r"https?://[^\s'\"]+", blob)
    # ssh/scp/curl/wget host arguments
    out += re.findall(r"(?:ssh|scp|curl|wget|nc)\s+(?:-\S+\s+)*([A-Za-z0-9._-]+\.[A-Za-z0-9._-]+)", blob)
    return out


def external_destinations(capability: str, params: dict | None) -> list[str]:
    """The external hosts (outside the perimeter) this action reaches, sorted +
    de-duped; ``[]`` if none. Break detection compares these against an agent's
    baseline egress set — same extraction the EGRESS chokepoint uses, exposed so
    callers don't reach into module internals."""
    params = params or {}
    hosts = {
        h for dest in _destinations(capability, params)
        if (h := _host_of(dest)) and _is_external_host(h)
    }
    return sorted(hosts)


def classify(capability: str, params: dict | None) -> set[Chokepoint]:
    """Which chokepoints does (capability, params) cross? Deterministic."""
    params = params or {}
    found: set[Chokepoint] = set()
    blob = capability + " " + " ".join(
        f"{k}={v}" for k, v in params.items() if isinstance(v, (str, int, float, bool))
    )

    # EGRESS — any destination resolving outside the perimeter.
    for dest in _destinations(capability, params):
        if _is_external_host(_host_of(dest)):
            found.add(Chokepoint.EGRESS)
            break
    # Capabilities whose whole job is reaching out / a remote.
    if capability in ("web_search", "corpus_ingest", "gh_issue_view") or capability.startswith("http"):
        found.add(Chokepoint.EGRESS)

    # IRREVERSIBLE — destruction or value movement.
    if _IRREVERSIBLE_RE.search(blob) or _MONEY_RE.search(blob):
        found.add(Chokepoint.IRREVERSIBLE)
    if capability in ("git_push", "file_delete") or "delete" in capability or "destroy" in capability:
        found.add(Chokepoint.IRREVERSIBLE)

    # CREDENTIAL — needs a secret to act.
    if _CREDENTIAL_RE.search(blob) or capability in ("fleet_ssh", "git_push", "git_commit"):
        found.add(Chokepoint.CREDENTIAL)

    return found


def contained_class(chokepoints: set[Chokepoint]) -> caps.ApprovalClass | None:
    """The floor a set of chokepoints imposes — None if it imposes nothing."""
    if Chokepoint.IRREVERSIBLE in chokepoints:
        return caps.ApprovalClass.HIGH_STAKES
    if chokepoints & {Chokepoint.EGRESS, Chokepoint.CREDENTIAL}:
        return caps.ApprovalClass.GATED
    return None


def apply(base: caps.ApprovalClass, capability: str, params: dict | None
          ) -> tuple[caps.ApprovalClass, list[str]]:
    """Elevate `base` if the action crosses a chokepoint. Never lowers.

    Returns (effective_class, [chokepoint names]) — the names explain WHY in
    the audit trail and the operator UI.
    """
    chokepoints = classify(capability, params)
    floor = contained_class(chokepoints)
    eff = base
    if floor is not None and _RANK[floor] > _RANK[base]:
        eff = floor
    return eff, sorted(c.value for c in chokepoints)
