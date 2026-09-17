# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Coverage Map — the strategic roll-up over witnessed findings.

Pillar B (``findings.py``) records each "witnessed but unsanctioned"
observation: AI-shaped activity that did NOT route through the broker. This
module turns those findings into the answer the strategy calls for
(docs/STRATEGY.md):

    coverage = GOVERNED ÷ (GOVERNED + UNGOVERNED)

It surfaces the ungoverned gap **highest-signal-first** (likely external AI
services before generic automation), each carrying its "bring under governance"
status — the day-one exposure map and the upsell worklist. Deterministic and
inference-free, like the rest of the gate.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .findings import list_findings
from .remediation import remediation_summary

# Open findings are the ungoverned gap. 'governed' = the operator brought it
# under governance (closed). 'dismissed' = the operator judged it fine; it is
# excluded from the coverage ratio entirely (neither gap nor win).
_UNGOVERNED_STATUSES = ["new", "acknowledged"]
_GOVERNED_STATUSES = ["governed"]

# Heuristic tier-1: which findings look like an external AI service (the
# highest-signal ungoverned findings). Extend via a data file later.
_AI_MARKERS = (
    "openai", "anthropic", "claude", "gpt", "gemini", "bedrock", "cohere",
    "mistral", "perplexity", "huggingface", "llm", "ai-api", "azure-openai",
    "groq", "deepseek", "x.ai", "langchain", "llamaindex", "transformers", "llama",
)
_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}


# Markers for suspicious / malicious egress — the threat tier (patterns.py
# 'suspicious-egress' category). Ranked ABOVE sanctioned AI: a crypto-miner or
# an exfil channel is more urgent than "you have an OpenAI key."
_THREAT_MARKERS = (
    "crypto", "mining", "miner", "exfil", "paste", "webhook-exfil", "ngrok",
    "pipedream", "requestbin", "unsanctioned", "shadow", "suspicious", "c2-",
    "beacon", "deepseek", "openrouter",
    # self-protection (Mechanism #2): a suppressed governance channel is the
    # single most suspicious thing we can see — rank it at the top.
    "suppressed",
)
# NB: "c2-" (hyphenated), not bare "c2" — bare "c2" false-positived on "ec2".


# Tier-1.5: UNKNOWN / unclassified. Vertirite does not pretend to know what this
# is — an artifact whose *shape* is unrecognized (a raw IP, a non-standard port,
# a disposable/odd TLD). It is NOT confirmed malicious and NOT a known AI service;
# it is "I don't recognize this — investigate." It ranks ABOVE ordinary baseline
# internet (so the operator sees it) but BELOW confirmed threats + AI. Discovery
# never auto-acts on it (surface-and-rank posture, docs/DEMO-PHILOSOPHY.md).
_RAW_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$")
_PORT_RE = re.compile(r":(\d+)$")
# Disposable / commonly-abused / freshly-registered TLDs: shape-suspicious but
# not, by themselves, proof of anything — exactly what "needs investigation" means.
_ODD_TLDS = (
    ".win", ".top", ".xyz", ".click", ".sbs", ".work", ".gq", ".cf", ".tk",
    ".ml", ".ga", ".rest", ".zip", ".mov", ".lol", ".monster", ".quest", ".cyou",
)


# The unknown tier means "an EXTERNAL host the sensor couldn't name" — i.e. it
# fell to the generic catch-all. Internal/east-west traffic is all bare IPs by
# nature, so shape alone would mislabel ordinary internal flows; those surface
# via the east-west plane + their own patterns (OT, internal-LLM, lateral),
# not the unknown tier.
_GENERIC_PATTERN_IDS = ("net-unrecognized-external-egress",)


def _looks_unknown(finding: Dict[str, Any]) -> bool:
    host = str(finding.get("target_hostname", "")).lower().strip()
    if not host:
        return False
    if _RAW_IP_RE.match(host):           # connecting to a bare IP — no name to trust
        return True
    m = _PORT_RE.search(host)
    if m and m.group(1) not in ("80", "443"):  # non-web port on an external host
        return True
    if host.split(":")[0].endswith(_ODD_TLDS):  # disposable / odd TLD
        return True
    return False


def _blob(finding: Dict[str, Any]) -> str:
    return " ".join(
        str(finding.get(k, ""))
        for k in ("pattern_id", "pattern_name", "target_hostname", "signal_type")
    ).lower()


def _looks_like_ai_service(finding: Dict[str, Any]) -> bool:
    return any(m in _blob(finding) for m in _AI_MARKERS)


def _looks_suspicious(finding: Dict[str, Any]) -> bool:
    return any(m in _blob(finding) for m in _THREAT_MARKERS)


def coverage_map(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """SEEN − GOVERNED, as a coverage ratio + the ranked ungoverned worklist."""
    governed = list_findings(tenant_id=tenant_id, status_filter=_GOVERNED_STATUSES)
    ungoverned = list_findings(tenant_id=tenant_id, status_filter=_UNGOVERNED_STATUSES)

    # Tag each finding so the UI can badge it, then rank: THREATS first, then
    # sanctioned AI, then UNKNOWN/unclassified, then confidence, then most-seen.
    # Each finding gets exactly one primary tier (threat > ai > unknown > baseline).
    for f in ungoverned:
        f["suspicious"] = _looks_suspicious(f)
        f["is_ai_service"] = _looks_like_ai_service(f)
        # self-finding (Mechanism #2): the product narcing on its own suppressed
        # governance channel. Badged distinctly in the UI.
        f["is_self"] = str(f.get("pattern_id", "")).startswith("self-")
        f["unclassified"] = (
            not f["suspicious"] and not f["is_ai_service"]
            and f.get("pattern_id") in _GENERIC_PATTERN_IDS
            and _looks_unknown(f))
        # plane: north-south (egress) | east-west (internal) | host-local (loopback).
        # Orthogonal to tier — an east-west finding can also be AI or unknown.
        f["plane"] = (f.get("evidence") or {}).get("plane", "north-south")
        # one-line "how to govern" hint; full BLOCK/ROUTE guidance via the
        # /v1/discovery/findings/{id}/remediation endpoint on expand.
        f["remediation"] = remediation_summary(f)
    ungoverned.sort(key=lambda f: (
        not f["suspicious"],
        not f["is_ai_service"],
        not f["unclassified"],
        _CONFIDENCE_RANK.get(f.get("confidence", "medium"), 1),
        -int(f.get("occurrence_count", 1) or 1),
    ))

    denom = len(governed) + len(ungoverned)
    coverage_pct = round(100.0 * len(governed) / denom, 1) if denom else 100.0

    return {
        "coverage_pct": coverage_pct,
        "counts": {
            "witnessed": denom,
            "governed": len(governed),
            "ungoverned": len(ungoverned),
            "ungoverned_ai_services": sum(1 for f in ungoverned if f["is_ai_service"]),
            "ungoverned_suspicious": sum(1 for f in ungoverned if f["suspicious"]),
            "ungoverned_unknown": sum(1 for f in ungoverned if f["unclassified"]),
            "ungoverned_self": sum(1 for f in ungoverned if f["is_self"]),
            # by network plane — egress vs internal vs same-host:
            "north_south": sum(1 for f in ungoverned if f["plane"] == "north-south"),
            "east_west": sum(1 for f in ungoverned if f["plane"] == "east-west"),
            "host_local": sum(1 for f in ungoverned if f["plane"] == "host-local"),
        },
        # The "bring under governance" worklist, threats first.
        "ungoverned": ungoverned,
    }
