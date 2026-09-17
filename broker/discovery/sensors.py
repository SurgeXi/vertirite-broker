# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Discovery sensor registry — the catalog of WHERE Vertirite can be pointed,
and how much of the environment each placement actually sees.

Discovery quality is entirely a function of sensor placement. A laptop-only
install sees one host; the egress proxy sees the whole workforce's outbound
calls; a switch SPAN / NetFlow sees east-west; a host agent sees loopback. This
module is the source-of-truth catalog of those tiers (for the onboarding
"where do I point you?" screen and docs/DISCOVERY-SENSORS.md), plus a derived
status that tells the operator how partial their current view is.

Everything here is customer-directed + opt-in: each source is something the
customer authorises and scopes. We never reach into a network we weren't
pointed at.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .findings import list_findings

# Planes of visibility (see network_sensor.analyze_flow):
#   north-south = crosses the network edge (egress)
#   east-west   = inside the LAN, never exits
#   host-local  = same machine (loopback / IPC)
#
# Each tier: the plane(s) it covers, what it catches, where it sits, how it's
# fed, the consent it needs, the enforcement reality, and build status.
SENSOR_TIERS: List[Dict[str, Any]] = [
    {
        "id": "host-agent-process",
        "title": "Host agent — processes, ports, containers",
        "planes": ["host-local"],
        "feed": "process",
        "catches": "AI client libs, ollama/vLLM, container images, listening ports, "
                   "and PID/user attribution — ON THE HOST IT RUNS ON ONLY.",
        "placement": "Installed on each host you want deep visibility into "
                     "(servers, build hosts, clinical/OT boxes).",
        "method": "the fleet agent process/port/container scan (auditd/eBPF host agent).",
        "consent": "Per-host install — customer authorises each host.",
        "enforcement": "Strong — host firewall / agent can block locally.",
        "status": "built",
    },
    {
        "id": "egress-proxy",
        "title": "Egress proxy logs",
        "planes": ["north-south"],
        "feed": "egress",
        "catches": "Every outbound call from every host behind the proxy — the single "
                   "richest source. ~80% of the surface from one config.",
        "placement": "Point at your forward/egress proxy (Squid, Zscaler, Palo Alto, "
                     "Cloudflare Gateway).",
        "method": "POST access logs to /v1/discovery/ingest/egress (raw_log) or a "
                  "normalised {destination, source} feed.",
        "consent": "Read access to existing proxy logs — no new agents.",
        "enforcement": "Strong — the proxy is ALSO the chokepoint where the broker "
                       "routes/blocks egress.",
        "status": "built",
    },
    {
        "id": "dns-resolver",
        "title": "DNS resolver logs",
        "planes": ["north-south"],
        "feed": "dns",
        "catches": "Every name lookup — even before a connection is made; catches "
                   "intent the proxy might miss.",
        "placement": "Point at internal DNS / AD DNS / Umbrella / Pi-hole query logs.",
        "method": "POST resolver log to /v1/discovery/ingest/dns (raw_log) or a "
                  "normalised {domain, source} feed.",
        "consent": "Read access to existing resolver logs.",
        "enforcement": "Moderate — DNS sinkhole / RPZ can block names.",
        "status": "built",
    },
    {
        "id": "flow-netflow",
        "title": "NetFlow / IPFIX / sFlow from switches & firewalls",
        "planes": ["north-south", "east-west"],
        "feed": "flow",
        "catches": "Machine-to-machine flows INCLUDING east-west — catches hosts that "
                   "bypass the proxy (IoT/OT, servers with direct egress).",
        "placement": "Enable flow export on core/distribution switches + the firewall; "
                     "a collector normalises and forwards.",
        "method": "Collector POSTs normalised flows to /v1/discovery/ingest/flow.",
        "consent": "Network-team change (enable export) — customer-directed.",
        "enforcement": "Indirect — drives switch ACL / segmentation, not the broker.",
        "status": "ingest-built; collector is a node-side deployment component",
    },
    {
        "id": "flow-span-zeek",
        "title": "Switch SPAN / TAP → Zeek",
        "planes": ["east-west", "north-south"],
        "feed": "flow",
        "catches": "Full east-west visibility incl. OT/ICS protocols (Modbus, DNP3, "
                   "EtherNet/IP, OPC-UA) — equipment talking to equipment.",
        "placement": "Mirror a core/OT switch port to a Zeek sensor (passive — no "
                     "inline risk).",
        "method": "Zeek conn.log → /v1/discovery/ingest/flow (raw_log, format=zeek).",
        "consent": "Network-team change (mirror port) — customer-directed.",
        "enforcement": "Indirect — drives segmentation / NAC.",
        "status": "ingest-built (parse_zeek_conn); Zeek sensor is a node-side component",
    },
    {
        "id": "flow-ebpf-host",
        "title": "On-host eBPF agent — socket-level flows",
        "planes": ["host-local", "east-west"],
        "feed": "flow",
        "catches": "Process-to-process over LOOPBACK and per-PID attribution of every "
                   "socket — the ONLY thing that sees same-host IPC. A network tap can't.",
        "placement": "Installed on hosts where loopback/IPC or attribution matters "
                     "(inference boxes, app servers, OT gateways).",
        "method": "Agent emits socket events → /v1/discovery/ingest/flow.",
        "consent": "Per-host install — customer authorises each host.",
        "enforcement": "Strong — agent/host firewall can block locally.",
        "status": "ingest-built; eBPF agent is a node-side deployment component",
    },
]

# Which feeds cover which plane — used to compute how partial the current view is.
_PLANES = ("north-south", "east-west", "host-local")


def _feeds_seen(tenant_id: Optional[str]) -> set:
    """Sensors that have actually produced findings (evidence.sensor)."""
    seen = set()
    for f in list_findings(tenant_id=tenant_id, status_filter=["new", "acknowledged", "governed"]):
        ev = f.get("evidence") or {}
        if isinstance(ev, dict) and ev.get("sensor"):
            seen.add(ev["sensor"])
        # process/container findings don't always carry evidence.sensor:
        if f.get("signal_type") in ("process", "container"):
            seen.add("process")
    return seen


def _planes_seen(tenant_id: Optional[str]) -> set:
    seen = set()
    for f in list_findings(tenant_id=tenant_id, status_filter=["new", "acknowledged", "governed"]):
        ev = f.get("evidence") or {}
        seen.add((ev.get("plane") if isinstance(ev, dict) else None) or "north-south")
    return seen


def discovery_sources(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """The sensor catalog + derived status: which feeds are live, which planes
    are covered, how partial the view is, and what to add next."""
    feeds = _feeds_seen(tenant_id)
    planes = _planes_seen(tenant_id)

    tiers = []
    for t in SENSOR_TIERS:
        tiers.append({**t, "active": t["feed"] in feeds})

    covered = {p: (p in planes) for p in _PLANES}
    # A "partial view" = at least one plane has no coverage. Laptop-only (process
    # signals only, no egress + no flow) is the strongest case.
    has_egress = "egress" in feeds or "dns" in feeds
    has_flow = "flow" in feeds
    partial = not (has_egress and has_flow)

    recs: List[str] = []
    if not has_egress:
        recs.append("Point me at your EGRESS PROXY + DNS logs (Tier 1) — one config, "
                    "sees the whole workforce's outbound calls (~80% of the surface).")
    if not has_flow:
        recs.append("Add NetFlow/IPFIX or a switch SPAN (Tier 2) so I can see EAST-WEST "
                    "traffic — equipment↔equipment that never crosses the edge.")
    if "process" not in feeds:
        recs.append("Install host agents (Tier 3) on key servers / OT / inference boxes "
                    "for loopback (process↔process) + per-PID attribution.")

    return {
        "tiers": tiers,
        "planes_covered": covered,
        "feeds_active": sorted(feeds),
        "partial_view": partial,
        "recommendations": recs,
    }
