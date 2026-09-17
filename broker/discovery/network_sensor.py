# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Network sensors — turn egress + DNS observation into discovery findings.

The host/process sensor (the fleet agent) sees what is RUNNING; these sensors see
what is REACHING OUT. The network is the great equalizer: anything that acts
must cross it, so egress + DNS observation catches the most for the least
deployment (docs/STRATEGY.md, FEATURE-discovery-ungoverned-ai.md, CONTAINMENT.md).

Two inputs, both producing 'network' witnessed findings that flow straight into
the Coverage Map:
  - egress : observed outbound connections (a proxy access log / netflow)
  - dns    : observed DNS queries (a resolver log)

Every external destination is matched against the network pattern catalog
(api.openai.com, Bedrock, Azure OpenAI, …). Known AI services flag
high-confidence; any other external host flags as 'unrecognized external egress'
(low). Internal destinations (RFC1918 / CGNAT 100.64 / .local) are ignored.
Deterministic, inference-free.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from ..containment import _is_external_host as is_external_host
from .findings import report_finding
from .patterns import patterns_by_signal_type, friendly_name

_GENERIC = "net-unrecognized-external-egress"


def _host_only(dest: str) -> str:
    d = (dest or "").strip()
    if "://" in d:
        return (urlparse(d).hostname or "").lower()
    d = d.split("/")[0]
    if d.count(":") == 1:  # host:port (not bare IPv6)
        d = d.split(":")[0]
    return d.lower()


def _vertirite_self_hosts() -> set:
    """Hosts Vertirite ITSELF reaches out to \u2014 its own beacon / brain / AI /
    gateway / feed endpoints \u2014 so the product's own egress is transparently
    SELF-DISCLOSED in discovery instead of mislabelled as unknown external egress
    (or invisible). Derived from the broker's own settings plus an explicit
    VERTIRITE_SELF_HOSTS override. Loopback / no-phone-home sentinels are excluded
    (they never leave the box)."""
    import os
    hosts: set = set()
    try:
        from ..config import settings as _s
        for _a in ("protection_beacon_url", "brain_url", "gateway_url",
                   "surge_core_url", "ollama_url", "ollama_ai_url",
                   "ollama_storage_url", "intelligence_feed_url"):
            _h = _host_only(getattr(_s, _a, "") or "")
            if _h and _h not in ("127.0.0.1", "localhost", "0.0.0.0"):
                hosts.add(_h)
    except Exception:
        pass
    for _h in (os.environ.get("VERTIRITE_SELF_HOSTS", "") or "").split(","):
        _h = _host_only(_h.strip())
        if _h:
            hosts.add(_h)
    return hosts


def match_host(host: str, tenant_id: Optional[str] = None) -> Optional[str]:
    """The network pattern_id matching `host`, or None for an internal host.

    External hosts matching no named AI service fall back to the generic
    'unrecognized external egress' pattern, so the full external surface shows.

    ``tenant_id`` selects that tenant's ACTIVE catalog (Mechanism #1): when the
    premium layer has decayed, premium-only patterns drop out and their hosts
    fall back to the generic catch-all — the rot, made observable.
    """
    h = _host_only(host)
    if h and h in _vertirite_self_hosts():
        return "self-vertirite-egress"   # the product disclosing its own egress
    if not is_external_host(h):
        return None
    for p in patterns_by_signal_type("network", tenant_id):
        if p["pattern_id"] == _GENERIC:
            continue
        host_re = p.get("match", {}).get("host_re")
        if host_re and re.search(host_re, h):
            return p["pattern_id"]
    return _GENERIC


def _report(dest: str, source: str, tenant_id: str, sensor: str) -> Optional[dict]:
    pid = match_host(dest, tenant_id)
    if pid is None:
        return None  # internal — ignored on the EGRESS path (use analyze_flow for east-west)
    return report_finding(
        tenant_id=tenant_id,
        source_host_id=source or "unknown",
        target_hostname=_host_only(dest),
        signal_type="network",
        pattern_id=pid,
        # egress/dns are north-south by definition.
        evidence={"sensor": sensor, "plane": "north-south", "observed_destination": dest, "friendly_name": friendly_name(pid)},
    )


def analyze_egress(observations: Iterable[dict], *, tenant_id: str) -> Dict[str, Any]:
    """observations: [{"destination": host_or_url, "source": host_id}, ...]."""
    reported = ai = 0
    for o in observations or []:
        r = _report(o.get("destination", ""), o.get("source", ""), tenant_id, "egress")
        if r:
            reported += 1
            ai += (r.get("pattern_id") != _GENERIC)
    return {"sensor": "egress", "reported": reported, "ai_services": ai}


def analyze_dns(queries: Iterable[dict], *, tenant_id: str) -> Dict[str, Any]:
    """queries: [{"domain": fqdn, "source": host_id}, ...]."""
    reported = ai = 0
    for q in queries or []:
        r = _report(q.get("domain", ""), q.get("source", ""), tenant_id, "dns")
        if r:
            reported += 1
            ai += (r.get("pattern_id") != _GENERIC)
    return {"sensor": "dns", "reported": reported, "ai_services": ai}


# --- east-west / internal flow sensor ---------------------------------------
# The egress/DNS tier above is BLIND to traffic that never leaves the network
# (PLC↔PLC, server↔server, a vendor box → an internal DB, an internal Ollama
# serving other hosts). This tier consumes connection FLOWS from inside the
# fabric — a NetFlow/IPFIX/sFlow collector, a switch SPAN/TAP via Zeek
# (conn.log), or an on-host eBPF agent — and records them with their network
# "plane" so the Coverage Map can show internal exposure alongside egress.

_LLM_PORTS = {11434, 8000, 8080, 1234, 5000}          # Ollama / vLLM / common inference
_OT_PORTS = {502, 20000, 44818, 4840, 2404, 102, 47808, 1911, 9600}  # Modbus/DNP3/ENIP/OPC-UA/IEC-104/BACnet
_LOOPBACK_RE = re.compile(r"^(127\.\d+\.\d+\.\d+|::1|localhost)$")


def _is_loopback(host: str) -> bool:
    return bool(_LOOPBACK_RE.match((host or "").strip().lower()))


def _classify_flow(dst: str, dst_port: Any, src: str,
                   tenant_id: Optional[str] = None) -> tuple[str, Optional[str]]:
    """Return (plane, pattern_id). plane ∈ {north-south, east-west, host-local}."""
    h = _host_only(dst)
    if not h:
        return "east-west", None
    if _is_loopback(h) or (src and h == _host_only(src)):
        return "host-local", "net-host-local-ipc"
    if is_external_host(h):
        return "north-south", (match_host(dst, tenant_id) or _GENERIC)
    try:
        port = int(dst_port)
    except (TypeError, ValueError):
        port = 0
    if port in _LLM_PORTS:
        return "east-west", "net-internal-llm-port"
    if port in _OT_PORTS:
        return "east-west", "net-ot-protocol"
    return "east-west", "net-internal-lateral"


def analyze_flow(flows: Iterable[dict], *, tenant_id: str) -> Dict[str, Any]:
    """flows: [{"src", "dst", "dst_port", "proto", "plane"?}, ...].

    Records internal AND external connections, tagged by plane — the east-west
    blind spot the egress tier can't see. `plane` in a flow is advisory; we
    re-derive it so a mislabeled collector can't smuggle internal traffic past.
    """
    by_plane: Dict[str, int] = {"north-south": 0, "east-west": 0, "host-local": 0}
    reported = 0
    for f in flows or []:
        dst = f.get("dst") or f.get("destination") or ""
        if not dst:
            continue
        plane, pid = _classify_flow(dst, f.get("dst_port") or f.get("port"),
                                    f.get("src") or f.get("source") or "", tenant_id)
        if pid is None:
            continue
        r = report_finding(
            tenant_id=tenant_id,
            source_host_id=(f.get("src") or f.get("source") or "unknown"),
            target_hostname=_host_only(dst),
            signal_type="network",
            pattern_id=pid,
            evidence={"sensor": "flow", "plane": plane,
                      "dst_port": f.get("dst_port") or f.get("port"),
                      "proto": (f.get("proto") or "tcp")},
        )
        if r:
            reported += 1
            by_plane[plane] = by_plane.get(plane, 0) + 1
    return {"sensor": "flow", "reported": reported, "by_plane": by_plane}


# --- log parsers: raw sensor logs -> observations ---------------------------

def parse_squid_log(text: str) -> List[dict]:
    """Squid access.log -> egress observations.

    `<ts> <client> <status> <bytes> <method> <url> <ident> <mime>`
    e.g. `... 10.0.0.5 NONE_NONE/200 0 CONNECT api.openai.com:443 - -`
         `... 10.0.0.5 TCP_MISS/200 921 GET http://example.com/ - text/html`
    """
    out: List[dict] = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        host = _host_only(parts[5])
        if host:
            out.append({"destination": host, "source": parts[1]})
    return out


_DNS_RE = re.compile(r"query\[[A-Z]+\]\s+(?P<domain>\S+)\s+from\s+(?P<src>\S+)", re.I)


def parse_dns_log(text: str) -> List[dict]:
    """Resolver log (dnsmasq-style) -> dns queries.

    e.g. `... dnsmasq[123]: query[A] api.openai.com from 10.0.0.5`
    """
    return [{"domain": m.group("domain"), "source": m.group("src")}
            for m in _DNS_RE.finditer(text or "")]


# Default Zeek conn.log column order (used when no #fields header is present).
_ZEEK_DEFAULT = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h",
                 "id.resp_p", "proto"]


def parse_zeek_conn(text: str) -> List[dict]:
    """Zeek conn.log (TSV) -> flows. Honours a `#fields` header if present;
    falls back to the default column order otherwise. This is the switch
    SPAN/TAP path — it carries internal (east-west) connections too.

    e.g. `1622... Cabc 10.0.0.5 51920 10.0.0.9 502 tcp ...`  (a Modbus flow)
    """
    cols = _ZEEK_DEFAULT
    out: List[dict] = []
    for line in (text or "").splitlines():
        if line.startswith("#fields"):
            cols = line.split("\t")[1:]
            continue
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t") if "\t" in line else line.split()
        rec = {cols[i]: parts[i] for i in range(min(len(cols), len(parts)))}
        dst = rec.get("id.resp_h")
        if not dst:
            continue
        out.append({"src": rec.get("id.orig_h", ""), "dst": dst,
                    "dst_port": rec.get("id.resp_p"), "proto": rec.get("proto", "tcp")})
    return out
