# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""agent_baseline — each governed agent's learned-normal behavior.

One row per (tenant_id, actor_id): the allow-sets and flags that describe what
this agent has been observed doing. Break detection compares each new action
against this baseline; a deviation is a break (see ``detector.py``).

Cold-start / warm-up (docs/FEATURE-break-detection.md, resolved decisions):
  * A brand-new agent starts ``warming``. While warming, the *novelty* signals
    (novel egress, first credential) are LEARNED rather than raised — a new
    agent where everything is new must not spray false breaks.
  * The *forbidden/dangerous* signals (irreversible attempt, scope violation,
    denial burst) fire immediately regardless of warm-up (``detector.py``).
  * The baseline flips to ``warm`` after WARMUP_MIN_ACTIONS actions or
    WARMUP_DAYS since first sight, whichever comes first. Once warm, novel
    items are NOT auto-learned — they raise a break and wait for the operator.

P2 adds the *statistical* bands (all learned while warming, frozen once warm):
active-hour set, the data-class set, and a rolling rate band (max actions seen
in a RATE_WINDOW_S window). Still deterministic — plain counts/sets, no model.

Everything here is metadata only (capability names, external hostnames, hour
buckets, data-class labels, counts) — never payload, never PII.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional, Set

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ...db import Base, session_scope

# Tunable knobs. Small enough to be practical per-agent; the doc's "500" was
# illustrative.
WARMUP_MIN_ACTIONS = 50
WARMUP_DAYS = 7
RATE_WINDOW_S = 300  # rolling window for the actions-per-window rate band

STATES = ("warming", "warm")

# Deterministic data-class tagging (P2). First match wins; None = unclassified.
_DATACLASS_PATTERNS = {
    "phi": re.compile(r"\b(phi|patient|medical|clinical|diagnos|health|hipaa|mrn|icd\d)\b", re.I),
    "financial": re.compile(r"\b(invoice|ledger|payroll|payment|\btax\b|wire|bank|gaap|revenue|ach)\b", re.I),
    "pii": re.compile(r"\b(ssn|passport|driver_?licen|date_of_birth|\bdob\b)\b", re.I),
}


def dataclass_of(capability: str, params: Optional[dict]) -> Optional[str]:
    """Label the sensitive data-class this action touches (phi/financial/pii), or
    None. Keyword heuristic over the capability + string params — deterministic."""
    blob = (capability or "") + " " + " ".join(
        str(v) for v in (params or {}).values() if isinstance(v, (str, int)))
    for cls, rx in _DATACLASS_PATTERNS.items():
        if rx.search(blob):
            return cls
    return None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _bid(tenant_id: str, actor_id: str) -> str:
    return f"{tenant_id}::{actor_id}"


class AgentBaselineTable(Base):
    __tablename__ = "agent_baseline"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)  # tenant::actor
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    capabilities: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    egress_destinations: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    data_classes: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    active_hours: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    credential_seen: Mapped[bool] = mapped_column(default=False)
    irreversible_seen: Mapped[bool] = mapped_column(default=False)

    action_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="warming", index=True)

    recent_denials: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    # P2: rolling action timestamps (rate) + the learned rate-band ceiling.
    recent_actions: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    rate_band_max: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


@dataclass(frozen=True)
class Baseline:
    """Immutable snapshot handed to the detector (decoupled from the session)."""
    tenant_id: str
    actor_id: str
    capabilities: Set[str] = field(default_factory=set)
    egress_destinations: Set[str] = field(default_factory=set)
    data_classes: Set[str] = field(default_factory=set)
    active_hours: Set[int] = field(default_factory=set)
    credential_seen: bool = False
    irreversible_seen: bool = False
    action_count: int = 0
    state: str = "warming"
    rate_band_max: int = 0
    recent_rate: int = 0   # transient: current rolling-window count (post-observe)

    @property
    def is_warm(self) -> bool:
        return self.state == "warm"


def _load_json_set(raw: str) -> set:
    try:
        return set(json.loads(raw) if raw else [])
    except Exception:
        return set()


def _snapshot(row: AgentBaselineTable, recent_rate: int = 0) -> Baseline:
    return Baseline(
        tenant_id=row.tenant_id,
        actor_id=row.actor_id,
        capabilities=_load_json_set(row.capabilities),
        egress_destinations=_load_json_set(row.egress_destinations),
        data_classes=_load_json_set(row.data_classes),
        active_hours={int(h) for h in _load_json_set(row.active_hours)},
        credential_seen=bool(row.credential_seen),
        irreversible_seen=bool(row.irreversible_seen),
        action_count=row.action_count,
        state=row.state,
        rate_band_max=row.rate_band_max or 0,
        recent_rate=recent_rate,
    )


def _get_or_create(db, tenant_id: str, actor_id: str) -> AgentBaselineTable:
    bid = _bid(tenant_id, actor_id)
    row = db.get(AgentBaselineTable, bid)
    if row is None:
        row = AgentBaselineTable(id=bid, tenant_id=tenant_id, actor_id=actor_id)
        # Seed the per-vertical prior (cold-start expectations); the learned
        # per-agent baseline overrides it as the agent warms.
        try:
            from . import priors as _priors
            p = _priors.prior_for(tenant_id)
            if p and p.get("data_classes"):
                row.data_classes = json.dumps(sorted(set(p["data_classes"])))
        except Exception:
            pass
        db.add(row)
        db.flush()
    return row


def load(tenant_id: str, actor_id: str) -> Baseline:
    """Snapshot the agent's baseline (creating an empty warming row if new)."""
    with session_scope() as db:
        return _snapshot(_get_or_create(db, tenant_id, actor_id))


def _maybe_warm(row: AgentBaselineTable) -> None:
    if row.state == "warm":
        return
    if row.action_count >= WARMUP_MIN_ACTIONS:
        row.state = "warm"
        return
    fs = row.first_seen_at
    if fs is not None:
        if fs.tzinfo is None:   # sqlite returns naive; treat as UTC
            fs = fs.replace(tzinfo=timezone.utc)
        if _utc_now() - fs >= timedelta(days=WARMUP_DAYS):
            row.state = "warm"


def _window_count(raw: str, now: datetime) -> tuple[list[str], int]:
    """Prune a rolling iso-timestamp list to RATE_WINDOW_S and return (kept, count)."""
    cutoff = now - timedelta(seconds=RATE_WINDOW_S)
    kept = []
    for s in _load_json_set(raw):
        try:
            if datetime.fromisoformat(s) >= cutoff:
                kept.append(s)
        except Exception:
            pass
    return kept, len(kept)


def observe(tenant_id: str, actor_id: str, capability: str,
            chokepoints: list[str], external_dests: list[str],
            data_class: Optional[str] = None, now: Optional[datetime] = None) -> Baseline:
    """Record one observed action. While ``warming`` this LEARNS (capabilities,
    destinations, data-classes, active hours, credential/irreversible flags, and
    the rate-band ceiling). Once ``warm`` it advances counters + the rolling rate
    but does NOT widen the learned allow-sets/bands — novel items are left for the
    detector to flag and the operator to fold in via ``learn``. Returns the
    post-observe snapshot, with ``recent_rate`` = the current rolling-window count.
    """
    now = now or _utc_now()
    with session_scope() as db:
        row = _get_or_create(db, tenant_id, actor_id)
        row.action_count += 1
        row.last_seen_at = now

        # Rolling rate (always tracked; band only widens while warming).
        kept, _ = _window_count(row.recent_actions, now)
        kept.append(now.isoformat())
        current_rate = len(kept)
        row.recent_actions = json.dumps(sorted(kept))

        hours = {int(h) for h in _load_json_set(row.active_hours)}

        if row.state == "warming":
            hours.add(now.hour)
            caps_ = _load_json_set(row.capabilities); caps_.add(capability)
            row.capabilities = json.dumps(sorted(caps_))
            if external_dests:
                dests = _load_json_set(row.egress_destinations)
                dests.update(external_dests)
                row.egress_destinations = json.dumps(sorted(dests))
            if data_class:
                dcs = _load_json_set(row.data_classes); dcs.add(data_class)
                row.data_classes = json.dumps(sorted(dcs))
            if "credential" in chokepoints:
                row.credential_seen = True
            if "irreversible" in chokepoints:
                row.irreversible_seen = True
            if current_rate > (row.rate_band_max or 0):
                row.rate_band_max = current_rate
        row.active_hours = json.dumps(sorted(hours))

        _maybe_warm(row)
        db.flush()
        return _snapshot(row, recent_rate=current_rate)


def learn(tenant_id: str, actor_id: str, *, capability: Optional[str] = None,
          dest: Optional[str] = None, data_class: Optional[str] = None,
          hour: Optional[int] = None, rate_band: Optional[int] = None,
          credential: bool = False, irreversible: bool = False) -> Baseline:
    """Fold a specific behavior into the baseline — the confirm-and-learn path
    called when an operator acknowledges a break as expected/benign."""
    with session_scope() as db:
        row = _get_or_create(db, tenant_id, actor_id)
        if capability:
            caps_ = _load_json_set(row.capabilities); caps_.add(capability)
            row.capabilities = json.dumps(sorted(caps_))
        if dest:
            dests = _load_json_set(row.egress_destinations); dests.add(dest)
            row.egress_destinations = json.dumps(sorted(dests))
        if data_class:
            dcs = _load_json_set(row.data_classes); dcs.add(data_class)
            row.data_classes = json.dumps(sorted(dcs))
        if hour is not None:
            hrs = {int(h) for h in _load_json_set(row.active_hours)}; hrs.add(int(hour))
            row.active_hours = json.dumps(sorted(hrs))
        if rate_band is not None and int(rate_band) > (row.rate_band_max or 0):
            row.rate_band_max = int(rate_band)
        if credential:
            row.credential_seen = True
        if irreversible:
            row.irreversible_seen = True
        db.flush()
        return _snapshot(row)


def record_denial(tenant_id: str, actor_id: str, now: Optional[datetime] = None,
                  window_s: int = 300) -> int:
    """Append a denial timestamp, prune to the window, return the count in it."""
    now = now or _utc_now()
    cutoff = now - timedelta(seconds=window_s)
    with session_scope() as db:
        row = _get_or_create(db, tenant_id, actor_id)
        stamps = []
        for s in _load_json_set(row.recent_denials):
            try:
                if datetime.fromisoformat(s) >= cutoff:
                    stamps.append(s)
            except Exception:
                pass
        stamps.append(now.isoformat())
        row.recent_denials = json.dumps(sorted(stamps))
        db.flush()
        return len(stamps)


def get(tenant_id: str, actor_id: str) -> Optional[dict]:
    """Read-only view for the API (returns None if the agent has no baseline)."""
    with session_scope() as db:
        row = db.get(AgentBaselineTable, _bid(tenant_id, actor_id))
        if row is None:
            return None
        _, rate = _window_count(row.recent_actions, _utc_now())
        return {
            "tenant_id": row.tenant_id,
            "actor_id": row.actor_id,
            "state": row.state,
            "action_count": row.action_count,
            "capabilities": sorted(_load_json_set(row.capabilities)),
            "egress_destinations": sorted(_load_json_set(row.egress_destinations)),
            "data_classes": sorted(_load_json_set(row.data_classes)),
            "active_hours": sorted(int(h) for h in _load_json_set(row.active_hours)),
            "credential_seen": bool(row.credential_seen),
            "irreversible_seen": bool(row.irreversible_seen),
            "rate_band_max": row.rate_band_max or 0,
            "recent_rate": rate,
            "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
            "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        }
