# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""The perishable intelligence catalog — schema, decay state machine, resolver.

A signed, versioned, DATED bundle of discovery patterns layered ON TOP of the
open baseline (discovery/patterns.py PATTERN_LIBRARY). The premium layer DECAYS:
once past its signed expiry + grace it drops out and the engine falls back to
baseline-only — a stolen/disconnected copy runs a frozen, rotting brain while the
open broker keeps working.

**Crown-jewel rule:** the baseline NEVER decays. Decay removes only the premium
layer. We don't lock the open broker; we gate the curated intelligence.

Deterministic + inference-free, like the rest of discovery.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..config import settings
from . import signing, store

logger = logging.getLogger("vertirite.intel.catalog")

SCHEMA = "vertirite.intel.v1"

# Freshness states.
FRESH = "fresh"
STALE = "stale"          # past expiry, within grace — premium still trusted
EXPIRED = "expired"      # past grace — premium dropped (the rot)
TAMPERED = "tampered"    # clock rolled back to fake freshness — premium dropped
_PREMIUM_OK = {FRESH, STALE}

# Clock-skew tolerance for the anti-rollback check (legit NTP nudges, VM drift).
_SKEW = timedelta(minutes=5)


class CatalogError(ValueError):
    """A candidate bundle failed verification / schema / version checks."""


@dataclass(frozen=True)
class Catalog:
    catalog_version: int
    issued_at: datetime
    expires_at: datetime
    tenant_scope: str
    patterns: List[Dict[str, Any]]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(s: str) -> datetime:
    dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def verify_and_parse(payload: Dict[str, Any], *, current_version: int = 0) -> Catalog:
    """Validate a candidate bundle. Raises CatalogError on any failure.

    Checks, in order: known schema; valid signature (signing.verify); required
    fields well-formed; ``catalog_version`` strictly greater than the installed
    one (monotonic — blocks replay + downgrade-to-an-older-but-fresher trick).
    """
    if payload.get("schema") != SCHEMA:
        raise CatalogError(f"unknown schema {payload.get('schema')!r}")
    if not signing.verify(payload):
        raise CatalogError("signature invalid or unverifiable")
    try:
        version = int(payload["catalog_version"])
        issued = _parse_dt(payload["issued_at"])
        expires = _parse_dt(payload["expires_at"])
        scope = str(payload.get("tenant_scope", "*"))
        patterns = list(payload["patterns"])
    except (KeyError, ValueError, TypeError) as exc:
        raise CatalogError(f"malformed bundle: {exc}") from exc
    if version <= current_version:
        raise CatalogError(
            f"version {version} is not newer than installed {current_version} (replay/downgrade)"
        )
    if expires <= issued:
        raise CatalogError("expires_at must be after issued_at")
    return Catalog(version, issued, expires, scope, patterns)


def install(tenant_id: str, payload: Dict[str, Any]) -> Catalog:
    """Verify a candidate bundle against the tenant's installed version and
    persist it as the new active catalog. Raises CatalogError on rejection."""
    cat = verify_and_parse(payload, current_version=store.get_max_version(tenant_id))
    store.install_catalog(tenant_id, payload)
    _cache.pop(tenant_id, None)
    logger.info("intel: installed catalog v%d for tenant=%s (expires %s)",
                cat.catalog_version, tenant_id, cat.expires_at.isoformat())
    return cat


def _state_for(cat: Catalog, tenant_id: str) -> str:
    now = _now()
    # Anti-rollback: a clock that reads before the persisted high-water-mark was
    # rolled back to fake freshness. Treat as tampered → premium drops.
    hwm = store.get_clock_hwm(tenant_id)
    if hwm is not None and now < hwm - _SKEW:
        return TAMPERED
    grace = timedelta(days=max(0, settings.intelligence_grace_days))
    if now < cat.expires_at:
        return FRESH
    if now < cat.expires_at + grace:
        return STALE
    return EXPIRED


def _active_catalog(tenant_id: str) -> Optional[Catalog]:
    rec = store.get_active_catalog(tenant_id)
    if rec is None:
        return None
    return Catalog(
        catalog_version=rec["catalog_version"],
        issued_at=_parse_dt(rec["issued_at"]),
        expires_at=_parse_dt(rec["expires_at"]),
        tenant_scope=rec.get("tenant_scope", "*"),
        patterns=rec["patterns"],
    )


def _merge(baseline: List[Dict[str, Any]], premium: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Premium adds new patterns and may refine baseline fields by pattern_id,
    but never removes a baseline entry (crown-jewel rule)."""
    by_id: Dict[str, Dict[str, Any]] = {p["pattern_id"]: dict(p) for p in baseline}
    for p in premium:
        pid = p.get("pattern_id")
        if not pid:
            continue
        if pid in by_id:
            by_id[pid].update(p)
        else:
            by_id[pid] = dict(p)
    return list(by_id.values())


# Resolved-patterns cache: tenant_id -> (monotonic_expiry, merged_patterns).
# A short TTL keeps the hot path (match_host per destination) off the DB. Decay
# flips happen at day-scale boundaries, so ≤TTL latency on a transition is fine;
# install() clears the entry immediately so a fresh catalog takes effect at once.
_CACHE_TTL_S = 30.0
_cache: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}


def active_patterns(tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Baseline PATTERN_LIBRARY merged with the tenant's premium patterns IFF the
    catalog is FRESH/STALE. EXPIRED/TAMPERED or no catalog → baseline-only.

    tenant_id None (or intelligence disabled) → baseline-only, preserving the
    pre-Mechanism-#1 behavior for every existing caller.
    """
    from ..discovery.patterns import PATTERN_LIBRARY

    if not settings.intelligence_enabled or not tenant_id:
        return list(PATTERN_LIBRARY)
    # License gate — premium intelligence requires the 'intelligence' entitlement
    # (no/expired license → free baseline tier).
    from ..licensing.license import entitled
    if not entitled("intelligence"):
        return list(PATTERN_LIBRARY)
    # Mechanism #3 — behavioral binding: a copy in a foreign environment is
    # withheld the premium catalog (immune rejection) when enforcement is on.
    from ..protection import binding
    if binding.enforced() and binding.is_foreign():
        return list(PATTERN_LIBRARY)
    cached = _cache.get(tenant_id)
    if cached and cached[0] > time.monotonic():
        return cached[1]
    cat = _active_catalog(tenant_id)
    if cat is None:
        merged = list(PATTERN_LIBRARY)
    else:
        state = _state_for(cat, tenant_id)
        merged = _merge(PATTERN_LIBRARY, cat.patterns) if state in _PREMIUM_OK else list(PATTERN_LIBRARY)
    _cache[tenant_id] = (time.monotonic() + _CACHE_TTL_S, merged)
    return merged


def catalog_status(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """The freshness/age summary the desktop renders as the visible decay
    indicator. Advances the clock high-water-mark as a side effect (this is a
    cold path, unlike active_patterns)."""
    from ..discovery.patterns import PATTERN_LIBRARY

    # Mechanism #3 — behavioral binding (cold path: bind-if-unset + raise drift
    # finding if foreign). Reported alongside the freshness state.
    from ..protection import binding
    from ..licensing.license import entitled
    bstate = binding.check(tenant_id or "default")
    foreign_block = bool(bstate.get("foreign") and bstate.get("enforced"))
    licensed = entitled("intelligence")  # premium intelligence requires a license

    base = {
        "state": "foreign" if foreign_block else "baseline-only",
        "catalog_version": 0,
        "issued_at": None,
        "expires_at": None,
        "age_days": None,
        "premium_pattern_count": 0,
        "baseline_pattern_count": len(PATTERN_LIBRARY),
        "baseline_only": True,
        "binding": bstate,
    }
    if not settings.intelligence_enabled or not tenant_id:
        return base
    cat = _active_catalog(tenant_id)
    if cat is None:
        return base
    store.advance_clock_hwm(tenant_id, _now())  # advance the monotonic mark
    state = _state_for(cat, tenant_id)
    # A foreign environment under enforcement OR an unlicensed instance → no premium.
    premium_live = state in _PREMIUM_OK and not foreign_block and licensed
    return {
        "state": ("foreign" if foreign_block else ("unlicensed" if not licensed else state)),
        "catalog_version": cat.catalog_version,
        "issued_at": cat.issued_at.isoformat(),
        "expires_at": cat.expires_at.isoformat(),
        "age_days": (_now() - cat.issued_at).days,
        "premium_pattern_count": len(cat.patterns) if premium_live else 0,
        "baseline_pattern_count": len(PATTERN_LIBRARY),
        "baseline_only": not premium_live,
        "binding": bstate,
    }


def clear_cache() -> None:
    """Test hook."""
    _cache.clear()
