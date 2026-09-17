# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from .config import settings
from .governor_store import get_local_mode
from .models import SurgeMode

logger = logging.getLogger("vertirite.core_client")


# Explicit restrictiveness rank. The SurgeMode enum's DECLARATION order is NOT
# restrictiveness order (LOCKDOWN is declared before ESCALATION_REQUIRED), so
# never infer restrictiveness from the enum — always rank through this map.
# Higher rank == more restrictive == tighter containment.
_RESTRICTIVENESS: dict[SurgeMode, int] = {
    SurgeMode.AUTONOMOUS: 0,
    SurgeMode.CONTROLLED: 1,
    SurgeMode.ESCALATION_REQUIRED: 2,
    SurgeMode.LOCKDOWN: 3,
}


def _rank(mode: SurgeMode) -> int:
    return _RESTRICTIVENESS[mode]


def effective_mode(local: SurgeMode, surge_core: Optional[SurgeMode]) -> SurgeMode:
    """Compose the effective mode from the local authority + optional upstream.

    The LOCAL mode is authoritative. surge-core is an OPTIONAL upstream that can
    only TIGHTEN: it is honored ONLY when it reports a mode strictly MORE
    restrictive than local. It can never loosen local (an upstream returning a
    less-restrictive mode is ignored), and when it is absent/unreachable
    (``surge_core is None``) the local mode stands — never a downgrade.
    """
    if surge_core is not None and _rank(surge_core) > _rank(local):
        return surge_core
    return local


# --- surge-core READ cache (30s). Caches ONLY the upstream read; the local
# authoritative mode is always read live from the store. ---
_cached_mode: Optional[SurgeMode] = None  # last surge-core mode, or None if unreachable/unknown
_cache_time: float = 0
_MODE_CACHE_TTL = 30.0  # re-check surge-core every 30 seconds, not every request
_surge_core_reachable: bool = False


def is_surge_core_reachable() -> bool:
    """Public read of the last-known surge-core reachability flag.

    Surfaced on the broker's /health response so operators can see surge-core
    state without having to grep the cached mode and infer from staleness.
    """
    return _surge_core_reachable


def last_surge_core_mode() -> Optional[SurgeMode]:
    """Last mode surge-core reported (from the 30s cache), or None when
    surge-core is unreachable / unconfigured / returned an unknown mode.
    Surfaced on GET /v1/mode."""
    return _cached_mode


async def _read_surge_core_mode() -> Optional[SurgeMode]:
    """Cached (30s) read of surge-core's reported mode.

    Returns None when surge-core is not configured, unreachable, or returns a
    mode this broker doesn't recognize. Updates the reachability flag surfaced
    by is_surge_core_reachable(). Logs only on reachability *transitions* so a
    sustained outage doesn't flood the log every 30s.
    """
    import time
    global _cached_mode, _cache_time, _surge_core_reachable

    if not settings.surge_core_url:
        _surge_core_reachable = False
        _cached_mode = None
        return None

    now = time.time()
    # Return cached upstream mode if still fresh
    if (now - _cache_time) < _MODE_CACHE_TTL:
        return _cached_mode

    # If we know surge-core is down, use a shorter timeout
    timeout = 1.5 if not _surge_core_reachable else 3.0
    was_reachable = _surge_core_reachable

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(f"{settings.surge_core_url}/state")
            response.raise_for_status()
            # surge-core's Go service returns the mode as plain text ("AUTONOMOUS\n").
            # Older deployments or future revisions may return JSON {"mode": "..."}.
            # Accept either so the broker doesn't break across surge-core versions.
            ctype = response.headers.get("content-type", "").lower()
            if "json" in ctype:
                mode = (response.json() or {}).get("mode", "")
            else:
                mode = response.text.strip()
        if not was_reachable:
            logger.info("surge-core recovered at %s", settings.surge_core_url)
        _surge_core_reachable = True
    except Exception as e:
        if was_reachable:
            logger.warning(
                "surge-core unreachable at %s — local mode authority stands (%s)",
                settings.surge_core_url, e,
            )
        _surge_core_reachable = False
        _cache_time = now  # cache the failure so we don't retry immediately
        _cached_mode = None
        return None

    try:
        _cached_mode = SurgeMode(mode)
        _cache_time = now
        return _cached_mode
    except ValueError:
        logger.warning("surge-core returned unknown mode %r — ignoring (local mode stands)", mode)
        _cache_time = now
        _cached_mode = None
        return None


async def fetch_mode() -> SurgeMode:
    """Return the EFFECTIVE SurgeMode (the mode the gate enforces).

    Base authority is the LOCAL mode store (get_local_mode) — this is what makes
    LOCKDOWN engageable without surge-core. surge-core, when configured and
    reachable, is an OPTIONAL upstream that can only TIGHTEN: it is honored only
    when strictly more restrictive than local. On surge-core outage the local
    mode stands (never a downgrade). The name is preserved so every existing
    call site transparently gets the correct effective mode.
    """
    local = get_local_mode()
    upstream = await _read_surge_core_mode()  # cached 30s; None if unreachable/unset/unknown

    # TIGHTEN-ONLY clamp, enforced HERE at the surge-core ingestion point — not
    # delegated to effective_mode alone, so a future refactor of that helper
    # cannot silently route around it. surge-core is honored ONLY when it
    # strictly RAISES restrictiveness above local; a compromised/spoofed upstream
    # sending a LESS restrictive mode (e.g. AUTONOMOUS while local is LOCKDOWN)
    # is discarded. This is exactly max(local, upstream) by rank.
    if upstream is not None and _rank(upstream) > _rank(local):
        return upstream
    return local


async def submit_approval_task(payload: dict[str, Any]) -> Optional[str]:
    if not settings.forward_approvals_to_surge_core:
        return None

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(f"{settings.surge_core_url}/task", json=payload)
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        logger.warning(
            "Failed to submit approval task to surge-core at %s: %s",
            settings.surge_core_url, exc,
        )
        return None

    task_id = data.get("id") or data.get("task_id")
    logger.info("Approval task submitted to surge-core: task_id=%s", task_id)
    return str(task_id) if task_id else None


async def submit_approval_decision(surge_task_id: str) -> bool:
    if not settings.forward_approvals_to_surge_core:
        return False

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(f"{settings.surge_core_url}/approve/{surge_task_id}")
            response.raise_for_status()
    except Exception as exc:
        logger.warning(
            "Failed to submit approval decision for task %s at %s: %s",
            surge_task_id, settings.surge_core_url, exc,
        )
        return False
    logger.info("Approval decision submitted for surge-core task: %s", surge_task_id)
    return True
