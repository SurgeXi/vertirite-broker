# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""License verification, install, and the entitlement check.

Gates PREMIUM features, not broker startup. ``entitled(feature)`` is the single
question the rest of the product asks. No license or expired → free/baseline tier
(open discovery still works).
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from ..config import settings
from . import signing, store

logger = logging.getLogger("vertirite.licensing")

SCHEMA = "vertirite.license.v1"
# Gateable premium features — the broker (INCLUDING the full governance surface) is
# BSL-open and free. The license gates the four premium MODULES only; governance is
# never gated. Open-core: the broker is free and inspectable, and the pilot buys the
# program — capability-registry design, coverage-map interpretation, the auditor-
# accepted artifact, these four modules, and federation across sites.
KNOWN_FEATURES = ("intelligence", "enforcement", "federation", "vertical-packs")

VALID = "valid"
EXPIRED = "expired"
TAMPERED = "tampered"   # clock rolled back to revive an expired license
NONE = "none"

_CLOCK_KEY = "__license__"   # reuses the Mechanism #1 monotonic clock HWM
_SKEW = timedelta(minutes=5)

_CACHE_TTL_S = 30.0
_cache: Optional[Tuple[float, Dict[str, Any]]] = None


class LicenseError(ValueError):
    """A candidate license failed verification / schema / field checks."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(s: str) -> datetime:
    dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def verify_and_parse(payload: Dict[str, Any]):
    if payload.get("schema") != SCHEMA:
        raise LicenseError(f"unknown schema {payload.get('schema')!r}")
    if not signing.verify(payload):
        raise LicenseError("signature invalid or unverifiable")
    try:
        issued = _parse_dt(payload["issued_at"])
        expires = _parse_dt(payload["expires_at"])
        features = list(payload.get("features", []) or [])
    except (KeyError, ValueError, TypeError) as exc:
        raise LicenseError(f"malformed license: {exc}") from exc
    if expires <= issued:
        raise LicenseError("expires_at must be after issued_at")
    return issued, expires, features


def install(payload: Dict[str, Any]) -> Dict[str, Any]:
    issued, expires, _ = verify_and_parse(payload)
    store.install(payload, issued, expires)
    _clear()
    logger.info("license: installed %s sku=%s expires %s",
                payload.get("license_id"), payload.get("sku"), expires.isoformat())
    return license_state()


def _clock_tampered() -> bool:
    """Anti-rollback: reuse the Mechanism #1 monotonic clock HWM. If the system
    clock reads before the high-water-mark, it was rolled back (to revive an
    expired license). Otherwise advance the mark."""
    from ..intelligence import store as intel_store
    now = _now()
    hwm = intel_store.get_clock_hwm(_CLOCK_KEY)
    if hwm is not None and now < hwm - _SKEW:
        return True
    intel_store.advance_clock_hwm(_CLOCK_KEY, now)
    return False


def license_state() -> Dict[str, Any]:
    rec = store.get()
    if rec is None:
        return {"state": NONE, "sku": None, "customer": None,
                "features": [], "expires_at": None, "days_left": None}
    now = _now()
    if _clock_tampered():
        return {"state": TAMPERED, "sku": rec["sku"], "customer": rec["customer"],
                "features": [], "expires_at": rec["expires_at"].isoformat(),
                "days_left": (rec["expires_at"] - now).days}
    expired = now >= rec["expires_at"]
    return {
        "state": EXPIRED if expired else VALID,
        "sku": rec["sku"],
        "customer": rec["customer"],
        "features": rec["features"] if not expired else [],  # expired → no premium
        "expires_at": rec["expires_at"].isoformat(),
        "days_left": (rec["expires_at"] - now).days,
    }


def _state_cached() -> Dict[str, Any]:
    global _cache
    if _cache and _cache[0] > time.monotonic():
        return _cache[1]
    st = license_state()
    _cache = (time.monotonic() + _CACHE_TTL_S, st)
    return st


def entitled(feature: str) -> bool:
    """True iff a VALID (non-expired) license grants this feature. When licensing
    is disabled (dev / unlicensed-open mode) everything is entitled — the shipped
    product sets license_enabled=True with the license public key baked in."""
    if not settings.license_enabled:
        return True
    st = _state_cached()
    return st["state"] == VALID and feature in st["features"]


def _clear() -> None:
    global _cache
    _cache = None


def reset_clock() -> None:
    """Test hook — clear the license anti-rollback high-water-mark so test order
    doesn't leak a rolled-forward clock between cases."""
    from ..db import session_scope
    from ..intelligence import store as intel_store
    from ..intelligence.store import IntelligenceClockTable
    intel_store.reset_caches()
    with session_scope() as db:
        row = db.get(IntelligenceClockTable, _CLOCK_KEY)
        if row is not None:
            db.delete(row)
    _clear()
