# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""The broker's own install identity — generated first-run, stable thereafter.

A unique ``instance_id`` + a ``canary`` secret. The canary rides in the
phone-home (PR2) so a copy reporting from a foreign environment is detectable;
the instance_id labels the self-finding when the phone-home is suppressed (PR1).

First-run generate + in-process cache mirrors jwt_keys.py:52-118.
"""
from __future__ import annotations

import logging
import secrets
import uuid
from typing import Optional

from . import store

logger = logging.getLogger("vertirite.protection.identity")

_cached: Optional[dict] = None


def get_instance() -> dict:
    """Load the singleton identity, generating it on first run. Cached."""
    global _cached
    if _cached is not None:
        return _cached
    rec = store.get_or_create(
        instance_id=str(uuid.uuid4()),
        canary=secrets.token_hex(16),
    )
    if _cached is None:
        logger.info("protection: instance identity %s", rec["instance_id"])
    _cached = rec
    return rec


def instance_id() -> str:
    return get_instance()["instance_id"]


def record_feed_success() -> None:
    store.record_success()


def record_feed_failure() -> int:
    """Increment + return the new consecutive-failure count."""
    return store.record_failure()


def beacon_state(threshold: int) -> dict:
    """The phone-home channel health, for the /v1/protection/identity endpoint."""
    rec = store.get() or get_instance()
    failures = int(rec.get("consecutive_feed_failures", 0))
    return {
        "last_feed_success_at": (rec.get("last_feed_success_at").isoformat()
                                 if rec.get("last_feed_success_at") else None),
        "consecutive_failures": failures,
        "suppressed": failures >= max(1, threshold),
    }


def reset_cache() -> None:
    """Test hook."""
    global _cached
    _cached = None
