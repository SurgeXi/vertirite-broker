# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Connected-tier metabolism — auto-pull fresh intelligence on a cadence (PR3).

The Connected SKU keeps its brain fresh by drawing down the latest SIGNED
catalog from a feed URL and installing it (verify + version-monotonic). A
background daemon thread, OFF by default (Sovereign = no phone-home): it runs
only when ``intelligence_feed_enabled`` AND ``intelligence_feed_url`` are set.
Mirrors the health scheduler thread (broker/scheduler.py).

The pull is the transparent phone-home of docs/PROTECTION-MODEL.md — it draws
fresh intelligence on each tick. A disconnected/stolen copy can't pull, so its
catalog rots to baseline-only. Pulls never raise: an unreachable feed simply
leaves the current catalog in place to age out.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List

import httpx

from ..config import settings
from . import catalog

logger = logging.getLogger("vertirite.intel.feed")

_thread: threading.Thread | None = None
_stop = threading.Event()


def _tenants() -> List[str]:
    raw = (settings.intelligence_feed_tenants or "default").strip()
    return [t.strip() for t in raw.split(",") if t.strip()] or ["default"]


def pull_once(tenant_id: str = "default") -> Dict[str, Any]:
    """Fetch the latest signed catalog from the feed and install it if newer.

    Returns a result dict; never raises. ``up_to_date`` (the feed's version is
    not newer than installed) is the common, healthy no-op. Every result is also
    fed to self-witness (Mechanism #2): a feed that goes unreachable is the
    broker's own governance channel being suppressed.
    """
    result = _pull(tenant_id)
    try:
        from ..protection.selfwitness import on_feed_result
        on_feed_result(result["status"], tenant_id=tenant_id,
                       feed_url=settings.intelligence_feed_url)
    except Exception:  # self-witness must never break the pull
        pass
    return result


def _pull(tenant_id: str) -> Dict[str, Any]:
    # License gate — drawing down premium catalogs requires 'intelligence'.
    from ..licensing.license import entitled
    if not entitled("intelligence"):
        return {"status": "unlicensed", "tenant_id": tenant_id}
    url = (settings.intelligence_feed_url or "").strip()
    if not url:
        return {"status": "disabled", "tenant_id": tenant_id}
    headers = {}
    if settings.intelligence_feed_token:
        headers["Authorization"] = f"Bearer {settings.intelligence_feed_token}"
    try:
        with httpx.Client(timeout=settings.intelligence_feed_timeout_s) as client:
            resp = client.get(url, headers=headers, params={"tenant_id": tenant_id})
        if resp.status_code != 200:
            logger.warning("intel feed %s -> HTTP %s", url, resp.status_code)
            return {"status": "feed_error", "tenant_id": tenant_id, "http": resp.status_code}
        bundle = resp.json()
    except Exception as exc:  # unreachable / bad JSON — keep the current catalog
        logger.warning("intel feed unreachable (%s) — keeping current catalog", exc)
        return {"status": "unreachable", "tenant_id": tenant_id, "error": str(exc)}

    try:
        cat = catalog.install(tenant_id, bundle)
    except catalog.CatalogError as e:
        msg = str(e)
        if "not newer" in msg:
            return {"status": "up_to_date", "tenant_id": tenant_id}
        logger.warning("intel feed: bundle rejected: %s", msg)
        return {"status": "rejected", "tenant_id": tenant_id, "reason": msg}
    logger.info("intel feed: installed catalog v%d for %s", cat.catalog_version, tenant_id)
    return {"status": "installed", "tenant_id": tenant_id, "catalog_version": cat.catalog_version}


def sweep(tenant_id: str = "default") -> Dict[str, Any]:
    """Recompute decay state + advance the anti-rollback clock (a cold-path call
    to catalog_status, whose side effect is the high-water-mark advance)."""
    return catalog.catalog_status(tenant_id)


def _loop() -> None:
    interval = max(60, int(settings.intelligence_refresh_interval_s))
    logger.info("intel feed refresher started — interval %ds, tenants=%s", interval, _tenants())
    while not _stop.is_set():
        for t in _tenants():
            try:
                pull_once(t)
                sweep(t)
                # Mechanism #2 PR2: report identity on the same Connected cadence.
                from ..protection.beacon import send_beacon
                send_beacon(t)
            except Exception as exc:
                logger.error("intel feed cycle error for %s: %s", t, exc)
        _stop.wait(timeout=interval)


def start_feed_refresher() -> None:
    """Launch the background refresher — no-op unless enabled + a URL is set."""
    global _thread
    if not settings.intelligence_feed_enabled or not (settings.intelligence_feed_url or "").strip():
        logger.info("intel feed refresher disabled (Sovereign / no-phone-home default)")
        return
    if _thread is not None and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, daemon=True, name="intel-feed-refresher")
    _thread.start()
    logger.info("intel feed refresher thread launched")


def stop_feed_refresher() -> None:
    global _thread
    if _thread is None:
        return
    _stop.set()
    _thread.join(timeout=10)
    _thread = None
    logger.info("intel feed refresher stopped")
