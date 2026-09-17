# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""The narc — raise a finding ABOUT OURSELVES when the phone-home is suppressed.

The intelligence feed (Mechanism #1 PR3) is the broker's governance channel. If a
thief firewalls it to hide a stolen copy, the pulls go ``unreachable`` — and that
is exactly the kind of blocked egress Vertirite exists to catch. So we catch our
OWN: after N consecutive unreachable pulls we report a ``self-egress-suppressed``
finding into the same coverage map the customer watches.

Only ``unreachable`` (couldn't reach the feed host at all) counts as suppression.
Any HTTP response means egress works. Suppression is meaningless without a feed
configured (Sovereign has no expected egress), so this is Connected-only.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from ..config import settings
from . import identity

logger = logging.getLogger("vertirite.protection.selfwitness")

# Feed-result statuses that mean "egress works" (we got an HTTP response).
_REACHABLE = {"installed", "up_to_date", "rejected", "feed_error"}


def _feed_host(feed_url: str) -> str:
    try:
        return urlparse(feed_url).hostname or feed_url or "intelligence-feed"
    except Exception:
        return "intelligence-feed"


def on_feed_result(status: str, *, tenant_id: str = "default", feed_url: str = "") -> None:
    """Update beacon state from a feed pull result; raise the self-finding on
    sustained suppression. Never raises."""
    if not settings.protection_enabled:
        return
    try:
        if status == "disabled":
            return  # no feed configured → no expected egress → nothing to suppress
        if status in _REACHABLE:
            identity.record_feed_success()
            return
        # status == "unreachable" (or any non-reachable) → the channel is blocked
        failures = identity.record_feed_failure()
        threshold = max(1, settings.protection_suppression_threshold)
        if failures >= threshold and not _recently_raised():
            _raise_self_finding(tenant_id=tenant_id, feed_url=feed_url, failures=failures)
    except Exception as exc:  # self-protection must never break the feed loop
        logger.debug("selfwitness skipped: %s", exc)


def _recently_raised() -> bool:
    """True while THIS suppression episode's raise is still fresh — a
    persistently firewalled feed fails every pull, and re-raising each time
    would re-fire the critical alert forever. The finding itself stays live
    (report_finding upserts); we just don't spam. store.record_success clears
    the stamp, so a NEW episode after recovery alerts immediately."""
    from . import store

    rec = store.get()
    last = (rec or {}).get("last_suppression_at")
    if last is None:
        return False
    window = max(1, settings.protection_suppression_realert_minutes)
    return datetime.now(timezone.utc) - last < timedelta(minutes=window)


def _raise_self_finding(*, tenant_id: str, feed_url: str, failures: int) -> None:
    from ..discovery.findings import report_finding
    from . import store

    rec = identity.get_instance()
    host = _feed_host(feed_url)
    last_ok = rec.get("last_feed_success_at")
    report_finding(
        tenant_id=tenant_id,
        source_host_id=rec["instance_id"],
        target_hostname=host,
        signal_type="network",
        pattern_id="self-egress-suppressed",
        confidence_override="high",
        evidence={
            "plane": "self",
            "consecutive_failures": failures,
            "last_feed_success_at": last_ok.isoformat() if last_ok else None,
            "instance_id": rec["instance_id"],
            "feed_host": host,
        },
    )
    store.mark_suppression()
    logger.warning(
        "SELF-EGRESS-SUPPRESSED: governance channel to %s unreachable for %d pulls — "
        "this instance's phone-home may be firewalled (possible hidden/stolen copy)",
        host, failures,
    )
    _alert(host, failures)


def _alert(host: str, failures: int) -> None:
    """Fire a critical alert through the configured channels (thread→async,
    mirrors scheduler._send_notification_async). Best-effort."""
    import asyncio

    async def _send():
        try:
            from ..notifications import send_alert
            await send_alert(
                severity="critical",
                title="Vertirite governance channel suppressed",
                message=(f"The intelligence feed ({host}) has been unreachable for "
                         f"{failures} consecutive pulls. This instance's phone-home may "
                         f"be firewalled — a sign of a hidden or stolen copy."),
                node="vertirite-self",
            )
        except Exception as e:
            logger.debug("self-suppression alert skipped: %s", e)

    try:
        loop = asyncio.new_event_loop()
        loop.run_until_complete(_send())
        loop.close()
    except Exception:
        pass
