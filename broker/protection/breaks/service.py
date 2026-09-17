# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""service — the guarded, feature-flagged entry points the gate calls.

Break detection is OFF by default (``VERTIRITE_BREAK_DETECTION=1`` to enable,
staging only). Every entry point swallows its own exceptions: integrity is
observational in P1 and must NEVER be able to fail a dispatch. Alerts are
scheduled in the background so alert I/O never blocks the gate.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone

from ... import containment
from . import baseline, detector, events

log = logging.getLogger("vertirite.breaks.service")


def enabled() -> bool:
    # Operator runtime override (interface toggle) wins over the env default.
    from . import runtime_config
    return runtime_config.effective("break_detection")


def _dispatch_alert(actor_id: str, brk: detector.Break) -> None:
    try:
        from ... import notifications
        coro = notifications.send_alert(
            severity=brk.severity,
            title=f"Agent break — {brk.reason}",
            message=brk.title,
            node=f"agent:{actor_id}",
        )
        try:
            asyncio.get_running_loop().create_task(coro)  # non-blocking in the gate
        except RuntimeError:
            asyncio.run(coro)  # no loop (e.g. a sync caller) — deliver inline
    except Exception:
        log.exception("break alert dispatch failed — non-fatal")


def observe_attempt(ctx, capability: str, params: dict,
                    eff_class, chokepoints) -> None:
    """Called at the gate right after ``containment.apply``. Runs the chokepoint
    behavioral breaks (first_irreversible always; novel_egress / first_credential
    once warm) and advances/learns the baseline."""
    if not enabled():
        return
    try:
        cps = list(chokepoints or [])
        bl = baseline.load(ctx.tenant_id, ctx.actor_id)          # pre-observe (frozen bands)
        dests = containment.external_destinations(capability, params)
        data_class = baseline.dataclass_of(capability, params)
        breaks = detector.evaluate_attempt(bl, capability, cps, dests)
        snap = baseline.observe(ctx.tenant_id, ctx.actor_id, capability, cps, dests,
                                data_class=data_class)
        # P2 statistical deviations — compare THIS action against the learned bands.
        breaks = breaks + detector.evaluate_statistical(
            bl, datetime.now(timezone.utc).hour, snap.recent_rate, data_class)
        # Session-scope drift (P3): within-session escalation, keyed by the session.
        sid = getattr(ctx, "parent_request_id", None) or getattr(ctx, "request_id", "")
        if sid:
            from . import session_tracker
            _prior, prior_count, newly_dangerous = session_tracker.observe(sid, cps)
            breaks = breaks + detector.evaluate_session_drift(ctx.actor_id, prior_count, newly_dangerous)
        for b in breaks:
            row = events.report_break(ctx.tenant_id, ctx.actor_id, b)
            _dispatch_alert(ctx.actor_id, b)
            _maybe_auto_clamp(ctx, b, row)
    except Exception:
        log.exception("break detection (attempt) failed — non-fatal")


def observe_denial(ctx, capability: str, reason: str) -> None:
    """Called at the gate's authorization-deny path. Runs scope_violation
    (always) and denial_burst (rolling threshold)."""
    if not enabled():
        return
    try:
        bl = baseline.load(ctx.tenant_id, ctx.actor_id)
        count = baseline.record_denial(ctx.tenant_id, ctx.actor_id)
        breaks = detector.evaluate_denial(bl, capability, reason, count)
        for b in breaks:
            row = events.report_break(ctx.tenant_id, ctx.actor_id, b)
            _dispatch_alert(ctx.actor_id, b)
            _maybe_auto_clamp(ctx, b, row)
    except Exception:
        log.exception("break detection (denial) failed — non-fatal")


def _maybe_auto_clamp(ctx, brk, row) -> None:
    """P3 detect->contain: conservative auto-clamp on the most dangerous breaks
    (today: first_irreversible -> elevated_high_stakes). Gated by
    VERTIRITE_DETECT_CONTAIN; never quarantines automatically; only-raises."""
    try:
        from . import containment_state as _cs
        if _cs.enabled():
            _cs.auto_clamp_for_break(ctx.tenant_id, ctx.actor_id, brk.reason,
                                     (row or {}).get("id"), brk.severity)
    except Exception:
        log.exception("auto-clamp skipped — non-fatal")
