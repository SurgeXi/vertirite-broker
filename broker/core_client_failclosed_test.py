# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Fail-closed governance regression guard.

Found 2026-06-14 by a live test: a `gated` capability executed without
approval because the unreachable governor-of-record fell back to the permissive
CONTROLLED mode (fail-OPEN). With ``governor_fail_closed=True`` (the Vertirite
default) a GOVERNED broker must drop to LOCKDOWN — deny by default — when it has
no explicit live mode and its upstream is gone.

Updated 2026-09-15 for gate 01 (local mode authority): the mode of record is now
LOCAL, and fail-closed's LOCKDOWN default applies only once a governor
credential EXISTS (a governed system). An UN-provisioned box (no governor
credential) never defaults to LOCKDOWN — that would be an unliftable brick on a
first boot; see mode_authority_test.test_bootstrap_no_governor_not_bricked.
"""
import asyncio

import broker.core_client as sc
from broker import policy
from broker.config import settings
from broker.db import session_scope
from broker.governor_store import GovernorStateTable
from broker.models import ExecuteCommandRequest, SurgeMode

_DEAD = "http://127.0.0.1:1"  # nothing listens on port 1 → connection refused
_GOV = "governor-failclosed-test-token"  # a provisioned governor → a GOVERNED box


def _reset(url: str, fail_closed: bool) -> None:
    sc._cached_mode = None
    sc._cache_time = 0
    sc._surge_core_reachable = False
    settings.surge_core_url = url
    settings.governor_fail_closed = fail_closed
    # A GOVERNED box: a governor credential is provisioned. fail-closed's
    # LOCKDOWN default only applies to governed systems.
    settings.governor_token = _GOV
    # Never-set local mode → exercise the default path.
    try:
        with session_scope() as db:
            db.query(GovernorStateTable).delete()
    except Exception:
        pass


def test_unreachable_governor_fails_closed_to_lockdown():
    _reset(_DEAD, fail_closed=True)
    assert asyncio.run(sc.fetch_mode()) == SurgeMode.LOCKDOWN


def test_failopen_fallback_preserved_when_disabled():
    # Deployments that opt out keep the old permissive fallback.
    _reset(_DEAD, fail_closed=False)
    assert asyncio.run(sc.fetch_mode()) == SurgeMode.CONTROLLED


def test_lockdown_requires_approval_for_controlled_tool():
    req = ExecuteCommandRequest(session_id="t", tool_name="command.execute")
    resp = policy.evaluate_request(req, SurgeMode.LOCKDOWN)
    assert resp.approval_required is True
    assert resp.status != "allowed"
