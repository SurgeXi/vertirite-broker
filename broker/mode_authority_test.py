# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Gate 01 — local mode authority tests.

Covers the security semantics of the auth-separated, tighten-only mode gate:

  * ``require_governor`` is a SEPARATE trust domain: only the governor token
    authenticates; operator/broker, demo, agent/bridge, and unauthenticated
    callers get 403. With no governor token provisioned it returns 503, so no
    one can set the mode until a governor credential exists.
  * POST /v1/mode sets the mode with the governor token, 403's every other
    caller, and 422's an invalid mode.
  * Effective-mode resolution: surge-core can only TIGHTEN local; it can never
    loosen it, and on outage the local mode stands (no downgrade).
  * Default when never set: LOCKDOWN when fail_closed, else CONTROLLED.
  * Persistence: a set mode survives a store re-read (restart).

Naming follows demo_role_test.py — the CI workflow picks up ``*_test.py``.
"""
from __future__ import annotations

import os
import tempfile

import pytest

# Force a temp SQLite DB BEFORE importing broker modules so building the app /
# reading the store never touches a real database. setdefault matches the other
# test modules — the first one to import wins and all share the migrated temp DB.
_db_fd, _db_path = tempfile.mkstemp(suffix="-mode-authority.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from .auth import require_governor  # noqa: E402
from .config import settings  # noqa: E402
from .db import Base, engine, init_db, session_scope  # noqa: E402
from .governor_store import GovernorStateTable, get_local_mode, set_local_mode  # noqa: E402
from .models import SurgeMode  # noqa: E402
from .core_client import effective_mode  # noqa: E402

# init_db only registers models; create the tables for the test DB.
init_db()
Base.metadata.create_all(engine)

GOV_TOKEN = "governor-token-fixture"
BROKER_TOKEN = settings.broker_api_token
DEMO_TOKEN = "demo-token-fixture"
BRIDGE_TOKEN = settings.bridge_api_token  # the agent/service plane


def _auth(token: str) -> str:
    return f"Bearer {token}"


def _clear_store() -> None:
    with session_scope() as db:
        db.query(GovernorStateTable).delete()


@pytest.fixture
def governor_configured():
    """A governor token distinct from every other trust domain, restored after."""
    prev = settings.governor_token
    settings.governor_token = GOV_TOKEN
    try:
        yield
    finally:
        settings.governor_token = prev


@pytest.fixture
def governor_unset():
    prev = settings.governor_token
    settings.governor_token = ""
    try:
        yield
    finally:
        settings.governor_token = prev


@pytest.fixture
def clean_store():
    """Empty governor_state (the never-set state) before and after the test."""
    _clear_store()
    try:
        yield
    finally:
        _clear_store()


@pytest.fixture
def fail_closed():
    prev = settings.governor_fail_closed
    settings.governor_fail_closed = True
    try:
        yield
    finally:
        settings.governor_fail_closed = prev


@pytest.fixture
def fail_open():
    prev = settings.governor_fail_closed
    settings.governor_fail_closed = False
    try:
        yield
    finally:
        settings.governor_fail_closed = prev


# ---------------------------------------------------------------------------
# require_governor — the auth-separation boundary
# ---------------------------------------------------------------------------

def test_governor_token_allowed(governor_configured):
    actor = require_governor(_auth(GOV_TOKEN))
    assert actor.role == "governor"
    assert actor.token_label == "governor"


def test_broker_operator_token_forbidden(governor_configured):
    # The platform_admin/operator token is a DIFFERENT trust domain → 403.
    with pytest.raises(HTTPException) as exc:
        require_governor(_auth(BROKER_TOKEN))
    assert exc.value.status_code == 403


def test_demo_token_forbidden(governor_configured):
    with pytest.raises(HTTPException) as exc:
        require_governor(_auth(DEMO_TOKEN))
    assert exc.value.status_code == 403


def test_agent_bridge_token_forbidden(governor_configured):
    # The agent/service (bridge) plane must NEVER authenticate to the governor.
    with pytest.raises(HTTPException) as exc:
        require_governor(_auth(BRIDGE_TOKEN))
    assert exc.value.status_code == 403


def test_unauthenticated_forbidden(governor_configured):
    with pytest.raises(HTTPException) as exc:
        require_governor("")
    assert exc.value.status_code == 403


def test_unset_governor_token_returns_503(governor_unset):
    # No governor credential provisioned → the local set-path is disabled for
    # everyone (503), including a caller presenting the (now inert) value.
    with pytest.raises(HTTPException) as exc:
        require_governor(_auth(GOV_TOKEN))
    assert exc.value.status_code == 503
    assert exc.value.detail == "local mode authority not configured"


# ---------------------------------------------------------------------------
# HTTP layer — POST /v1/mode
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    from .main import app
    return TestClient(app)


def test_post_mode_with_governor_sets_mode(client, governor_configured, clean_store):
    resp = client.post(
        "/v1/mode",
        headers={"Authorization": _auth(GOV_TOKEN)},
        json={"mode": "LOCKDOWN", "reason": "drill"},
    )
    assert resp.status_code == 200
    assert resp.json()["local"] == "LOCKDOWN"
    # And it actually persisted to the store.
    assert get_local_mode() == SurgeMode.LOCKDOWN


def test_post_mode_non_governor_forbidden(client, governor_configured, clean_store):
    resp = client.post(
        "/v1/mode",
        headers={"Authorization": _auth(BROKER_TOKEN)},
        json={"mode": "LOCKDOWN"},
    )
    assert resp.status_code == 403


def test_post_mode_invalid_mode_422(client, governor_configured, clean_store):
    resp = client.post(
        "/v1/mode",
        headers={"Authorization": _auth(GOV_TOKEN)},
        json={"mode": "NOT_A_MODE"},
    )
    assert resp.status_code == 422


def test_get_mode_readable_by_operator(client, governor_configured, clean_store):
    resp = client.get("/v1/mode", headers={"Authorization": _auth(BROKER_TOKEN)})
    assert resp.status_code == 200
    body = resp.json()
    assert "effective" in body and "local" in body and "surge_core_reachable" in body


# ---------------------------------------------------------------------------
# Hardening #6 — the ungoverned state is VISIBLE, not silent
# ---------------------------------------------------------------------------

def test_governed_false_when_unprovisioned(client, governor_unset, clean_store):
    # Ungoverned: mode shows a plausible CONTROLLED, but governed=false makes the
    # non-operational posture explicit so a reader can't mistake it for governed.
    r = client.get("/v1/mode", headers={"Authorization": _auth(BROKER_TOKEN)})
    assert r.status_code == 200
    body = r.json()
    assert body["governed"] is False
    assert body["mode_authority"] == "unprovisioned"
    assert body["effective"] == "CONTROLLED"  # default, NOT bricked
    # Entitlements surfaces it too (what the console reads).
    e = client.get("/v1/entitlements", headers={"Authorization": _auth(BROKER_TOKEN)})
    assert e.json()["governed"] is False


def test_governed_true_when_provisioned(client, governor_configured, clean_store):
    r = client.get("/v1/mode", headers={"Authorization": _auth(BROKER_TOKEN)})
    assert r.status_code == 200
    body = r.json()
    assert body["governed"] is True
    assert body["mode_authority"] == "operational"
    e = client.get("/v1/entitlements", headers={"Authorization": _auth(BROKER_TOKEN)})
    assert e.json()["governed"] is True


# ---------------------------------------------------------------------------
# Effective-mode resolution — surge-core can only TIGHTEN (rank logic)
# ---------------------------------------------------------------------------

def test_surge_core_can_tighten():
    # local CONTROLLED + surge-core LOCKDOWN → LOCKDOWN (tighten wins).
    assert effective_mode(SurgeMode.CONTROLLED, SurgeMode.LOCKDOWN) == SurgeMode.LOCKDOWN


def test_surge_core_cannot_loosen():
    # local LOCKDOWN + surge-core AUTONOMOUS → LOCKDOWN (upstream CANNOT loosen).
    assert effective_mode(SurgeMode.LOCKDOWN, SurgeMode.AUTONOMOUS) == SurgeMode.LOCKDOWN


def test_surge_core_unreachable_uses_local():
    # surge-core unreachable (None) → effective = local (no downgrade).
    assert effective_mode(SurgeMode.CONTROLLED, None) == SurgeMode.CONTROLLED
    assert effective_mode(SurgeMode.LOCKDOWN, None) == SurgeMode.LOCKDOWN


def test_escalation_is_between_controlled_and_lockdown():
    # ESCALATION_REQUIRED is declared LAST in the enum but ranks BELOW LOCKDOWN.
    assert effective_mode(SurgeMode.CONTROLLED, SurgeMode.ESCALATION_REQUIRED) == SurgeMode.ESCALATION_REQUIRED
    assert effective_mode(SurgeMode.ESCALATION_REQUIRED, SurgeMode.CONTROLLED) == SurgeMode.ESCALATION_REQUIRED
    assert effective_mode(SurgeMode.ESCALATION_REQUIRED, SurgeMode.LOCKDOWN) == SurgeMode.LOCKDOWN


# ---------------------------------------------------------------------------
# Default-when-never-set (on a GOVERNED box — a governor credential exists)
# ---------------------------------------------------------------------------

def test_default_fail_closed_is_lockdown(clean_store, governor_configured, fail_closed):
    # A governed box (governor credential provisioned) with no explicit mode and
    # fail_closed defaults to LOCKDOWN.
    assert get_local_mode() == SurgeMode.LOCKDOWN


def test_default_fail_open_is_controlled(clean_store, governor_configured, fail_open):
    assert get_local_mode() == SurgeMode.CONTROLLED


# ---------------------------------------------------------------------------
# Hardening #1 — BOOTSTRAP TRAP: an un-provisioned box is never bricked
# ---------------------------------------------------------------------------

def test_bootstrap_no_governor_not_bricked(clean_store, governor_unset, fail_closed):
    # No governor credential + fail_closed=True must NOT default to LOCKDOWN:
    # the set-path is 503 until a credential is provisioned, so a LOCKDOWN
    # default would be an unliftable brick on first boot. Must be CONTROLLED.
    assert get_local_mode() == SurgeMode.CONTROLLED


# ---------------------------------------------------------------------------
# Hardening #2 — tighten-only ENFORCED on the surge-core ingestion path
# (fetch_mode itself, not only the shared helper)
# ---------------------------------------------------------------------------

def test_fetch_mode_discards_spoofed_looser_upstream(governor_configured, clean_store, monkeypatch):
    import asyncio

    import broker.core_client as sc

    # Local authority = LOCKDOWN (explicitly set by a governor).
    set_local_mode(SurgeMode.LOCKDOWN, actor="governor")

    # A compromised/spoofed surge-core returns the LEAST restrictive mode.
    async def _spoof() -> SurgeMode:
        return SurgeMode.AUTONOMOUS

    monkeypatch.setattr(sc, "_read_surge_core_mode", _spoof)
    # fetch_mode must clamp at ingestion: effective stays LOCKDOWN.
    assert asyncio.run(sc.fetch_mode()) == SurgeMode.LOCKDOWN


def test_fetch_mode_honors_upstream_tighten(governor_configured, clean_store, monkeypatch):
    import asyncio

    import broker.core_client as sc

    set_local_mode(SurgeMode.CONTROLLED, actor="governor")

    async def _tighten() -> SurgeMode:
        return SurgeMode.LOCKDOWN

    monkeypatch.setattr(sc, "_read_surge_core_mode", _tighten)
    assert asyncio.run(sc.fetch_mode()) == SurgeMode.LOCKDOWN


# ---------------------------------------------------------------------------
# Hardening #3 — no operator/agent/demo/broker token can MINT governor authority
# ---------------------------------------------------------------------------

def test_no_operator_token_confers_governor_authority(governor_configured):
    # None of the other trust domains authenticate to the governor gate; there
    # is no role escalation path from operator/admin/service/demo to governor.
    for tok in (BROKER_TOKEN, BRIDGE_TOKEN, DEMO_TOKEN, "mae_someapikey", "random"):
        with pytest.raises(HTTPException) as exc:
            require_governor(_auth(tok))
        assert exc.value.status_code == 403


def test_governor_token_only_from_config_not_settable_by_api(client, governor_configured, clean_store):
    # The governor credential is provisioned out-of-band (env/config) only.
    # Exercising an admin endpoint that could plausibly mint authority (the
    # entitlements/license surface) must not change settings.governor_token, and
    # a platform_admin still cannot set the mode afterward.
    before = settings.governor_token
    r = client.get("/v1/entitlements", headers={"Authorization": _auth(BROKER_TOKEN)})
    assert r.status_code == 200
    assert settings.governor_token == before  # unchanged — no API minted it
    # And the admin still can't set the mode (no escalation to governor).
    r2 = client.post("/v1/mode", headers={"Authorization": _auth(BROKER_TOKEN)}, json={"mode": "AUTONOMOUS"})
    assert r2.status_code == 403


# ---------------------------------------------------------------------------
# Hardening #4 — every mode change lands in the append-only audit, attributed
# ---------------------------------------------------------------------------

def test_post_mode_writes_attributed_audit(client, governor_configured, clean_store):
    from .repository import list_audit_events

    resp = client.post(
        "/v1/mode",
        headers={"Authorization": _auth(GOV_TOKEN)},
        json={"mode": "ESCALATION_REQUIRED", "reason": "quarter-close freeze"},
    )
    assert resp.status_code == 200
    rows = list_audit_events(limit=50, action_prefix="governor.set_mode")
    assert rows, "mode change must write an audit row"
    row = rows[0]
    assert row.actor_id == "governor"          # attributed setter
    assert "ESCALATION_REQUIRED" in row.summary  # what it was set to
    assert "quarter-close freeze" in row.summary  # the reason (from what/why)


# ---------------------------------------------------------------------------
# Hardening #5 — a compromised governor is revocable by something OTHER than
# itself: (a) surge-core upstream can still force LOCKDOWN over any local mode;
# (b) rotating governor_token in config invalidates the old credential.
# ---------------------------------------------------------------------------

def test_upstream_can_lockdown_over_compromised_local(governor_configured, clean_store, monkeypatch):
    import asyncio

    import broker.core_client as sc

    # A compromised governor sets the loosest local mode.
    set_local_mode(SurgeMode.AUTONOMOUS, actor="governor")

    async def _upstream_lockdown() -> SurgeMode:
        return SurgeMode.LOCKDOWN

    monkeypatch.setattr(sc, "_read_surge_core_mode", _upstream_lockdown)
    # Upstream (an out-of-band authority) can still force LOCKDOWN → revocation.
    assert asyncio.run(sc.fetch_mode()) == SurgeMode.LOCKDOWN


def test_rotating_governor_token_invalidates_old():
    # Rotate the credential in config; the OLD token no longer authenticates.
    prev = settings.governor_token
    settings.governor_token = "governor-token-rotated-fixture"
    try:
        with pytest.raises(HTTPException) as exc:
            require_governor(_auth(GOV_TOKEN))  # the old value
        assert exc.value.status_code == 403
        # The new one works.
        assert require_governor(_auth("governor-token-rotated-fixture")).role == "governor"
    finally:
        settings.governor_token = prev


# ---------------------------------------------------------------------------
# Persistence across restart
# ---------------------------------------------------------------------------

def test_set_mode_persists_across_reload(clean_store, fail_open):
    # fail_open so the DEFAULT would be CONTROLLED — proving the LOCKDOWN below
    # comes from the persisted row, not the fail-closed default.
    set_local_mode(SurgeMode.LOCKDOWN, actor="governor")
    # get_local_mode opens a fresh session every call (no in-process cache), so
    # re-reading it IS a restart as far as the store is concerned.
    assert get_local_mode() == SurgeMode.LOCKDOWN
