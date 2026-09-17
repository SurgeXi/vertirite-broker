# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Demo-token scoping tests.

The public try.vertirite.com console authenticates with a static key
printed in the URL fragment. Historically that key equalled
``broker_api_token`` → role ``platform_admin`` → FULL admin (command
execution, terminal, filesystem, key vault, agent/fleet/self-heal,
cross-tenant admin). These tests verify the fix:

  * a SEPARATE ``demo_api_token`` resolves to the locked-down role
    ``demo`` (not platform_admin);
  * the ``require_not_demo`` dependency refuses role ``demo`` with 403
    while allowing every other role;
  * over HTTP, a demo caller is 403'd on a dangerous endpoint but keeps
    the read/govern product surface;
  * with ``demo_api_token`` unset (the default) NO demo role exists and
    behavior is exactly as before — the broker token still maps to
    platform_admin.

Naming follows peer_stream_test.py / tenant_isolation_test.py — the CI
workflow picks up ``*_test.py`` files in broker/.
"""
from __future__ import annotations

import os
import tempfile

import pytest

# Force a temp SQLite DB BEFORE importing the broker modules (so importing
# broker.main to build the FastAPI app never touches a real database).
_db_fd, _db_path = tempfile.mkstemp(suffix="-demo-role.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from . import auth  # noqa: E402
from .auth import (  # noqa: E402
    AuthContext,
    require_bearer_token,
    require_not_demo,
    require_operator_or_demo,
    require_platform_admin,
    utc_now,
)
from .config import settings  # noqa: E402

DEMO_TOKEN = "demo-token-fixture"  # the value printed in the try.vertirite.com URL fragment
BROKER_TOKEN = settings.broker_api_token


def _auth(token: str) -> str:
    return f"Bearer {token}"


@pytest.fixture
def demo_configured():
    """Configure a demo token distinct from the broker token, and restore after."""
    prev = settings.demo_api_token
    settings.demo_api_token = DEMO_TOKEN
    try:
        yield
    finally:
        settings.demo_api_token = prev


@pytest.fixture
def demo_unset():
    """Ensure no demo token is configured (the shipped default), and restore after."""
    prev = settings.demo_api_token
    settings.demo_api_token = ""
    try:
        yield
    finally:
        settings.demo_api_token = prev


# ---------------------------------------------------------------------------
# Token → role resolution
# ---------------------------------------------------------------------------

def test_demo_token_resolves_to_demo_role(demo_configured):
    actor = require_bearer_token(_auth(DEMO_TOKEN))
    assert actor.role == "demo"
    assert actor.token_label == "demo"


def test_broker_token_still_platform_admin(demo_configured):
    # The existing broker_api_token path is UNCHANGED even with a demo token set.
    actor = require_bearer_token(_auth(BROKER_TOKEN))
    assert actor.role == "platform_admin"
    assert actor.token_label == "broker-admin"


def test_demo_token_is_inert_when_unset(demo_unset):
    # With demo_api_token empty, the demo value is just an invalid token → 403.
    with pytest.raises(HTTPException) as exc:
        require_bearer_token(_auth(DEMO_TOKEN))
    assert exc.value.status_code == 403


def test_broker_token_unchanged_when_demo_unset(demo_unset):
    # Backward-compat: broker token behavior is identical to before the feature.
    actor = require_bearer_token(_auth(BROKER_TOKEN))
    assert actor.role == "platform_admin"


# ---------------------------------------------------------------------------
# require_not_demo dependency
# ---------------------------------------------------------------------------

def test_require_not_demo_refuses_demo(demo_configured):
    with pytest.raises(HTTPException) as exc:
        require_not_demo(_auth(DEMO_TOKEN))
    assert exc.value.status_code == 403


def test_require_not_demo_allows_platform_admin(demo_configured):
    actor = require_not_demo(_auth(BROKER_TOKEN))
    assert actor.role == "platform_admin"


def test_require_platform_admin_refuses_demo(demo_configured):
    # Cross-tenant/admin routes are gated by require_platform_admin, which the
    # demo role fails automatically (role != platform_admin).
    with pytest.raises(HTTPException) as exc:
        require_platform_admin(_auth(DEMO_TOKEN))
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# require_operator_or_demo dependency — the demo's read + govern surface
# ---------------------------------------------------------------------------

def test_require_operator_or_demo_allows_platform_admin(demo_configured):
    actor = require_operator_or_demo(_auth(BROKER_TOKEN))
    assert actor.role == "platform_admin"


def test_require_operator_or_demo_allows_demo(demo_configured):
    actor = require_operator_or_demo(_auth(DEMO_TOKEN))
    assert actor.role == "demo"


def _fake_role(monkeypatch, role: str):
    """Force require_bearer_token to resolve to an arbitrary role, so we can
    exercise the SaaS member/owner branches without standing up a tenant DB."""
    def _fake(authorization: str = ""):
        return AuthContext(user_id="u1", token_label="saas-acme",
                           created_at=utc_now(), role=role)
    monkeypatch.setattr(auth, "require_bearer_token", _fake)


def test_require_operator_or_demo_refuses_member(monkeypatch):
    _fake_role(monkeypatch, "member")
    with pytest.raises(HTTPException) as exc:
        require_operator_or_demo(_auth("mse_whatever"))
    assert exc.value.status_code == 403


def test_require_operator_or_demo_refuses_owner(monkeypatch):
    _fake_role(monkeypatch, "owner")
    with pytest.raises(HTTPException) as exc:
        require_operator_or_demo(_auth("mse_whatever"))
    assert exc.value.status_code == 403


def test_require_operator_or_demo_refuses_unauth():
    # An invalid/absent credential never resolves to a role → 403 (require_bearer_token).
    with pytest.raises(HTTPException) as exc:
        require_operator_or_demo(_auth("not-a-real-token"))
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# HTTP layer — the deny/allow split as the demo experiences it
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    # Build the schema in the temp SQLite DB. In prod alembic owns schema
    # creation (init_db only registers models); for the test DB we register
    # every model then create_all so the discovery/govern handlers have tables.
    from .db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(engine)
    from .main import app
    return TestClient(app)


def test_demo_denied_on_dangerous_endpoint(client, demo_configured):
    # /v1/keys (key vault) is dangerous → demo gets 403 at the auth dependency
    # before the handler ever runs.
    resp = client.get("/v1/keys", headers={"Authorization": _auth(DEMO_TOKEN)})
    assert resp.status_code == 403


def test_demo_allowed_on_product_endpoint(client, demo_configured):
    # /v1/me is part of the product surface the live demo needs → 200.
    resp = client.get("/v1/me", headers={"Authorization": _auth(DEMO_TOKEN)})
    assert resp.status_code == 200
    assert resp.json()["token_label"] == "demo"


def test_platform_admin_still_reaches_dangerous_endpoint(client, demo_configured):
    # The admin path is unaffected: broker token still lists keys.
    resp = client.get("/v1/keys", headers={"Authorization": _auth(BROKER_TOKEN)})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# HTTP layer — the demo's discovery/exposure/govern product surface (1.4)
# ---------------------------------------------------------------------------

def test_demo_allowed_on_discovery_coverage(client, demo_configured):
    # The Coverage Map is the headline demo view → the demo must get 200.
    resp = client.get("/v1/discovery/coverage", headers={"Authorization": _auth(DEMO_TOKEN)})
    assert resp.status_code == 200


def test_demo_can_govern_a_finding(client, demo_configured):
    # The demo's headline action: bring a finding under governance. Seed one
    # (as the admin seeder would), then govern it AS THE DEMO over HTTP.
    from .discovery.findings import report_finding
    finding = report_finding(
        tenant_id="default",
        source_host_id="demo-host-1",
        target_hostname="api.openai.com",
        signal_type="network",
        pattern_id="net-openai-saas",
    )
    resp = client.post(
        f"/v1/discovery/findings/{finding['id']}/govern",
        headers={"Authorization": _auth(DEMO_TOKEN)},
        json={},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "governed"


def test_demo_denied_on_finding_injection(client, demo_configured):
    # Injecting findings (the seeder's job) stays admin-only → demo 403.
    resp = client.post(
        "/v1/discovery/ingest/flow",
        headers={"Authorization": _auth(DEMO_TOKEN)},
        json={"flows": [], "tenant_id": "default"},
    )
    assert resp.status_code == 403


def test_demo_denied_on_integrity_config(client, demo_configured):
    # Mutating integrity config stays admin-only → demo 403.
    resp = client.post(
        "/v1/integrity/config",
        headers={"Authorization": _auth(DEMO_TOKEN)},
        json={},
    )
    assert resp.status_code == 403
