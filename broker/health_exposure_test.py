# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""/health exposure tests.

`/health` was unauthenticated and returned internal topology (DB host+engine,
environment, surge-core mode, component reachability) to any anonymous caller —
readable by a prospect on the public demo. These tests pin the split:
  * public /health is minimal liveness only (no topology fields);
  * detailed health moved to /v1/health behind the bearer token.

Naming follows demo_role_test.py — CI picks up *_test.py.
"""
from __future__ import annotations

import os
import tempfile

import pytest

_db_fd, _db_path = tempfile.mkstemp(suffix="-health.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from fastapi.testclient import TestClient  # noqa: E402

from .config import settings  # noqa: E402

BROKER_TOKEN = settings.broker_api_token
_TOPOLOGY_FIELDS = {"environment", "database_target", "surge_core_mode",
                    "surge_core_reachable", "tunnel_alive", "ollama_reachable"}


def _auth(token: str) -> str:
    return f"Bearer {token}"


@pytest.fixture(scope="module")
def client():
    from .db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(engine)
    from .main import app
    return TestClient(app)


def test_public_health_is_minimal_no_topology(client):
    r = client.get("/health")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("status") == "ok"
    assert body.get("service")
    leaked = _TOPOLOGY_FIELDS & set(body)
    assert not leaked, f"public /health leaks topology fields: {leaked}"


def test_detailed_health_requires_auth(client):
    r = client.get("/v1/health")
    assert r.status_code == 401, r.text


def test_detailed_health_with_token_returns_topology(client):
    r = client.get("/v1/health", headers={"Authorization": _auth(BROKER_TOKEN)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert _TOPOLOGY_FIELDS <= set(body), "authed /v1/health should carry the detail"
    # creds must stay redacted even for authed callers
    assert "***@" in body["database_target"] or "@" not in body["database_target"]
