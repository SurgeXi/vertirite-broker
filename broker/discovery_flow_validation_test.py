# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Input-validation tests for POST /v1/discovery/ingest/flow.

Before the typed request model, the route took `payload: dict` and hand-parsed
it, so an authorized-but-buggy/compromised collector could:
  * send `flows` as a string  -> 500 (unhandled AttributeError iterating a str);
  * send a flow with a non-int `dst_port` ("NOTINT") -> 200, silently ingested
    as a junk finding.
Both should be a clean 422. These tests pin that, and prove the happy path +
the src/dst/dst_port aliases (source/destination/port) still work so existing
collectors don't break.

Naming follows demo_role_test.py / peer_stream_test.py — CI picks up *_test.py.
"""
from __future__ import annotations

import os
import tempfile

import pytest

# Force a temp SQLite DB BEFORE importing broker modules (never touch a real DB).
_db_fd, _db_path = tempfile.mkstemp(suffix="-flow-validation.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from fastapi.testclient import TestClient  # noqa: E402

from .config import settings  # noqa: E402

BROKER_TOKEN = settings.broker_api_token


def _auth(token: str) -> str:
    return f"Bearer {token}"


@pytest.fixture(scope="module")
def client():
    # Build the schema in the temp SQLite DB (see demo_role_test.py): in prod
    # alembic owns schema creation; for the test DB we register models then
    # create_all so the auth/audit path has its tables.
    from .db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(engine)
    from .main import app
    return TestClient(app)


def _admin(body):
    return {"headers": {"Authorization": _auth(BROKER_TOKEN)}, "json": body}


def test_non_int_dst_port_is_422_not_silent_accept(client):
    # The dst_port="NOTINT" case that used to be ingested as a junk finding.
    r = client.post("/v1/discovery/ingest/flow", **_admin(
        {"tenant_id": "default",
         "flows": [{"src": "10.0.0.1", "dst": "10.0.0.2", "dst_port": "NOTINT", "proto": "tcp"}]}))
    assert r.status_code == 422, r.text


def test_flows_as_string_is_422_not_500(client):
    # Wrong type for `flows` used to iterate a string and 500.
    r = client.post("/v1/discovery/ingest/flow", **_admin(
        {"tenant_id": "default", "flows": "not-a-list"}))
    assert r.status_code == 422, r.text


def test_valid_flow_still_ingests(client):
    r = client.post("/v1/discovery/ingest/flow", **_admin(
        {"tenant_id": "default",
         "flows": [{"src": "10.0.0.1", "dst": "10.0.0.2", "dst_port": 8443, "proto": "tcp"}]}))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sensor"] == "flow"
    assert "by_plane" in body


def test_collector_aliases_still_accepted(client):
    # source/destination/port are the alternate names a collector may emit.
    r = client.post("/v1/discovery/ingest/flow", **_admin(
        {"tenant_id": "default",
         "flows": [{"source": "10.0.0.1", "destination": "10.0.0.2", "port": 22, "proto": "tcp"}]}))
    assert r.status_code == 200, r.text
    assert r.json()["sensor"] == "flow"


def test_empty_flows_list_ok(client):
    r = client.post("/v1/discovery/ingest/flow", **_admin(
        {"tenant_id": "default", "flows": []}))
    assert r.status_code == 200, r.text
    assert r.json()["reported"] == 0
