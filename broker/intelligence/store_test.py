# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Catalog persistence: highest-version active, and the monotonic clock HWM."""
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

_db_fd, _db_path = tempfile.mkstemp(suffix="-intel-store.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

import broker.intelligence.store as store  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(bind=engine)


_schema()


def _now():
    return datetime.now(timezone.utc)


def _payload(v):
    return {
        "schema": "vertirite.intel.v1", "catalog_version": v,
        "issued_at": (_now() - timedelta(days=1)).isoformat(),
        "expires_at": (_now() + timedelta(days=30)).isoformat(),
        "tenant_scope": "*", "signature": "ab", "patterns": [{"pattern_id": "x"}],
    }


def test_install_and_get_active_is_highest_version():
    t = "t-" + uuid.uuid4().hex[:8]
    for v in (1, 3, 2):
        store.install_catalog(t, _payload(v))
    assert store.get_active_catalog(t)["catalog_version"] == 3
    assert store.get_max_version(t) == 3


def test_get_active_none_when_absent():
    assert store.get_active_catalog("nobody-" + uuid.uuid4().hex) is None
    assert store.get_max_version("nobody-" + uuid.uuid4().hex) == 0


def test_clock_hwm_is_monotonic():
    t = "t-" + uuid.uuid4().hex[:8]
    store.reset_caches()
    n = _now()
    store.advance_clock_hwm(t, n)
    store.advance_clock_hwm(t, n - timedelta(hours=1))  # backward → ignored
    assert store.get_clock_hwm(t) == n
    later = n + timedelta(hours=1)
    store.advance_clock_hwm(t, later)
    assert store.get_clock_hwm(t) == later


def test_install_advances_hwm():
    t = "t-" + uuid.uuid4().hex[:8]
    store.reset_caches()
    store.install_catalog(t, _payload(1))
    assert store.get_clock_hwm(t) is not None
