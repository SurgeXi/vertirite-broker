# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Instance identity is generated once + persists; beacon tracks suppression."""
import os
import tempfile

_db_fd, _db_path = tempfile.mkstemp(suffix="-protection-id.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

import broker.protection.identity as identity  # noqa: E402
import broker.protection.store as store  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(bind=engine)


_schema()


def test_instance_is_stable_and_persisted():
    identity.reset_cache()
    a = identity.get_instance()
    assert a["instance_id"] and a["canary"]
    identity.reset_cache()              # drop the in-process cache
    b = identity.get_instance()         # must LOAD the same row, not regenerate
    assert b["instance_id"] == a["instance_id"]
    assert b["canary"] == a["canary"]


def test_failure_increments_and_success_resets():
    identity.get_instance()
    store.record_success()              # baseline: zero failures
    assert identity.record_feed_failure() == 1
    assert identity.record_feed_failure() == 2
    identity.record_feed_success()
    st = identity.beacon_state(threshold=3)
    assert st["consecutive_failures"] == 0 and st["suppressed"] is False


def test_beacon_suppressed_at_threshold():
    identity.get_instance()
    store.record_success()
    for _ in range(3):
        identity.record_feed_failure()
    st = identity.beacon_state(threshold=3)
    assert st["consecutive_failures"] == 3 and st["suppressed"] is True
