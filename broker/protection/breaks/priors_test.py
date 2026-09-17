# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Per-vertical priors — cold-start seeding of a new agent's baseline."""
import json
import os
import tempfile
import uuid

_db_fd, _db_path = tempfile.mkstemp(suffix="-breaks-priors.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from broker.config import settings  # noqa: E402
from broker.protection.breaks import priors, baseline  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db(); Base.metadata.create_all(bind=engine)


_schema()

_MAP = {"t-med": "medical", "t-acct": "accounting", "t-ot": "manufacturing"}


def test_vertical_and_prior_resolution(monkeypatch):
    monkeypatch.setattr(settings, "tenant_verticals", json.dumps(_MAP))
    assert priors.vertical_for("t-med") == "medical"
    assert priors.vertical_for("t-unknown") is None
    assert priors.prior_for("t-acct")["data_classes"] == ["financial", "pii"]
    assert priors.prior_for("t-ot")["internet_egress_expected"] is False


def test_bad_json_is_ignored(monkeypatch):
    monkeypatch.setattr(settings, "tenant_verticals", "{not json")
    assert priors.vertical_for("t-med") is None


def test_new_medical_agent_seeded_with_phi(monkeypatch):
    monkeypatch.setattr(settings, "tenant_verticals", json.dumps(_MAP))
    actor = f"agent-{uuid.uuid4().hex[:8]}"
    bl = baseline.load("t-med", actor)   # first creation seeds the prior
    assert "phi" in bl.data_classes


def test_unknown_tenant_gets_no_seed(monkeypatch):
    monkeypatch.setattr(settings, "tenant_verticals", json.dumps(_MAP))
    actor = f"agent-{uuid.uuid4().hex[:8]}"
    bl = baseline.load("t-novertical", actor)
    assert bl.data_classes == set()


def test_seeded_phi_suppresses_dataclass_escalation(monkeypatch):
    monkeypatch.setattr(settings, "tenant_verticals", json.dumps(_MAP))
    from broker.protection.breaks import detector
    actor = f"agent-{uuid.uuid4().hex[:8]}"
    bl = baseline.load("t-med", actor)
    # force warm to exercise the statistical rule against the seeded set
    warm = baseline.Baseline("t-med", actor, data_classes=bl.data_classes,
                             active_hours={9}, state="warm")
    bs = detector.evaluate_statistical(warm, now_hour=9, recent_rate=0, data_class="phi")
    assert not any(b.reason == "dataclass_escalation" for b in bs)  # phi is expected
