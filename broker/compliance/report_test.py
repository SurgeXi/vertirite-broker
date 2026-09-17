# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Compliance evidence — control catalog + report aggregation + integrity seal."""
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

_db_fd, _db_path = tempfile.mkstemp(suffix="-compliance.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from broker.compliance import frameworks, report  # noqa: E402
from broker.protection.breaks import events, containment_state  # noqa: E402
from broker.protection.breaks.detector import Break  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db(); Base.metadata.create_all(bind=engine)


_schema()


# --- control catalog ---
def test_catalog_covers_all_frameworks():
    cat = frameworks.catalog()
    assert set(cat["frameworks"]) >= {"OWASP_LLM", "MITRE_ATLAS", "HIPAA", "SOX", "NIST_800_82", "IEC_62443"}
    # every control maps every framework
    for ctrl in cat["controls"]:
        assert set(ctrl["frameworks"].keys()) == set(frameworks.FRAMEWORKS)
        assert all(ctrl["frameworks"].values())  # no empty lists
    assert "do not claim certification" in cat["disclaimer"].lower()


def test_control_by_id():
    assert frameworks.control_by_id("chokepoint.egress")["frameworks"]["HIPAA"]
    assert frameworks.control_by_id("nope") is None


# --- report aggregation ---
def test_empty_report_is_well_formed_and_sealed():
    r = report.build_report(f"t-{uuid.uuid4().hex[:8]}")
    assert r["report_type"] == "vertirite_compliance_evidence"
    assert r["activity"]["breaks_total"] == 0
    # audit.trail is always in force
    assert any(c["id"] == "audit.trail" for c in r["controls_exercised"])
    assert r["integrity"]["algo"] == "sha256" and len(r["integrity"]["hash"]) == 64


def test_report_reflects_breaks_and_maps_controls():
    t = f"t-{uuid.uuid4().hex[:8]}"
    events.report_break(t, "agent-1",
                        Break(reason="first_irreversible", severity="critical",
                              title="wire", target="pay_invoice", chokepoints=["irreversible"]))
    events.report_break(t, "agent-1",
                        Break(reason="novel_egress", severity="warning",
                              title="egress", target="evil.example.com", chokepoints=["egress"]))
    r = report.build_report(t)
    assert r["activity"]["breaks_total"] == 2
    assert r["activity"]["breaks_by_severity"].get("critical") == 1
    assert set(r["activity"]["chokepoints_crossed"]) == {"irreversible", "egress"}
    ids = {c["id"] for c in r["controls_exercised"]}
    assert {"detection.break", "chokepoint.egress", "chokepoint.irreversible"} <= ids


def test_containment_action_maps_to_controls():
    t = f"t-{uuid.uuid4().hex[:8]}"
    containment_state.set_state(t, "agent-2", "quarantined", "confirmed exfil", set_by="op")
    r = report.build_report(t)
    assert r["activity"]["containment_actions"] == 1
    ids = {c["id"] for c in r["controls_exercised"]}
    assert {"containment.detect_to_contain", "approval.human_gate"} <= ids


def test_window_excludes_out_of_range():
    t = f"t-{uuid.uuid4().hex[:8]}"
    events.report_break(t, "agent-3",
                        Break(reason="novel_egress", severity="warning", title="egress",
                              target="x", chokepoints=["egress"]))
    future = datetime.now(timezone.utc) + timedelta(days=1)
    r = report.build_report(t, since=future)  # window starts in the future
    assert r["activity"]["breaks_total"] == 0


def test_integrity_hash_is_deterministic_and_covers_content():
    t = f"t-{uuid.uuid4().hex[:8]}"
    r1 = report.build_report(t)
    # rebuild identical window -> generated_at differs, so hashes differ (they cover
    # generated_at); but the hash must be a valid 64-hex sha256 over the body.
    assert len(r1["integrity"]["hash"]) == 64
    int_block = r1.pop("integrity")
    import hashlib
    from broker.intelligence import signing
    assert hashlib.sha256(signing.canonical_bytes(r1)).hexdigest() == int_block["hash"]
