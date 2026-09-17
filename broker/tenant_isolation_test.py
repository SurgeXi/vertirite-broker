# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Tenant isolation bleed test.

Verifies that data written for tenant A is not returned when querying
for tenant B, across every query path that scopes by tenant_id:
  - fleet_manifest.list_hosts(tenant_id=...)
  - fleet_manifest.coverage_summary(tenant_id=...)
  - discovery.findings.list_findings(tenant_id=...)
  - repository.list_audit_events(tenant_id=...)

Plus suspension enforcement: a suspended tenant must raise
TenantSuspended; an active tenant must pass.

These tests run against a temp SQLite DB and exercise the helper
functions directly (no HTTP). That makes them fast and hermetic — CI
can run them without standing up the FastAPI app.

Naming convention follows peer_stream_test.py — the CI workflow picks
up *_test.py files in broker/.
"""
from __future__ import annotations

import os
import tempfile
import uuid
from datetime import datetime, timezone

# Force a temp SQLite DB BEFORE importing the broker modules.
_db_fd, _db_path = tempfile.mkstemp(suffix="-tenant-isolation.db")
os.close(_db_fd)
os.environ["SURGE_OPERATOR_DATABASE_URL"] = f"sqlite+pysqlite:///{_db_path}"


def _set_up_schema():
    """Create all the broker tables in the temp DB.

    We do this once at module import. Tests then write fresh rows per
    test case via uuid'd names so they don't collide.
    """
    # importlib trick to make sure the broker reads the env var we just set
    from . import db as broker_db  # noqa: F401
    from .db import Base, engine, init_db
    init_db()
    Base.metadata.create_all(bind=engine)


_set_up_schema()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _new_tenant(name: str, plan: str = "free") -> str:
    """Create a tenant directly via the helper. Returns the tenant_id."""
    from .tenant import create_tenant
    tenant = create_tenant(name=f"{name} [{uuid.uuid4().hex[:6]}]", plan=plan)
    return tenant["id"]


def _new_host(tenant_id: str, hostname: str) -> str:
    """Declare a fleet host for the tenant. Returns the host_id."""
    from .fleet_manifest import declare_host
    host = declare_host(
        tenant_id=tenant_id,
        hostname=f"{hostname}-{uuid.uuid4().hex[:6]}.test",
        role="production-core",
    )
    return host["id"]


def _new_finding(tenant_id: str, source_host_id: str, target: str) -> str:
    """Post a witnessed finding for the tenant. Returns the finding_id."""
    from .discovery.findings import report_finding
    finding = report_finding(
        tenant_id=tenant_id,
        source_host_id=source_host_id,
        target_hostname=target,
        signal_type="process",
        pattern_id="py-openai-client",
        evidence={"pid": 999, "synthetic": True},
    )
    return finding["id"]


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_fleet_hosts_isolated_by_tenant():
    """list_hosts(tenant_id=A) returns only A's hosts; B's hosts are absent."""
    from .fleet_manifest import list_hosts

    tenant_a = _new_tenant("tenantA")
    tenant_b = _new_tenant("tenantB")
    host_a = _new_host(tenant_a, "alpha")
    host_b = _new_host(tenant_b, "beta")

    a_hosts = list_hosts(tenant_id=tenant_a)
    b_hosts = list_hosts(tenant_id=tenant_b)

    a_ids = {h["id"] for h in a_hosts}
    b_ids = {h["id"] for h in b_hosts}
    assert host_a in a_ids, "tenant A's host should be in A's list"
    assert host_a not in b_ids, "tenant A's host MUST NOT appear in B's list (bleed)"
    assert host_b in b_ids, "tenant B's host should be in B's list"
    assert host_b not in a_ids, "tenant B's host MUST NOT appear in A's list (bleed)"


def test_coverage_summary_isolated_by_tenant():
    """coverage_summary(tenant_id=A) counts only A's hosts."""
    from .fleet_manifest import coverage_summary

    tenant_a = _new_tenant("covA")
    tenant_b = _new_tenant("covB")
    _new_host(tenant_a, "covA-host1")
    _new_host(tenant_a, "covA-host2")
    _new_host(tenant_b, "covB-host1")

    cov_a = coverage_summary(tenant_id=tenant_a)
    cov_b = coverage_summary(tenant_id=tenant_b)

    a_hostnames = {h["hostname"] for h in cov_a["hosts"]}
    b_hostnames = {h["hostname"] for h in cov_b["hosts"]}
    # Both tenants have only-their-own hosts in their respective summaries
    assert all("covA" in n for n in a_hostnames), (
        f"A's coverage should only contain A's hosts; saw {a_hostnames}"
    )
    assert all("covB" in n for n in b_hostnames), (
        f"B's coverage should only contain B's hosts; saw {b_hostnames}"
    )


def test_witnessed_findings_isolated_by_tenant():
    """list_findings(tenant_id=A) returns only A's findings."""
    from .discovery.findings import list_findings

    tenant_a = _new_tenant("witA")
    tenant_b = _new_tenant("witB")
    host_a = _new_host(tenant_a, "wit-source-a")
    host_b = _new_host(tenant_b, "wit-source-b")
    f_a = _new_finding(tenant_a, host_a, "internal-A.example.com")
    f_b = _new_finding(tenant_b, host_b, "internal-B.example.com")

    a_findings = list_findings(tenant_id=tenant_a)
    b_findings = list_findings(tenant_id=tenant_b)

    a_ids = {f["id"] for f in a_findings}
    b_ids = {f["id"] for f in b_findings}
    assert f_a in a_ids
    assert f_a not in b_ids, "A's finding leaked into B's list"
    assert f_b in b_ids
    assert f_b not in a_ids, "B's finding leaked into A's list"


def test_audit_events_isolated_by_tenant():
    """list_audit_events(tenant_id=A) returns only events tagged A.

    Critical assertion: tenant_id=NULL events (legacy / non-tenant-scoped)
    MUST NOT appear in either A's or B's filtered view. They're visible
    in the unfiltered cross-tenant view only.
    """
    from .repository import write_audit_event, list_audit_events

    tenant_a = _new_tenant("audA")
    tenant_b = _new_tenant("audB")

    a_event = write_audit_event(
        actor_id="test-actor-a",
        action="test.bleed",
        entity_type="tenant",
        entity_id=tenant_a,
        summary="event for tenant A",
        tenant_id=tenant_a,
    )
    b_event = write_audit_event(
        actor_id="test-actor-b",
        action="test.bleed",
        entity_type="tenant",
        entity_id=tenant_b,
        summary="event for tenant B",
        tenant_id=tenant_b,
    )
    untagged = write_audit_event(
        actor_id="test-actor-bg",
        action="test.bleed",
        entity_type="system",
        entity_id="bg-task",
        summary="background untagged event",
        # tenant_id deliberately omitted (NULL)
    )

    a_events = list_audit_events(limit=200, action_prefix="test.bleed", tenant_id=tenant_a)
    b_events = list_audit_events(limit=200, action_prefix="test.bleed", tenant_id=tenant_b)
    all_events = list_audit_events(limit=200, action_prefix="test.bleed")

    a_ids = {e.id for e in a_events}
    b_ids = {e.id for e in b_events}
    all_ids = {e.id for e in all_events}

    assert a_event in a_ids, "A's event missing from A's filtered view"
    assert a_event not in b_ids, "A's event leaked into B's filtered view (bleed)"
    assert b_event in b_ids
    assert b_event not in a_ids, "B's event leaked into A's filtered view (bleed)"

    # Untagged event: must NOT appear in either tenant's filtered view
    # (the filter is exact match on tenant_id; NULL != A and NULL != B)
    assert untagged not in a_ids, "untagged event leaked into A's filtered view"
    assert untagged not in b_ids, "untagged event leaked into B's filtered view"
    # But it MUST appear in the cross-tenant (unfiltered) view
    assert untagged in all_ids, "untagged event missing from cross-tenant view"


def test_suspended_tenant_raises_on_assert_active():
    """A suspended or archived tenant must raise TenantSuspended."""
    from .tenant import (
        assert_tenant_active,
        TenantSuspended,
        update_tenant_status,
    )

    tenant_id = _new_tenant("susptest")
    # Active first — no raise
    assert_tenant_active(tenant_id)  # should not raise

    # Suspend
    update_tenant_status(tenant_id, "suspended")
    try:
        assert_tenant_active(tenant_id)
    except TenantSuspended as e:
        assert e.status == "suspended"
        assert e.tenant_id == tenant_id
    else:
        raise AssertionError("expected TenantSuspended when status=suspended")

    # Reactivate
    update_tenant_status(tenant_id, "active")
    assert_tenant_active(tenant_id)  # should not raise again

    # Archive
    update_tenant_status(tenant_id, "archived")
    try:
        assert_tenant_active(tenant_id)
    except TenantSuspended as e:
        assert e.status == "archived"
    else:
        raise AssertionError("expected TenantSuspended when status=archived")


def test_missing_tenant_raises_lookup_error():
    """A tenant_id that doesn't exist must raise LookupError, not TenantSuspended."""
    from .tenant import assert_tenant_active

    fake_id = f"never-existed-{uuid.uuid4().hex[:8]}"
    try:
        assert_tenant_active(fake_id)
    except LookupError as e:
        assert fake_id in str(e)
    else:
        raise AssertionError("expected LookupError for non-existent tenant")


# ---------------------------------------------------------------------------
# Smoke entry-point: `python -m broker.tenant_isolation_test`
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    tests = [
        test_fleet_hosts_isolated_by_tenant,
        test_coverage_summary_isolated_by_tenant,
        test_witnessed_findings_isolated_by_tenant,
        test_audit_events_isolated_by_tenant,
        test_suspended_tenant_raises_on_assert_active,
        test_missing_tenant_raises_lookup_error,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            print(f"  FAIL  {t.__name__}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    raise SystemExit(0 if failed == 0 else 1)
