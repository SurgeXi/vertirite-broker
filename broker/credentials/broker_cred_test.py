# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Credential brokering (Wave B #6). Pure grant-evaluation; issues nothing real."""
from datetime import datetime, timezone
import broker.credentials.broker_cred as CB

POLICY = {"allowed_scopes": ["read:invoices", "read:ledger"], "max_ttl_seconds": 3600, "default_ttl_seconds": 900}
NOW = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)


def test_valid_request_granted():
    g = CB.evaluate_credential_request({"agent_id": "a1", "scopes": ["read:invoices"], "ttl_seconds": 600}, POLICY, NOW)
    assert g["granted"] and g["ttl_seconds"] == 600 and g["ttl_capped"] is False
    assert g["scopes"] == ["read:invoices"] and g["grant_id"] and g["expires_at"].startswith("2026-09-11T12:10")


def test_out_of_policy_scope_denied():
    g = CB.evaluate_credential_request({"agent_id": "a1", "scopes": ["write:ledger"]}, POLICY)
    assert g["granted"] is False and g["denied_scopes"] == ["write:ledger"]


def test_ttl_capped_to_policy_max():
    g = CB.evaluate_credential_request({"agent_id": "a1", "scopes": ["read:ledger"], "ttl_seconds": 999999}, POLICY, NOW)
    assert g["granted"] and g["ttl_seconds"] == 3600 and g["ttl_capped"] is True


def test_default_ttl_when_unspecified():
    g = CB.evaluate_credential_request({"agent_id": "a1", "scopes": ["read:ledger"]}, POLICY, NOW)
    assert g["ttl_seconds"] == 900


def test_missing_agent_denied():
    assert CB.evaluate_credential_request({"scopes": ["read:ledger"]}, POLICY)["granted"] is False


def test_no_scopes_denied():
    assert CB.evaluate_credential_request({"agent_id": "a1", "scopes": []}, POLICY)["granted"] is False


def test_partial_out_of_policy_denies_whole():
    g = CB.evaluate_credential_request({"agent_id": "a1", "scopes": ["read:ledger", "admin:all"]}, POLICY)
    assert g["granted"] is False and g["denied_scopes"] == ["admin:all"]
