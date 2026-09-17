# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Stage 2 policy ladder: threat -> BLOCK, sanctioned -> ROUTE, else default."""
import broker.enforcement.policy as pol


def test_threat_destination_is_blocked():
    # Reuses the shared coverage threat markers (e.g. "exfil", "miner", "c2-").
    d = pol.decide(destination="https://exfil-relay.example", model="")
    assert d.action == "block"
    assert d.is_threat is True
    assert d.allowed is False


def test_sanctioned_model_is_routed(monkeypatch):
    monkeypatch.setattr(pol.settings, "proxy_sanctioned_models", "gpt-4,gpt-3.5")
    d = pol.decide(destination="https://api.openai.com", model="gpt-4o-mini")
    assert d.action == "route"
    assert d.sanctioned is True
    assert d.allowed is True


def test_unsanctioned_default_route(monkeypatch):
    monkeypatch.setattr(pol.settings, "proxy_sanctioned_models", "")
    monkeypatch.setattr(pol.settings, "proxy_default_decision", "route")
    d = pol.decide(destination="https://api.openai.com", model="gpt-4o")
    assert d.action == "route"
    assert d.sanctioned is False
    assert d.is_threat is False


def test_unsanctioned_default_block(monkeypatch):
    monkeypatch.setattr(pol.settings, "proxy_sanctioned_models", "")
    monkeypatch.setattr(pol.settings, "proxy_default_decision", "block")
    d = pol.decide(destination="https://api.openai.com", model="gpt-4o")
    assert d.action == "block"
    assert d.allowed is False
    assert d.is_threat is False  # blocked by policy, not because it's a threat


def test_threat_beats_sanctioned_allowlist(monkeypatch):
    # A threat destination is blocked even if the model is allowlisted.
    monkeypatch.setattr(pol.settings, "proxy_sanctioned_models", "gpt-4")
    d = pol.decide(destination="https://exfil.bad", model="gpt-4o")
    assert d.action == "block"
    assert d.is_threat is True


def test_host_normalisation():
    assert pol._host_of("https://API.OpenAI.com/v1/chat") == "api.openai.com"
    assert pol._host_of("api.openai.com:8443") == "api.openai.com"
