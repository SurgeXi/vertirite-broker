# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Real-time finding alerts (Wave A #1). Off by default; fires only on new
high-signal findings. Pure decision + payload logic, no DB needed."""
import broker.discovery.findings as F
from broker.config import settings


def _pattern(cat):
    return {"category": cat}


def _finding(pid="net-crypto-mining-pool"):
    return {"id": "f1", "tenant_id": "t1", "pattern_id": pid,
            "pattern_name": "Outbound to a mining pool", "confidence": "high",
            "target_hostname": "minexmr.com", "source_host_id": "host-9",
            "signal_type": "network"}


def _enable(monkeypatch, url="http://alerts.example/hook"):
    monkeypatch.setattr(settings, "alert_webhook_enabled", True)
    monkeypatch.setattr(settings, "alert_webhook_url", url)


def test_no_alert_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "alert_webhook_enabled", False)
    assert F.build_finding_alert(_finding(), _pattern("suspicious-egress")) is None


def test_no_alert_without_url(monkeypatch):
    monkeypatch.setattr(settings, "alert_webhook_enabled", True)
    monkeypatch.setattr(settings, "alert_webhook_url", "")
    assert F.build_finding_alert(_finding(), _pattern("suspicious-egress")) is None


def test_alerts_on_threat_with_friendly_name(monkeypatch):
    _enable(monkeypatch)
    p = F.build_finding_alert(_finding(), _pattern("suspicious-egress"))
    assert p is not None
    assert p["category"] == "suspicious-egress"
    assert p["name"] == "Crypto-mining pool"      # friendly name, not the raw pattern name
    assert p["target_hostname"] == "minexmr.com"
    assert p["type"] == "vertirite.finding.new"


def test_no_alert_on_ai_service_by_default(monkeypatch):
    _enable(monkeypatch)
    assert F.build_finding_alert(_finding("net-openai-saas"), _pattern("service-endpoint")) is None


def test_ai_alerts_when_category_opted_in(monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setattr(settings, "alert_categories", ("suspicious-egress", "service-endpoint"))
    p = F.build_finding_alert(_finding("net-openai-saas"), _pattern("service-endpoint"))
    assert p is not None and p["name"] == "OpenAI"


def test_dispatch_calls_sender(monkeypatch):
    _enable(monkeypatch)
    sent = []
    monkeypatch.setattr(F, "_alert_sender", lambda url, payload: sent.append((url, payload)))
    F._dispatch_alert(_finding(), _pattern("suspicious-egress"))
    assert len(sent) == 1 and sent[0][0] == "http://alerts.example/hook"
    # a non-alerting category dispatches nothing
    F._dispatch_alert(_finding("net-openai-saas"), _pattern("service-endpoint"))
    assert len(sent) == 1


def test_payload_is_metadata_only(monkeypatch):
    _enable(monkeypatch)
    p = F.build_finding_alert(_finding(), _pattern("suspicious-egress"))
    assert set(p.keys()) <= {"type", "finding_id", "tenant_id", "pattern_id", "name",
                             "vendor", "category", "confidence", "target_hostname",
                             "source_host_id", "signal_type"}
