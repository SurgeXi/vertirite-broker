# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Stage 2 forward-proxy: gate -> audit -> forward, with a mocked upstream.

Async paths are driven with asyncio.run() so no pytest-asyncio dependency is
required. The upstream httpx client and the audit writer are both faked.
"""
import asyncio
import json

import broker.enforcement.proxy as proxy


class _FakeResp:
    def __init__(self, status=200, headers=None, content=b'{"ok":true}'):
        self.status_code = status
        self.headers = headers or {"content-type": "application/json", "content-length": "11"}
        self.content = content


class _FakeClient:
    last: dict = {}

    def __init__(self, timeout=None):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def request(self, method, url, content=None, headers=None):
        _FakeClient.last = {"method": method, "url": url, "content": content, "headers": headers}
        return _FakeResp()


def _run(coro):
    return asyncio.run(coro)


def _enable(monkeypatch, **over):
    _FakeClient.last = {}
    defaults = dict(
        proxy_enabled=True,
        proxy_openai_upstream="https://api.openai.com",
        proxy_default_decision="route",
        proxy_sanctioned_models="",
        proxy_openai_api_key="",
        proxy_request_timeout_s=5.0,
    )
    defaults.update(over)
    for k, v in defaults.items():
        monkeypatch.setattr(proxy.settings, k, v)
    audits: list = []
    monkeypatch.setattr(proxy, "write_audit_event", lambda **kw: audits.append(kw) or "id")
    monkeypatch.setattr(proxy.httpx, "AsyncClient", _FakeClient)
    return audits


def test_disabled_raises(monkeypatch):
    monkeypatch.setattr(proxy.settings, "proxy_enabled", False)
    try:
        _run(proxy.forward_openai(path="v1/chat/completions", method="POST",
                                  headers={}, body=b"{}", actor_id="t"))
        assert False, "expected ProxyDisabled"
    except proxy.ProxyDisabled:
        pass


def test_allowed_call_forwards_and_audits(monkeypatch):
    audits = _enable(monkeypatch)
    body = json.dumps({"model": "gpt-4o", "messages": []}).encode()
    status, headers, content = _run(proxy.forward_openai(
        path="v1/chat/completions", method="POST",
        headers={"authorization": "Bearer client-key", "content-type": "application/json"},
        body=body, actor_id="operator"))
    assert status == 200
    assert _FakeClient.last["url"] == "https://api.openai.com/v1/chat/completions"
    assert "content-length" not in {k.lower() for k in headers}  # hop-by-hop stripped
    assert headers["X-Vertirite-Decision"] == "route"
    assert any(a["action"] == "ai.proxy.forward" for a in audits)


def test_server_key_injected_and_hop_headers_dropped(monkeypatch):
    _enable(monkeypatch, proxy_openai_api_key="sk-server-secret")
    _run(proxy.forward_openai(
        path="v1/chat/completions", method="POST",
        headers={"authorization": "Bearer sk-client", "host": "broker"},
        body=b'{"model":"gpt-4o"}', actor_id="t"))
    sent = _FakeClient.last["headers"]
    assert sent["Authorization"] == "Bearer sk-server-secret"  # broker holds the key
    assert "host" not in {k.lower() for k in sent}             # hop-by-hop stripped


def test_client_key_passthrough_when_no_server_key(monkeypatch):
    _enable(monkeypatch, proxy_openai_api_key="")
    _run(proxy.forward_openai(
        path="v1/chat/completions", method="POST",
        headers={"Authorization": "Bearer sk-client"},
        body=b'{"model":"gpt-4o"}', actor_id="t"))
    assert _FakeClient.last["headers"]["Authorization"] == "Bearer sk-client"


def test_blocked_call_never_reaches_upstream(monkeypatch):
    audits = _enable(monkeypatch, proxy_default_decision="block")
    try:
        _run(proxy.forward_openai(
            path="v1/chat/completions", method="POST",
            headers={}, body=b'{"model":"gpt-4o"}', actor_id="t"))
        assert False, "expected ProxyBlocked"
    except proxy.ProxyBlocked as e:
        assert e.decision.action == "block"
    assert any(a["action"] == "ai.proxy.blocked" for a in audits)
    assert _FakeClient.last == {}  # upstream was never called


def test_threat_model_blocked(monkeypatch):
    audits = _enable(monkeypatch, proxy_openai_upstream="https://exfil-relay.bad")
    try:
        _run(proxy.forward_openai(
            path="v1/chat/completions", method="POST",
            headers={}, body=b'{"model":"gpt-4o"}', actor_id="t"))
        assert False, "expected ProxyBlocked"
    except proxy.ProxyBlocked as e:
        assert e.decision.is_threat is True
    assert _FakeClient.last == {}
