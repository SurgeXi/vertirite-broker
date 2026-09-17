# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""The advisory connector emits plane-correct changes and applies nothing."""
import broker.enforcement.connectors as conn


def test_advisory_is_registered_by_default():
    assert "advisory" in conn.list_connectors()
    assert conn.get("advisory") is not None
    assert conn.get("nope") is None


def test_advisory_never_applies():
    r = conn.get("advisory").apply(target="api.openai.com", plane="north-south")
    assert r.applied is False  # dry-run, zero blast radius
    assert "DNS RPZ" in r.change
    assert "advisory" in r.detail


def test_advisory_change_is_plane_specific():
    c = conn.get("advisory")
    ns = c.apply(target="api.openai.com", plane="north-south").change
    ew = c.apply(target="10.20.3.9", plane="east-west").change
    hl = c.apply(target="127.0.0.1", plane="host-local").change
    assert "DNS RPZ" in ns
    assert "switch ACL" in ew and "do NOT inline a box" in ew
    assert "host firewall" in hl


def test_advisory_supports_all_planes():
    c = conn.get("advisory")
    assert c.supports("north-south") and c.supports("east-west") and c.supports("host-local")


def test_advisory_conforms_to_protocol():
    assert isinstance(conn.get("advisory"), conn.EnforcementConnector)


def test_real_connectors_registered():
    assert "webhook" in conn.list_connectors()
    assert "dns-rpz" in conn.list_connectors()


def test_dns_rpz_supports_only_north_south():
    c = conn.get("dns-rpz")
    assert c.supports("north-south") is True
    assert c.supports("east-west") is False


def test_apply_disabled_applies_nothing_even_when_not_dry_run(monkeypatch):
    monkeypatch.setattr(conn, "_REGISTRY", conn._REGISTRY)  # no-op, keep registry
    from broker.config import settings
    monkeypatch.setattr(settings, "enforcement_apply_enabled", False)
    monkeypatch.setattr(settings, "enforcement_webhook_url", "https://hook.example")
    r = conn.get("webhook").apply(target="api.openai.com", plane="north-south", dry_run=False)
    assert r.applied is False and "apply disabled" in r.detail


def test_dns_rpz_real_apply_writes_file(monkeypatch, tmp_path):
    from broker.config import settings
    rpz = tmp_path / "rpz.zone"
    monkeypatch.setattr(settings, "enforcement_apply_enabled", True)
    monkeypatch.setattr(settings, "enforcement_dns_rpz_path", str(rpz))
    r = conn.get("dns-rpz").apply(target="evil.example", plane="north-south", dry_run=False)
    assert r.applied is True
    assert "evil.example" in rpz.read_text() and "CNAME" in rpz.read_text()


def test_webhook_real_apply_posts(monkeypatch):
    import broker.enforcement.connectors as c
    from broker.config import settings
    monkeypatch.setattr(settings, "enforcement_apply_enabled", True)
    monkeypatch.setattr(settings, "enforcement_webhook_url", "https://hook.example/block")
    sent = {}
    class _R:
        status_code = 200
    class _C:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def post(self, url, json=None, headers=None):
            sent.update({"url": url, "json": json}); return _R()
    import httpx
    monkeypatch.setattr(httpx, "Client", _C)
    r = c.get("webhook").apply(target="api.openai.com", plane="north-south", dry_run=False)
    assert r.applied is True
    assert sent["json"] == {"action": "block", "target": "api.openai.com", "plane": "north-south"}


def test_webhook_dry_run_applies_nothing():
    r = conn.get("webhook").apply(target="x", plane="north-south", dry_run=True)
    assert r.applied is False and "dry-run" in r.detail
