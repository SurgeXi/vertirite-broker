# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Email alert channel: the operator's own relay, escaped content, Vertirite branding."""
from __future__ import annotations

import asyncio
import os
import tempfile

_db_fd, _db_path = tempfile.mkstemp(suffix="-email.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from . import notifications as N  # noqa: E402
from .config import settings  # noqa: E402


class FakeSMTP:
    instances: list = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.calls, self.sent = host, port, [], None
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def starttls(self, context=None):
        self.calls.append("starttls")

    def login(self, u, p):
        self.calls.append("login")

    def sendmail(self, frm, to, msg):
        self.sent = msg


def _send(monkeypatch, **cfg):
    FakeSMTP.instances.clear()
    monkeypatch.setattr(N.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(settings, "alert_email_smtp_host", "relay.example.internal")
    monkeypatch.setattr(settings, "alert_email_smtp_port", 25)
    for k, v in cfg.items():
        monkeypatch.setattr(settings, k, v)
    asyncio.run(N.send_email_alert("ops@example.com", "Approval needed: <b>x</b>",
                                   "summary <script>alert(1)</script>"))
    return FakeSMTP.instances[-1]


def test_html_part_is_escaped_and_branded(monkeypatch):
    s = _send(monkeypatch, alert_email_starttls=False)
    html_part = s.sent.split("Content-Type: text/html", 1)[1]   # the rendered part
    assert "<script>alert(1)</script>" not in html_part
    assert "&lt;script&gt;" in html_part and "&lt;b&gt;x&lt;/b&gt;" in html_part
    assert "Sent by Vertirite" in html_part and "Maestro" not in s.sent


def test_starttls_on_by_default(monkeypatch):
    s = _send(monkeypatch)
    assert s.calls[:2] == ["ehlo", "starttls"]


def test_starttls_can_be_off_for_an_onprem_relay(monkeypatch):
    s = _send(monkeypatch, alert_email_starttls=False)
    assert "starttls" not in s.calls and s.sent


def test_internal_ca_file_is_used(monkeypatch):
    seen = {}

    def fake_ctx(cafile=None):
        seen["cafile"] = cafile
        return None

    monkeypatch.setattr(N.ssl, "create_default_context", fake_ctx)
    _send(monkeypatch, alert_email_ca_file="/etc/ssl/internal-ca.pem")
    assert seen["cafile"] == "/etc/ssl/internal-ca.pem"
