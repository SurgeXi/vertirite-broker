# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Generic webhook payload carries the alert text as both `message` and `body`."""
from __future__ import annotations

import asyncio
import os
import tempfile

_db_fd, _db_path = tempfile.mkstemp(suffix="-webhook.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from . import notifications as N  # noqa: E402
from .config import settings  # noqa: E402


def test_generic_webhook_has_body_and_message(monkeypatch):
    sent = {}

    async def fake_webhook(url, payload):
        sent.update(payload)

    monkeypatch.setattr(N, "send_webhook_alert", fake_webhook)
    monkeypatch.setattr(settings, "alert_email_enabled", False)
    monkeypatch.setattr(settings, "alert_pushover_enabled", False)
    monkeypatch.setattr(settings, "alert_webhook_enabled", True)
    monkeypatch.setattr(settings, "alert_webhook_url", "http://receiver.example.internal/hook")
    asyncio.run(N.send_alert(severity="critical", title="Approval needed: x", message="details", node="approvals"))
    assert sent["body"] == sent["message"] and "details" in sent["body"]
    assert sent["source"] == "vertirite-broker" and "Approval needed: x" in sent["title"]
