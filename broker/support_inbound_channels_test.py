# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Inbound support tickets notify the operator through THIS broker's alert channels only.

Before: every inbound ticket POSTed to a hardcoded ntfy URL/topic (a SurgeXi-fleet pattern)
from the customer's broker. Now it goes through notifications.send_alert, which uses only the
channels the operator configured, and the module makes no HTTP call of its own.
"""
from __future__ import annotations

import asyncio
import inspect
import os
import tempfile

_db_fd, _db_path = tempfile.mkstemp(suffix="-inbound.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from . import notifications  # noqa: E402
from . import support_inbound as SI  # noqa: E402
from .db import Base, engine, init_db  # noqa: E402

init_db()
Base.metadata.create_all(engine)


def test_inbound_ticket_notifies_via_operator_channels(monkeypatch):
    sent = []

    async def fake_send_alert(severity, title, message, node=None):
        sent.append((severity, title, node))
        return {"channels": {}}

    monkeypatch.setattr(notifications, "send_alert", fake_send_alert)
    out = asyncio.run(SI.inbound_create_ticket(channel="email", sender_identity="user@customer.example",
                                               source_ip="192.0.2.10", subject="broken", body="help",
                                               priority="high"))
    assert out["ok"] and out["ticket"]
    assert sent == [("critical", "Inbound support ticket via email", "support")]


def test_module_makes_no_direct_http_call():
    src = inspect.getsource(SI)
    assert "httpx" not in src and "8088" not in src and "ntfy" not in src.lower()
