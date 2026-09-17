# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""
Vertirite — Alerts store

Holds operator alerts and exposes them to the control-plane API. The
publishable broker does NOT poll fleet nodes or run any node-exec health
checks (that is fleet-ops, which the integrating system owns); this module
is only the durable alert store plus its query/acknowledge surface. The
scheduler lifecycle hooks are retained as no-ops so start/stop wiring in
main.py stays stable.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("maestro.scheduler")

# ---------------------------------------------------------------------------
# SQLite store for alerts
# ---------------------------------------------------------------------------
_db: sqlite3.Connection | None = None
_db_lock = threading.Lock()


def _ensure_db() -> sqlite3.Connection:
    global _db
    if _db is not None:
        return _db

    import os
    db_dir = os.path.join(os.path.dirname(__file__), "..", "..", ".data")
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, "maestro_health.db")

    _db = sqlite3.connect(db_path, check_same_thread=False)
    _db.row_factory = sqlite3.Row
    _db.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            node TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            acknowledged INTEGER DEFAULT 0,
            timestamp TEXT NOT NULL
        )
    """)
    _db.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts (acknowledged, timestamp DESC)"
    )
    _db.commit()
    logger.info("Alert store initialized")
    return _db


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_alert(node: str, severity: str, message: str) -> str:
    """Create an alert and return its ID."""
    db = _ensure_db()
    alert_id = str(uuid.uuid4())
    now = _utc_now_iso()
    with _db_lock:
        db.execute(
            "INSERT INTO alerts (id, node, severity, message, acknowledged, timestamp) VALUES (?, ?, ?, ?, 0, ?)",
            (alert_id, node, severity, message, now),
        )
        db.commit()
    logger.warning("Alert [%s] %s: %s — %s", alert_id[:8], severity, node, message)
    return alert_id


def _send_notification_async(severity: str, title: str, message: str, node: str):
    """Fire-and-forget notification."""
    import asyncio

    async def _send():
        try:
            from .notifications import send_alert
            await send_alert(severity=severity, title=title, message=message, node=node)
        except Exception as e:
            logger.debug("Notification skipped: %s", e)

    try:
        loop = asyncio.new_event_loop()
        loop.run_until_complete(_send())
        loop.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Query functions (API-accessible)
# ---------------------------------------------------------------------------

def get_alerts(acknowledged: bool = False) -> list[dict]:
    """Get alerts, optionally filtering by acknowledged status."""
    db = _ensure_db()
    with _db_lock:
        rows = db.execute(
            "SELECT * FROM alerts WHERE acknowledged = ? ORDER BY timestamp DESC LIMIT 100",
            (1 if acknowledged else 0,),
        ).fetchall()
    return [dict(row) for row in rows]


def acknowledge_alert(alert_id: str) -> bool:
    """Mark an alert as acknowledged. Returns True if found and updated."""
    db = _ensure_db()
    with _db_lock:
        cursor = db.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,)
        )
        db.commit()
    if cursor.rowcount > 0:
        logger.info("Alert acknowledged: %s", alert_id)
        return True
    return False


# ---------------------------------------------------------------------------
# Scheduler lifecycle — retained as no-ops (no fleet-health polling)
# ---------------------------------------------------------------------------

def start_scheduler(interval_seconds: int = 300) -> None:
    """No-op: the publishable broker runs no fleet-health polling loop.

    Retained so main.py's startup wiring stays stable. The alert store is
    initialized lazily on first use.
    """
    _ensure_db()
    logger.info("Alert store ready (no fleet-health polling in the publishable broker)")


def stop_scheduler() -> None:
    """No-op counterpart to start_scheduler."""
    return None
