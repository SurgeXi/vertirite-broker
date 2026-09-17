# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""
Vertirite — Dashboard / Mission Control

Aggregates unacknowledged alerts and broker self-health into a single
payload for the operator dashboard. The publishable control plane has no
fleet-ops node view, no command-execution history, and no learning stats —
it authorizes, records, and audits; it does not execute.
"""

from __future__ import annotations

import logging
import time

from .config import settings

logger = logging.getLogger("maestro.dashboard")


async def get_dashboard(startup_time: float) -> dict:
    """
    Build the mission-control payload.

    Parameters
    ----------
    startup_time : float
        The broker's startup epoch (time.time() captured at startup).
    """
    from .scheduler import get_alerts

    # -- Unacknowledged alerts --
    alerts = get_alerts(acknowledged=False)

    # -- Broker self-health --
    uptime = time.time() - startup_time if startup_time else 0.0

    return {
        "alerts": alerts,
        "broker": {
            "uptime_seconds": round(uptime, 1),
            "tunnel_alive": False,
            "ollama_reachable": False,  # no bundled model in the publishable broker
        },
    }
