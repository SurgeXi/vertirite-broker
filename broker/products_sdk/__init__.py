# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""SurgeXi Products SDK — minimal Python client for invoking Surge.

Any SurgeXi product (Music Production Edge, Accounting Pros,
Managed IT, geopro, qcheck, ...) imports this module to call Surge.

Quickstart:

    from broker.products_sdk import SurgeClient

    surge = SurgeClient.from_env()  # reads SURGE_BROKER_URL + SURGE_TOKEN

    # Free-form intent
    result = await surge.invoke(
        intent="add a tenant for Acme Plumbing, owner acme@example.com",
        tenant_id="creator",
    )

    # Direct capability
    result = await surge.dispatch(
        capability="support_ticket_list",
        params={"status": "escalated"},
        tenant_id="creator",
    )

    # Discovery
    caps = await surge.list_capabilities()
    pbs  = await surge.list_playbooks()

The client is async-first (matches the broker's async surface). For
sync code, wrap with `asyncio.run(...)`.

Distribution: this module is bundled with the broker for now. When
consumer repos start depending on it heavily, we'll extract to a
separate published package (`pip install surgexi-products-sdk`).
"""

from .client import (
    SurgeClient,
    InvokeResult,
    DispatchResult,
    SurgeError,
    SurgeUnreachable,
    AwaitingApproval,
    AwaitingCapability,
)

__all__ = [
    "SurgeClient",
    "InvokeResult",
    "DispatchResult",
    "SurgeError",
    "SurgeUnreachable",
    "AwaitingApproval",
    "AwaitingCapability",
]
