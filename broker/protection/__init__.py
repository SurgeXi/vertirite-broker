# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Self-protection — Mechanism #2 of the Vertirite protection model
(docs/PROTECTION-MODEL.md, "self-narcs-theft").

You cannot steal a surveillance product and use it to evade surveillance. The
product treats its OWN phone-home channel (the intelligence feed, Mechanism #1
PR3) as a monitored target: a thief who firewalls it to hide a stolen copy trips
the product's own egress detector, which raises a finding ABOUT ITSELF in the
same coverage map the customer already watches.

Submodules:
  * store.py       — the singleton instance-identity + beacon-state table.
  * identity.py    — first-run instance id + canary; beacon success/failure.
  * selfwitness.py — raise the `self-egress-suppressed` finding on suppression.
  * breaks/       — Break Detection P1: agent behavioral baseline + break events.
"""
from . import store  # noqa: F401 — registers the ORM table for init_db()
from . import breaks  # noqa: F401 — registers agent_baseline + break_events (Break Detection P1)
