# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Break Detection (P1) — behavioral integrity for governed agents.

The temporal layer of the Vertirite spine: Discovery *sees* AI, Containment
*stops* individual actions by chokepoint, and Break Detection asks whether a
governed agent still behaves like *itself* over time. A break is a deviation
from the agent's learned-normal, or an action that is off-policy regardless of
history. Deterministic and inference-free — no model in the loop (the
non-inference invariant).

See docs/FEATURE-break-detection.md + docs/PR-break-detection-p1.md.

Importing this package registers the ORM tables for init_db(). The gate imports
``service`` explicitly to keep this import light during init_db().
"""
from . import baseline           # noqa: F401 — registers agent_baseline
from . import events             # noqa: F401 — registers break_events
from . import containment_state  # noqa: F401 — registers agent_containment_state (P3 detect->contain)
from . import runtime_config      # noqa: F401 — registers runtime_flags (operator interface toggles)
