# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""session_tracker — per-session chokepoint aggregation for session-scope drift.

Completes P3's detection side (the deterministic reformulation of "intent drift",
FEATURE-break-detection.md signal #10). Where the per-agent baseline asks "is this
agent behaving like itself over its whole history?", session drift asks a narrower,
complementary question: **did this one task/session start benign and then reach for
something dangerous mid-chain?** — the signature of a session that got hijacked, even
for an agent that routinely does irreversible work in *other* sessions.

Deterministic, inference-free: a set + counter per session. In-memory with a TTL
(sessions are short-lived; this is alert-only, so restart-loss is acceptable and we
avoid a migration). Keyed by the invocation's session id (parent_request_id, else
request_id).
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

# A session must do at least this many actions WITHOUT a dangerous chokepoint
# before a later dangerous crossing counts as "drift" (vs. a task that was
# dangerous from the start, which is normal for its purpose).
MIN_BENIGN_BEFORE_DRIFT = 3
SESSION_TTL_S = 3600  # prune sessions idle longer than this
_DANGEROUS = frozenset({"irreversible", "credential"})


@dataclass
class _Session:
    chokepoints: Set[str] = field(default_factory=set)
    action_count: int = 0
    last_ts: float = field(default_factory=time.monotonic)


_LOCK = threading.Lock()
_SESSIONS: Dict[str, _Session] = {}


def _prune(now: float) -> None:
    stale = [k for k, s in _SESSIONS.items() if now - s.last_ts > SESSION_TTL_S]
    for k in stale:
        _SESSIONS.pop(k, None)


def observe(session_id: str, chokepoints: List[str]) -> Tuple[Set[str], int, List[str]]:
    """Record an action in a session. Returns (chokepoints seen BEFORE this action,
    action_count BEFORE this action, newly-dangerous chokepoints crossed now)."""
    now = time.monotonic()
    with _LOCK:
        _prune(now)
        s = _SESSIONS.get(session_id)
        if s is None:
            s = _Session()
            _SESSIONS[session_id] = s
        prior = set(s.chokepoints)
        prior_count = s.action_count
        newly_dangerous = [c for c in (chokepoints or [])
                           if c in _DANGEROUS and c not in prior]
        s.chokepoints.update(chokepoints or [])
        s.action_count += 1
        s.last_ts = now
        return prior, prior_count, newly_dangerous


def reset() -> None:
    """Test helper — clear all session state."""
    with _LOCK:
        _SESSIONS.clear()
