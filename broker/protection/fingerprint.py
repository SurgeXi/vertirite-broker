# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""A stable environment fingerprint for this install (Mechanism #2 PR2).

Hash of hostname + platform + machine-id. A copy moved to a different machine
produces a different fingerprint, so the control plane raises a
``foreign-fingerprint`` signal. Also the seed for Mechanism #3 (behavioral
binding). Metadata only — a one-way hash, no raw host details leave the box.
"""
from __future__ import annotations

import hashlib
import platform
import socket
from typing import Optional

_cached: Optional[str] = None


def _machine_id() -> str:
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(p) as f:
                v = f.read().strip()
                if v:
                    return v
        except OSError:
            pass
    return ""


def compute() -> str:
    """A short, stable hex digest of this environment. Cached in-process."""
    global _cached
    if _cached is not None:
        return _cached
    parts = [socket.gethostname(), platform.system(), platform.machine(), _machine_id()]
    _cached = hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]
    return _cached


def reset_cache() -> None:
    """Test hook."""
    global _cached
    _cached = None
