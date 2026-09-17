# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""runtime_config — operator-settable feature flags for Break Detection.

The break-detection flags started life as env vars (VERTIRITE_BREAK_DETECTION /
VERTIRITE_DETECT_CONTAIN), which need a container restart to change. This adds a
runtime override an operator can flip from the Vertirite interface without a
restart: an override row in `runtime_flags` wins over the env default.

`effective()` is on the gate hot path (checked per dispatch for detect_contain),
so overrides are cached in-process with a short TTL — at most one tiny DB read
every CACHE_TTL_S per flag, not one per action. Deterministic, no model.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ...db import Base, session_scope

CACHE_TTL_S = 5.0

# flag key -> (env var, env default). The env is the fallback when no override row.
FLAGS = {
    "break_detection": ("VERTIRITE_BREAK_DETECTION", "0"),
    "detect_contain": ("VERTIRITE_DETECT_CONTAIN", "0"),
}

# key -> (value, expires_at) in-process cache.
_CACHE: Dict[str, Tuple[Optional[str], float]] = {}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RuntimeFlagTable(Base):
    __tablename__ = "runtime_flags"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(16), nullable=False)  # "1" / "0"
    updated_by: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


def _override(key: str) -> Optional[str]:
    """DB override for a flag, cached; None if no override row set."""
    now = time.monotonic()
    cached = _CACHE.get(key)
    if cached is not None and cached[1] > now:
        return cached[0]
    val: Optional[str] = None
    try:
        with session_scope() as db:
            row = db.get(RuntimeFlagTable, key)
            val = row.value if row is not None else None
    except Exception:
        val = None  # table missing / DB blip -> fall back to env (fail-safe)
    _CACHE[key] = (val, now + CACHE_TTL_S)
    return val


def _truthy(v: Optional[str]) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "on"}


def effective(key: str) -> bool:
    """The flag's effective value: DB override if set, else the env default."""
    env_var, env_default = FLAGS.get(key, ("", "0"))
    ov = _override(key)
    if ov is not None:
        return _truthy(ov)
    return _truthy(os.environ.get(env_var, env_default))


def set_flag(key: str, value: bool, actor: str, note: str = "") -> Dict:
    """Operator override. Persists + invalidates the cache immediately."""
    if key not in FLAGS:
        raise ValueError(f"unknown flag {key!r}; must be one of {sorted(FLAGS)}")
    with session_scope() as db:
        row = db.get(RuntimeFlagTable, key)
        if row is None:
            row = RuntimeFlagTable(key=key)
            db.add(row)
        row.value = "1" if value else "0"
        row.updated_by = actor
        row.updated_at = _utc_now()
        if note:
            row.note = note.strip()[:512]
        db.flush()
    _CACHE.pop(key, None)  # next read reflects it
    return status()


def status() -> Dict:
    """Current effective state + source (override vs env) for the UI."""
    out: Dict[str, Dict] = {}
    for key, (env_var, env_default) in FLAGS.items():
        ov = _override(key)
        out[key] = {
            "enabled": effective(key),
            "source": "override" if ov is not None else "env",
            "env_default": _truthy(os.environ.get(env_var, env_default)),
        }
    return out
