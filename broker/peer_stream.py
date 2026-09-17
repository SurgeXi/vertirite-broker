# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""peer_stream.py — surge-as-peer unprompted-speech channel (Brain-Ollama#11).

Three jobs:

  1. Persist unprompted messages from Brain to a DB table so they survive
     when the user has no UI session open. When user opens chat next, any
     undelivered messages get delivered first.

  2. Fan messages out to currently-connected SSE listeners (the Maestro
     console subscribes via /v1/peer-stream on session load).

  3. Enforce "quiet until useful" — per-user daily cap and dedupe within
     a 1h window so surge can't spam.

Architecture: the SSE listeners live in an in-process registry keyed by
user_id. Each listener is an asyncio.Queue. When Brain POSTs to
/v1/peer-stream/post, the broker:

  a. Validates the bearer token (must match SURGE_OPERATOR_BRAIN_PEER_TOKEN
     so only Brain can push)
  b. Runs quiet-until-useful checks
  c. Persists to unprompted_messages (id, user_id, ...)
  d. Fans out to any registered listeners for that user_id
  e. Returns {accepted: bool, reason: str, message_id: str}

When a user connects to /v1/peer-stream:
  a. Auth check (existing bearer token middleware)
  b. Replay any undelivered messages from DB (mark delivered as we go)
  c. Register an asyncio.Queue listener
  d. Yield SSE events as messages arrive
  e. On disconnect, deregister + cancel
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator

from sqlalchemy import Column, DateTime, Integer, String, Text, select, update
from sqlalchemy.orm import declarative_base

from .db import session_scope, Base

log = logging.getLogger("maestro.peer_stream")


# ---------- DB table ----------

class UnpromptedMessageTable(Base):
    __tablename__ = "unprompted_messages"
    id = Column(String(64), primary_key=True)
    user_id = Column(String(128), nullable=False, index=True)
    tenant_id = Column(String(128), nullable=False, default="creator", index=True)
    source = Column(String(64), nullable=False, default="surge-peer-unprompted")
    trigger_kind = Column(String(64), nullable=False)
    content = Column(Text, nullable=False)
    content_hash = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    delivered_at = Column(DateTime(timezone=True), nullable=True)


# ---------- in-process listener registry ----------

_listeners: dict[str, list[asyncio.Queue]] = defaultdict(list)
_listeners_lock = asyncio.Lock()


async def _register_listener(user_id: str) -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=64)
    async with _listeners_lock:
        _listeners[user_id].append(q)
    log.info("peer_stream listener attached for user_id=%s (total=%d)",
             user_id, len(_listeners[user_id]))
    return q


async def _deregister_listener(user_id: str, q: asyncio.Queue):
    async with _listeners_lock:
        if q in _listeners.get(user_id, []):
            _listeners[user_id].remove(q)
        if not _listeners.get(user_id):
            _listeners.pop(user_id, None)
    log.info("peer_stream listener detached for user_id=%s", user_id)


async def _fanout_to_user(user_id: str, payload: dict):
    async with _listeners_lock:
        listeners = list(_listeners.get(user_id, []))
    for q in listeners:
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            log.warning("listener queue full for user_id=%s — dropping message", user_id)


# ---------- quiet-until-useful guards ----------

DAILY_CAP = int(os.environ.get("SURGE_PEER_STREAM_DAILY_CAP", "3"))
DEDUPE_WINDOW_SECONDS = int(os.environ.get("SURGE_PEER_STREAM_DEDUPE_S", "3600"))


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.strip().lower().encode("utf-8")).hexdigest()[:32]


def _check_quiet_guard(user_id: str, content: str, trigger_kind: str) -> tuple[bool, str]:
    """Returns (allowed, reason). Reason is a short string for the audit log."""
    now = datetime.now(timezone.utc)
    today_start = now - timedelta(hours=24)
    dedupe_start = now - timedelta(seconds=DEDUPE_WINDOW_SECONDS)
    chash = _content_hash(content)

    with session_scope() as db:
        today_count = db.query(UnpromptedMessageTable).filter(
            UnpromptedMessageTable.user_id == user_id,
            UnpromptedMessageTable.created_at >= today_start,
        ).count()
        if today_count >= DAILY_CAP:
            return (False, f"daily cap {DAILY_CAP} reached")

        dupe = db.query(UnpromptedMessageTable).filter(
            UnpromptedMessageTable.user_id == user_id,
            UnpromptedMessageTable.content_hash == chash,
            UnpromptedMessageTable.created_at >= dedupe_start,
        ).first()
        if dupe is not None:
            return (False, f"dedupe match in last {DEDUPE_WINDOW_SECONDS}s")

    return (True, "ok")


# ---------- public API used by main.py endpoints ----------

async def post_unprompted(
    *,
    user_id: str,
    tenant_id: str,
    content: str,
    trigger_kind: str,
) -> dict:
    """Brain calls this via POST /v1/peer-stream/post.
    Returns {accepted: bool, reason: str, message_id: Optional[str]}."""
    allowed, reason = _check_quiet_guard(user_id, content, trigger_kind)
    if not allowed:
        log.info("peer_stream guarded user_id=%s trigger=%s reason=%s",
                 user_id, trigger_kind, reason)
        return {"accepted": False, "reason": reason, "message_id": None}

    msg_id = uuid.uuid4().hex[:32]
    now = datetime.now(timezone.utc)
    chash = _content_hash(content)

    with session_scope() as db:
        db.add(UnpromptedMessageTable(
            id=msg_id,
            user_id=user_id,
            tenant_id=tenant_id,
            source="surge-peer-unprompted",
            trigger_kind=trigger_kind,
            content=content,
            content_hash=chash,
            created_at=now,
            delivered_at=None,
        ))

    payload = {
        "message_id": msg_id,
        "source": "surge-peer-unprompted",
        "trigger_kind": trigger_kind,
        "content": content,
        "created_at": now.isoformat(),
    }
    await _fanout_to_user(user_id, payload)
    log.info("peer_stream accepted user_id=%s trigger=%s msg_id=%s",
             user_id, trigger_kind, msg_id)
    return {"accepted": True, "reason": "ok", "message_id": msg_id}


async def stream_for_user(user_id: str) -> AsyncIterator[str]:
    """Generator yielding SSE-formatted events for the user. First yields
    any undelivered messages from DB, then waits on the live listener queue."""
    # 1. replay undelivered
    with session_scope() as db:
        undelivered = list(db.scalars(
            select(UnpromptedMessageTable)
            .where(UnpromptedMessageTable.user_id == user_id)
            .where(UnpromptedMessageTable.delivered_at.is_(None))
            .order_by(UnpromptedMessageTable.created_at)
        ))
        for m in undelivered:
            payload = {
                "message_id": m.id,
                "source": m.source,
                "trigger_kind": m.trigger_kind,
                "content": m.content,
                "created_at": m.created_at.isoformat(),
                "replayed": True,
            }
            yield f"data: {json.dumps(payload)}\n\n"
        # mark delivered
        if undelivered:
            db.execute(
                update(UnpromptedMessageTable)
                .where(UnpromptedMessageTable.id.in_([m.id for m in undelivered]))
                .values(delivered_at=datetime.now(timezone.utc))
            )

    # 2. live tail
    q = await _register_listener(user_id)
    try:
        # Heartbeat every 25s so reverse proxies don't close idle conns
        while True:
            try:
                payload = await asyncio.wait_for(q.get(), timeout=25.0)
                yield f"data: {json.dumps(payload)}\n\n"
                # mark delivered for live messages too
                with session_scope() as db:
                    db.execute(
                        update(UnpromptedMessageTable)
                        .where(UnpromptedMessageTable.id == payload.get("message_id"))
                        .values(delivered_at=datetime.now(timezone.utc))
                    )
            except asyncio.TimeoutError:
                yield f": heartbeat {int(time.time())}\n\n"
    finally:
        await _deregister_listener(user_id, q)
