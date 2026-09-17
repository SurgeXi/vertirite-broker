# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""support_inbound.py — fallback issue-reporting channels.

When AI is THE problem, the in-app ticket system can fail too. This module
gives users alternate paths that DON'T require Brain to be up:

  - Public web form on /status (HTML POST → /v1/tickets/public)
  - Email-to-ticket (mail watcher already running on node-01 parses
    incoming mail to support@... and POSTs here)
  - SMS-to-ticket (Twilio webhook → /v1/tickets/inbound-sms; not wired
    until a phone number is provisioned, but the endpoint is here)

All three converge on `inbound_create_ticket()` which:
  - Persists the ticket immediately (no Brain dependency)
  - Maps inbound identity (email / phone) to a user_id when possible
  - Always pings the operator's ntfy topic — these channels exist
    BECAUSE the AI/in-app path failed, so operator notification is
    not optional
  - Then BEST-EFFORT tries the surge triage; if Brain is down, the
    ticket sits in `open` until operator looks at it

Security posture:
  - These endpoints accept unauthenticated POSTs, so they're rate-limited
    by IP (10 / 5min per IP) and content size (subject ≤300, body ≤8000)
  - Spam guard: simple heuristic + sender-domain reputation could land
    later; for now, the operator ntfy push is the canary
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from .db import session_scope
from .support import SupportTicketTable, _row_to_dict_from_table

log = logging.getLogger("maestro.support_inbound")

NTFY_URL = os.environ.get("SURGE_NTFY_URL", "http://localhost:8088").rstrip("/")
NTFY_TOPIC_OPS = os.environ.get("SURGE_ACTIONS_TOPIC", "surgexi-actions-todd")
RATE_LIMIT_PER_IP_5MIN = int(os.environ.get("SURGE_INBOUND_RATE_LIMIT_5MIN", "10"))


# ---------- in-memory rate limit (per source IP) ----------

_ip_window: dict[str, list[float]] = {}


def _rate_limit_ok(ip: str) -> bool:
    now = time.time()
    bucket = _ip_window.setdefault(ip, [])
    # Drop entries older than 5 minutes
    cutoff = now - 300
    while bucket and bucket[0] < cutoff:
        bucket.pop(0)
    if len(bucket) >= RATE_LIMIT_PER_IP_5MIN:
        return False
    bucket.append(now)
    return True


# ---------- identity mapping ----------

EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def _user_id_from_email(email: str) -> str:
    """Map sender email → user_id. For now, look up tenant_users by email;
    fall back to a deterministic 'inbound-<sha>' pseudo-user so the same
    sender's tickets cluster.
    """
    if not email or not EMAIL_RE.match(email):
        return f"inbound-anon-{hashlib.sha256(b'unknown').hexdigest()[:8]}"
    try:
        from .tenant import get_tenant_user_by_email
        u = get_tenant_user_by_email(email.lower())
        if u and u.get("id"):
            return u["id"]
    except Exception:
        pass
    return f"inbound-{hashlib.sha256(email.lower().encode()).hexdigest()[:12]}"


def _user_id_from_phone(phone: str) -> str:
    digits = re.sub(r"\D", "", phone or "")
    return f"inbound-sms-{digits[-10:] or 'unknown'}"


# ---------- core ----------

async def inbound_create_ticket(
    *,
    channel: str,                # "web_form" | "email" | "sms"
    sender_identity: str,        # email / phone / form-supplied address
    source_ip: str,
    product: str = "general",
    subject: str = "",
    body: str = "",
    priority: str = "medium",
) -> dict:
    """Create a ticket from a fallback (non-authed) channel. Always pages
    operator. Best-effort triage.
    """
    if not _rate_limit_ok(source_ip):
        log.warning("rate-limited inbound from ip=%s channel=%s", source_ip, channel)
        return {"ok": False, "error": "rate_limited",
                "detail": f"more than {RATE_LIMIT_PER_IP_5MIN} requests in 5 minutes from your IP"}

    if channel == "email":
        user_id = _user_id_from_email(sender_identity)
    elif channel == "sms":
        user_id = _user_id_from_phone(sender_identity)
    else:
        user_id = _user_id_from_email(sender_identity) if sender_identity else "inbound-web-anonymous"

    if not subject:
        subject = f"[{channel}] (no subject)"
    if not body:
        body = "(empty body)"

    # Persist directly — no Brain dependency
    ticket_id = hashlib.sha256(f"{user_id}:{time.time()}".encode()).hexdigest()[:24]
    now = datetime.now(timezone.utc)
    with session_scope() as db:
        db.add(SupportTicketTable(
            id=ticket_id,
            user_id=user_id,
            tenant_id="creator",  # multi-tenant: derive from email lookup later
            product=product[:64],
            subject=subject[:300],
            body=body[:8000],
            status="open",
            priority=priority,
            triage_summary=f"INBOUND via {channel} from {sender_identity[:80]}",
            audit_context=None,
            created_at=now,
            updated_at=now,
        ))
    log.info("inbound ticket created id=%s channel=%s sender=%s",
             ticket_id, channel, sender_identity[:40])

    # ALWAYS ntfy operator — these channels exist precisely because the
    # in-app path may be broken, so operator awareness is non-optional
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(
                f"{NTFY_URL}/{NTFY_TOPIC_OPS}",
                data=(f"📨 INBOUND {channel.upper()} ticket\n"
                      f"From: {sender_identity}\n"
                      f"Product: {product}\n"
                      f"Subject: {subject[:120]}\n"
                      f"Body: {body[:300]}").encode(),
                headers={
                    # HTTP headers are latin-1 only; keep title plain ASCII.
                    # Emoji + non-ASCII flair stays in the body.
                    "Title": f"Inbound ticket - {channel}",
                    "Priority": "urgent" if priority in ("high", "critical") else "high",
                    "Tags": f"ticket,inbound,{channel}",
                },
            )
    except Exception as e:
        log.warning("operator ntfy push failed for inbound id=%s: %s", ticket_id, e)

    # Best-effort triage — if Brain is down, this just leaves status=open
    # which is exactly the right behavior (operator owns it)
    try:
        from .support import _run_triage
        import asyncio as _asyncio
        _asyncio.create_task(_run_triage(ticket_id))
    except Exception as e:
        log.warning("background triage kick-off failed for inbound id=%s: %s", ticket_id, e)

    with session_scope() as db:
        row = db.get(SupportTicketTable, ticket_id)
        return {"ok": True, "ticket": _row_to_dict_from_table(row) if row else None}


# ---------- email parsing helper ----------

def parse_email_to_ticket_args(raw_email: str) -> dict:
    """Pull subject / body / sender from a raw RFC822 email. Used by the
    mail watcher when it picks up mail to support@..."""
    import email as email_lib
    msg = email_lib.message_from_string(raw_email)
    subject = msg.get("Subject", "(no subject)")
    sender = msg.get("From", "")
    sender_match = EMAIL_RE.search(sender)
    sender_email = sender_match.group(0) if sender_match else sender
    if msg.is_multipart():
        body = ""
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(errors="replace")
    else:
        body = msg.get_payload(decode=True).decode(errors="replace") if msg.get_payload() else ""
    # Tag music vs general from To: address conventions
    to = (msg.get("To") or "").lower()
    product = "music" if "music" in to else "general"
    return {
        "channel": "email",
        "sender_identity": sender_email,
        "subject": subject.strip()[:300],
        "body": body.strip()[:8000],
        "product": product,
    }
