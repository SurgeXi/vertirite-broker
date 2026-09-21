# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""
Maestro AI — Remote Alert Notification System

Delivers critical alerts through multiple channels:
1. Email (SMTP) — send to configured recipients
2. Webhook (generic) — POST to Slack, Discord, Teams, or custom URL
3. Pushover (phone push notifications) — real-time mobile alerts

All channels are independently configurable. The system checks which
channels are enabled and delivers through each active one.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import httpx

from .config import settings

logger = logging.getLogger("maestro.notifications")

# ── Delivery log (in-memory, last 100) ───────────────────────────────

_delivery_log: list[dict] = []
_MAX_LOG = 100


def _log_delivery(channel: str, severity: str, title: str, success: bool, error: str = ""):
    """Record a delivery attempt."""
    entry = {
        "channel": channel,
        "severity": severity,
        "title": title,
        "success": success,
        "error": error,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _delivery_log.append(entry)
    if len(_delivery_log) > _MAX_LOG:
        _delivery_log.pop(0)
    if success:
        logger.info("Alert delivered via %s: [%s] %s", channel, severity, title)
    else:
        logger.warning("Alert delivery FAILED via %s: [%s] %s — %s", channel, severity, title, error)


def get_delivery_log() -> list[dict]:
    """Return the last 100 delivery attempts."""
    return _delivery_log[-50:]


# ── Alert Settings ───────────────────────────────────────────────────

def get_alert_settings() -> dict:
    """Return current alert configuration (secrets redacted)."""
    return {
        "email": {
            "enabled": settings.alert_email_enabled,
            "to": settings.alert_email_to,
            "smtp_host": settings.alert_email_smtp_host,
            "smtp_port": settings.alert_email_smtp_port,
            "smtp_user": settings.alert_email_smtp_user,
            "smtp_pass_set": bool(settings.alert_email_smtp_pass),
        },
        "webhook": {
            "enabled": settings.alert_webhook_enabled,
            "url_set": bool(settings.alert_webhook_url),
        },
        "pushover": {
            "enabled": settings.alert_pushover_enabled,
            "token_set": False,  # checked from keyvault below
            "user_set": False,
        },
    }


async def get_alert_settings_full() -> dict:
    """Return alert settings with Pushover key status from keyvault."""
    result = get_alert_settings()

    # Check keyvault for Pushover keys
    try:
        from .keyvault import get_key_by_name
        pushover_token = get_key_by_name("pushover_api_token")
        pushover_user = get_key_by_name("pushover_user_key")
        result["pushover"]["token_set"] = pushover_token is not None
        result["pushover"]["user_set"] = pushover_user is not None
    except Exception:
        pass

    return result


# ── Core Alert Dispatcher ────────────────────────────────────────────

async def send_alert(
    severity: str,
    title: str,
    message: str,
    node: Optional[str] = None,
) -> dict:
    """Send an alert through all configured channels.

    Args:
        severity: "critical", "warning", or "info"
        title: Short alert title
        message: Detailed alert message
        node: Optional node name that triggered the alert

    Returns:
        dict with delivery results per channel
    """
    results = {
        "severity": severity,
        "title": title,
        "channels": {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    full_title = f"[Maestro {severity.upper()}] {title}"
    if node:
        full_title = f"[Maestro {severity.upper()}] [{node}] {title}"

    full_message = f"{message}\n\nNode: {node or 'N/A'}\nTime: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"

    # Email
    if settings.alert_email_enabled and settings.alert_email_smtp_host:
        try:
            await send_email_alert(
                to=settings.alert_email_to,
                subject=full_title,
                body=full_message,
            )
            results["channels"]["email"] = {"status": "sent"}
            _log_delivery("email", severity, title, True)
        except Exception as e:
            results["channels"]["email"] = {"status": "failed", "error": str(e)}
            _log_delivery("email", severity, title, False, str(e))

    # Webhook
    if settings.alert_webhook_enabled and settings.alert_webhook_url:
        try:
            payload = {
                "severity": severity,
                "title": full_title,
                "message": full_message,
                "node": node,
                "timestamp": results["timestamp"],
                "source": "vertirite-broker",
            }
            await send_webhook_alert(settings.alert_webhook_url, payload)
            results["channels"]["webhook"] = {"status": "sent"}
            _log_delivery("webhook", severity, title, True)
        except Exception as e:
            results["channels"]["webhook"] = {"status": "failed", "error": str(e)}
            _log_delivery("webhook", severity, title, False, str(e))

    # Pushover
    if settings.alert_pushover_enabled:
        try:
            from .keyvault import get_key_by_name
            pushover_token = get_key_by_name("pushover_api_token")
            pushover_user = get_key_by_name("pushover_user_key")
            if pushover_token and pushover_user:
                # Map severity to Pushover priority
                priority_map = {
                    "critical": 1,   # high priority, bypass quiet hours
                    "warning": 0,    # normal priority
                    "info": -1,      # low priority, no sound
                }
                priority = priority_map.get(severity, 0)
                await send_pushover_alert(
                    token=pushover_token,
                    user=pushover_user,
                    title=full_title,
                    message=full_message,
                    priority=priority,
                )
                results["channels"]["pushover"] = {"status": "sent"}
                _log_delivery("pushover", severity, title, True)
            else:
                results["channels"]["pushover"] = {"status": "skipped", "reason": "keys not in vault"}
                _log_delivery("pushover", severity, title, False, "keys not in vault")
        except Exception as e:
            results["channels"]["pushover"] = {"status": "failed", "error": str(e)}
            _log_delivery("pushover", severity, title, False, str(e))

    active = sum(1 for c in results["channels"].values() if c.get("status") == "sent")
    total = len(results["channels"])
    if total == 0:
        logger.info("Alert [%s] %s — no channels configured", severity, title)
    else:
        logger.info("Alert [%s] %s — delivered to %d/%d channels", severity, title, active, total)

    return results


# ── Email Channel ────────────────────────────────────────────────────

async def send_email_alert(to: str, subject: str, body: str) -> None:
    """Send an alert via SMTP.

    Uses STARTTLS on the configured SMTP host/port.
    Runs synchronously (SMTP is blocking) but is fast enough for alerts.
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.alert_email_smtp_user or "alerts@example.com"
    msg["To"] = to

    # Plain text part
    msg.attach(MIMEText(body, "plain"))

    # HTML part
    html_body = f"""
    <html>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
            <div style="background: #1a1a2e; color: #fff; padding: 16px 20px;">
                <h2 style="margin: 0; font-size: 18px;">{subject}</h2>
            </div>
            <div style="padding: 20px; background: #fff; color: #333;">
                <pre style="white-space: pre-wrap; font-family: 'SF Mono', Menlo, monospace; font-size: 13px; line-height: 1.5;">{body}</pre>
            </div>
            <div style="padding: 12px 20px; background: #f5f5f5; color: #888; font-size: 12px;">
                Sent by Maestro AI — Maestro
            </div>
        </div>
    </body>
    </html>
    """
    msg.attach(MIMEText(html_body, "html"))

    context = ssl.create_default_context()

    with smtplib.SMTP(settings.alert_email_smtp_host, settings.alert_email_smtp_port) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        if settings.alert_email_smtp_user and settings.alert_email_smtp_pass:
            server.login(settings.alert_email_smtp_user, settings.alert_email_smtp_pass)
        server.sendmail(msg["From"], [to], msg.as_string())

    logger.info("Email alert sent to %s: %s", to, subject)


# ── Webhook Channel ──────────────────────────────────────────────────

async def send_webhook_alert(url: str, payload: dict) -> None:
    """Send an alert via webhook POST.

    Compatible with Slack incoming webhooks, Discord webhooks,
    Microsoft Teams connectors, and any generic JSON webhook.
    """
    # Detect Slack/Discord format and adapt payload
    if "hooks.slack.com" in url or "discord.com/api/webhooks" in url:
        # Slack/Discord expect a specific format
        severity = payload.get("severity", "info")
        color_map = {"critical": "#ff0000", "warning": "#ff9900", "info": "#0099ff"}
        webhook_body = {
            "text": payload["title"],
            "attachments": [
                {
                    "color": color_map.get(severity, "#0099ff"),
                    "title": payload["title"],
                    "text": payload["message"],
                    "footer": f"Maestro AI | {payload.get('node', 'N/A')}",
                    "ts": payload.get("timestamp", ""),
                }
            ],
        }
    else:
        # Generic JSON webhook
        webhook_body = payload

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(url, json=webhook_body)
        resp.raise_for_status()

    logger.info("Webhook alert sent to %s", url[:60])


# ── Pushover Channel ────────────────────────────────────────────────

async def send_pushover_alert(
    token: str,
    user: str,
    title: str,
    message: str,
    priority: int = 0,
) -> None:
    """Send an alert via Pushover API (phone push notification).

    Priority levels:
        -2: no notification
        -1: quiet notification (no sound)
         0: normal
         1: high priority (bypass quiet hours)
         2: emergency (repeated until acknowledged)
    """
    payload = {
        "token": token,
        "user": user,
        "title": title,
        "message": message[:1024],  # Pushover limit
        "priority": priority,
        "sound": "siren" if priority >= 1 else "pushover",
    }

    # Emergency priority requires retry and expire params
    if priority == 2:
        payload["retry"] = 60      # retry every 60 seconds
        payload["expire"] = 3600   # stop after 1 hour

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post("https://api.pushover.net/1/messages.json", data=payload)
        resp.raise_for_status()

    logger.info("Pushover alert sent: %s (priority=%d)", title[:50], priority)


# ── Test Alert ───────────────────────────────────────────────────────

async def send_test_alert() -> dict:
    """Send a test alert through all configured channels."""
    return await send_alert(
        severity="info",
        title="Test Alert",
        message="This is a test alert from Maestro AI. If you received this, your alert channel is working correctly.",
        node="vertirite-broker",
    )


# ── Chat-Friendly Summary ───────────────────────────────────────────

async def get_alert_settings_summary() -> str:
    """Return a formatted summary of alert settings for chat."""
    cfg = await get_alert_settings_full()

    lines = ["**Alert Notification Settings**\n"]

    # Email
    email = cfg["email"]
    status = "ENABLED" if email["enabled"] else "disabled"
    lines.append(f"  Email: **{status}**")
    if email["enabled"]:
        lines.append(f"    To: {email['to']}")
        lines.append(f"    SMTP: {email['smtp_host']}:{email['smtp_port']}")
        lines.append(f"    Credentials: {'configured' if email['smtp_pass_set'] else 'NOT SET'}")

    # Webhook
    webhook = cfg["webhook"]
    status = "ENABLED" if webhook["enabled"] else "disabled"
    lines.append(f"  Webhook: **{status}**")
    if webhook["enabled"]:
        lines.append(f"    URL: {'configured' if webhook['url_set'] else 'NOT SET'}")

    # Pushover
    pushover = cfg["pushover"]
    status = "ENABLED" if pushover["enabled"] else "disabled"
    lines.append(f"  Pushover: **{status}**")
    if pushover["enabled"]:
        lines.append(f"    API Token: {'in vault' if pushover['token_set'] else 'NOT SET'}")
        lines.append(f"    User Key: {'in vault' if pushover['user_set'] else 'NOT SET'}")

    # Recent deliveries
    recent = _delivery_log[-5:]
    if recent:
        lines.append(f"\n**Recent Deliveries ({len(_delivery_log)} total):**")
        for d in recent:
            icon = "ok" if d["success"] else "FAILED"
            lines.append(f"  - [{d['severity']}] {d['title'][:40]} via {d['channel']} — {icon}")

    active_count = sum(1 for k in ["email", "webhook", "pushover"] if cfg[k]["enabled"])
    if active_count == 0:
        lines.append("\nNo alert channels are enabled. Configure in environment variables or settings.")
    else:
        lines.append(f"\n{active_count} channel(s) active.")

    return "\n".join(lines)
