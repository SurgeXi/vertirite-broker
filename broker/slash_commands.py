# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""
Maestro AI — Slash Command Registry

Slash commands provide quick access to special functions.
Type / in the input to see available commands.
"""

from __future__ import annotations

SLASH_COMMANDS = [
    {
        "command": "/help",
        "description": "Show all available commands",
        "category": "general",
    },
    {
        "command": "/btw",
        "description": "Add context without running a command — side note to Maestro",
        "category": "general",
    },
    {
        "command": "/clear",
        "description": "Clear the conversation",
        "category": "general",
    },
    {
        "command": "/new",
        "description": "Start a new chat",
        "category": "general",
    },
    {
        "command": "/briefing",
        "description": "Morning briefing — fleet, brain, alerts, trends",
        "category": "operations",
    },
    {
        "command": "/baseline",
        "description": "Full node-01 system baseline",
        "category": "operations",
    },
    {
        "command": "/brain",
        "description": "Check Ollama brain health and inference status",
        "category": "operations",
    },
    {
        "command": "/fleet",
        "description": "Fleet health across all nodes",
        "category": "operations",
    },
    {
        "command": "/nodes",
        "description": "List all available remote nodes",
        "category": "operations",
    },
    {
        "command": "/alerts",
        "description": "Show pending alerts and approvals",
        "category": "operations",
    },
    {
        "command": "/search",
        "description": "Search the web — /search <query>",
        "category": "tools",
    },
    {
        "command": "/find",
        "description": "Search files across the network — /find <query>",
        "category": "tools",
    },
    {
        "command": "/read",
        "description": "Read a document or file — /read <path>",
        "category": "tools",
    },
    {
        "command": "/open",
        "description": "Open and read any document (PDF, DOCX, XLSX, etc.)",
        "category": "tools",
    },
    {
        "command": "/plugins",
        "description": "List installed plugins",
        "category": "tools",
    },
    {
        "command": "/memory",
        "description": "Search Maestro's long-term memory",
        "category": "knowledge",
    },
    {
        "command": "/learn",
        "description": "Show what Maestro has learned from interactions",
        "category": "knowledge",
    },
    {
        "command": "/who",
        "description": "Show what Maestro knows about you",
        "category": "knowledge",
    },
    {
        "command": "/context",
        "description": "List loaded context files",
        "category": "knowledge",
    },
    {
        "command": "/logs",
        "description": "View recent broker logs",
        "category": "admin",
    },
    {
        "command": "/debug",
        "description": "Toggle debug logging mode",
        "category": "admin",
    },
    {
        "command": "/voice",
        "description": "Start a voice session",
        "category": "modes",
    },
    {
        "command": "/schedule",
        "description": "Schedule a recurring task — /schedule \"command\" every 6h",
        "category": "automation",
    },
    {
        "command": "/automate",
        "description": "Create event trigger — /automate when disk>85% then \"command\"",
        "category": "automation",
    },
    {
        "command": "/schedules",
        "description": "List all scheduled tasks",
        "category": "automation",
    },
    {
        "command": "/triggers",
        "description": "List all event triggers",
        "category": "automation",
    },
    {
        "command": "/alert",
        "description": "Show alert notification settings and delivery log",
        "category": "admin",
    },
    {
        "command": "/test-alert",
        "description": "Send a test alert through all configured channels",
        "category": "admin",
    },
    {
        "command": "/diagnose",
        "description": "Run self-diagnosis on all Maestro systems",
        "category": "admin",
    },
    {
        "command": "/heal",
        "description": "Trigger self-healing — fix detected issues",
        "category": "admin",
    },
    {
        "command": "/ssh",
        "description": "Run command on a remote node — /ssh <node> <command>",
        "category": "remote",
    },
    {
        "command": "/status",
        "description": "Full health check on a node — /status <node>",
        "category": "remote",
    },
    {
        "command": "/all",
        "description": "Run command on ALL nodes — /all <command>",
        "category": "remote",
    },
    {
        "command": "/admin",
        "description": "Platform admin — /admin help, tenants, users, upgrade <email> <plan>, grant <email>, revoke <email>, audit",
        "category": "admin-platform",
    },
]


ADMIN_HELP = (
    "Platform admin commands:\n"
    "  /admin tenants                 — list tenants with plans and balances\n"
    "  /admin users                   — list users across all tenants\n"
    "  /admin admins                  — list platform admins\n"
    "  /admin upgrade <email> <plan>  — change a user's tenant plan\n"
    "  /admin grant <email>           — grant platform_admin to a user\n"
    "  /admin revoke <email>          — revoke platform_admin from a user\n"
    "  /admin audit                   — recent admin actions"
)


def handle_admin_command(actor_id: str, actor_role: str, text: str) -> str:
    """Execute an /admin slash command. Returns the display message.

    Must be called only after role gating. Returns a human-friendly string
    that the chat handler renders to the user.
    """
    if actor_role != "platform_admin":
        return "Unknown command. Type /help for a list of commands."

    parts = text.strip().split()
    if len(parts) < 2 or parts[1] == "help":
        return ADMIN_HELP

    sub = parts[1].lower()

    from .tenant import (
        PLAN_TOKEN_ALLOCATION,
        VALID_ROLES,
        get_tenant,
        get_tenant_user_by_email,
        list_all_users,
        list_platform_admins,
        update_tenant_plan,
        update_user_role,
    )
    from .repository import write_audit_event, list_audit_events

    if sub == "tenants":
        from .db import session_scope
        from .tenant import TenantTable
        from sqlalchemy import select
        with session_scope() as db:
            rows = db.execute(select(TenantTable)).scalars().all()
            lines = [f"{'NAME':30} {'PLAN':14} {'BALANCE':>14} {'USED':>10}"]
            for t in rows:
                lines.append(f"{t.name[:30]:30} {t.plan:14} {t.token_balance:>14,} {t.tokens_used_total:>10,}")
        return "\n".join(lines)

    if sub == "users":
        users = list_all_users()
        lines = [f"{'EMAIL':40} {'ROLE':16} {'STATUS':10}"]
        for u in users:
            lines.append(f"{u['email'][:40]:40} {u['role']:16} {u['status']:10}")
        return "\n".join(lines)

    if sub == "admins":
        admins = list_platform_admins()
        if not admins:
            return "No platform admins."
        return "Platform admins:\n" + "\n".join(f"  {a['email']} ({a['display_name']})" for a in admins)

    if sub == "upgrade":
        if len(parts) < 4:
            return "Usage: /admin upgrade <email> <plan>"
        email, plan = parts[2], parts[3]
        if plan not in PLAN_TOKEN_ALLOCATION:
            return f"Invalid plan '{plan}'. Valid: {list(PLAN_TOKEN_ALLOCATION.keys())}"
        user = get_tenant_user_by_email(email)
        if user is None:
            return f"No user with email {email}"
        previous = get_tenant(user["tenant_id"])
        previous_plan = previous["plan"] if previous else "unknown"
        updated = update_tenant_plan(user["tenant_id"], plan)
        if updated is None:
            return f"Failed to update tenant for {email}"
        write_audit_event(
            actor_id=actor_id,
            action="plan.updated",
            entity_type="tenant",
            entity_id=updated["id"],
            summary=f"Plan changed for {email}: {previous_plan} → {plan} (via /admin slash)",
        )
        return f"✅ {email} is now on plan '{plan}' (was '{previous_plan}'). New balance: {updated['token_balance']:,} tokens."

    if sub in ("grant", "revoke"):
        if len(parts) < 3:
            return f"Usage: /admin {sub} <email>"
        email = parts[2]
        new_role = "platform_admin" if sub == "grant" else "member"
        user = get_tenant_user_by_email(email)
        if user is None:
            return f"No user with email {email}"
        previous_role = user["role"]
        # Self-demotion lockout guard
        if sub == "revoke" and user["id"] == actor_id and previous_role == "platform_admin":
            admins = list_platform_admins()
            if len(admins) <= 1:
                return "Cannot revoke — you are the last platform admin. Grant another user first."
        updated = update_user_role(user["id"], new_role)
        write_audit_event(
            actor_id=actor_id,
            action="admin.role_granted" if sub == "grant" else "admin.role_revoked",
            entity_type="user",
            entity_id=user["id"],
            summary=f"Role changed for {email}: {previous_role} → {new_role} (via /admin slash)",
        )
        verb = "granted" if sub == "grant" else "revoked"
        return f"✅ {verb}: {email} is now '{new_role}' (was '{previous_role}')."

    if sub == "audit":
        admin_events = list_audit_events(limit=15, action_prefix="admin.")
        plan_events = list_audit_events(limit=15, action_prefix="plan.")
        combined = sorted(admin_events + plan_events, key=lambda e: e.created_at, reverse=True)[:15]
        if not combined:
            return "No admin events yet."
        lines = ["Recent admin actions:"]
        for e in combined:
            ts = e.created_at.strftime("%Y-%m-%d %H:%M") if e.created_at else "?"
            lines.append(f"  [{ts}] {e.action:20} by {e.actor_id[:20]:20} — {e.summary}")
        return "\n".join(lines)

    return f"Unknown /admin subcommand: {sub}\n\n{ADMIN_HELP}"

# Map slash commands to chat commands
SLASH_TO_CHAT = {
    "/help": "help",
    "/briefing": "briefing",
    "/baseline": "baseline",
    "/brain": "brain health",
    "/fleet": "fleet health",
    "/nodes": "nodes",
    "/alerts": "show approvals",
    "/plugins": "plugins",
    "/learn": "learning stats",
    "/who": "who am i",
    "/context": "context files",
    "/logs": "logs",
    "/debug": "debug mode",
    "/schedules": "schedules",
    "/triggers": "triggers",
    "/alert": "alert settings",
    "/test-alert": "test alert",
    "/diagnose": "diagnose",
    "/heal": "heal now",
    "/voice": None,  # handled in UI
    "/clear": None,  # handled in UI
    "/new": None,  # handled in UI
}


def resolve_slash_command(text: str) -> str | None:
    """Convert a slash command to a chat command. Returns None if handled in UI."""
    parts = text.strip().split(None, 1)
    cmd = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""

    # Direct mapping
    if cmd in SLASH_TO_CHAT:
        mapped = SLASH_TO_CHAT[cmd]
        if mapped is None:
            return None  # UI-only command
        return mapped

    # Commands with arguments
    if cmd == "/search":
        return f"search: {args}" if args else "search: "
    if cmd == "/find":
        return f"find: {args}" if args else "find: "
    if cmd == "/read" or cmd == "/open":
        return f"open: {args}" if args else "open: "
    if cmd == "/memory":
        return f"memory: {args}" if args else "memory stats"
    if cmd == "/ssh":
        return f"ssh {args}" if args else "nodes"
    if cmd == "/status":
        return f"status {args}" if args else "status node-01"
    if cmd == "/all":
        return f"all: {args}" if args else "fleet health"
    if cmd == "/btw":
        # BTW is a side note — prefix with context marker
        return f"[context] {args}" if args else None

    return text  # Not a slash command, pass through


def get_slash_commands(role: str = "member") -> list[dict]:
    """Return slash commands visible to a given role.

    Platform-admin-only commands (category='admin-platform') are hidden from
    non-admins.
    """
    if role == "platform_admin":
        return SLASH_COMMANDS
    return [c for c in SLASH_COMMANDS if c.get("category") != "admin-platform"]


def filter_slash_commands(query: str, role: str = "member") -> list[dict]:
    """Filter slash commands by partial match for autocomplete, role-aware."""
    visible = get_slash_commands(role)
    q = query.lower().lstrip("/")
    if not q:
        return visible
    return [c for c in visible if q in c["command"].lower() or q in c["description"].lower()]
