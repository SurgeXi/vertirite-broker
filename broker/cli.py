# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Broker operator CLI — run on the host to bootstrap and manage platform admins.

Usage:
    python -m broker.cli seed-admin <email> <password> [--tenant NAME] [--display-name NAME]
    python -m broker.cli grant-admin <email>
    python -m broker.cli revoke-admin <email>
    python -m broker.cli list-admins
    python -m broker.cli list-users
    python -m broker.cli upgrade-plan <email> <plan>

Must run on a host with DB access (reads SURGE_OPERATOR_DATABASE_URL from the
environment the broker uses). Intended for initial bootstrap — once a platform
admin exists, day-to-day role changes should happen through the admin UI or
the /admin slash commands so they carry a real actor id in the audit trail.

`seed-admin` is the canonical first-install command: it creates the tenant
(if needed), creates the user, and grants platform_admin in one shot.
Idempotent — if the email already exists, it just grants platform_admin
without recreating the row.
"""
from __future__ import annotations

import argparse
import sys
from typing import Optional

from .db import init_db
from .repository import write_audit_event
from .tenant import (
    PLAN_TOKEN_ALLOCATION,
    get_tenant,
    get_tenant_user_by_email,
    list_all_users,
    list_platform_admins,
    update_tenant_plan,
    update_user_role,
)


CLI_ACTOR_ID = "cli"


def cmd_seed_admin(
    email: str,
    password: str,
    tenant_name: Optional[str] = None,
    display_name: Optional[str] = None,
    must_change: bool = False,
) -> int:
    """Create or elevate the first platform_admin. Idempotent.

    If no user with this email exists, registers one (creating a tenant
    too if tenant_name is provided). If the user exists, just grants
    platform_admin role on their existing tenant. Either way, the final
    state is: this email has platform_admin role.

    Reads from env if args not given:
        VERTIRITE_SEED_ADMIN_EMAIL
        VERTIRITE_SEED_ADMIN_PASSWORD
        VERTIRITE_SEED_ADMIN_TENANT
        VERTIRITE_SEED_ADMIN_DISPLAY_NAME
    """
    import asyncio
    from .saas_auth import register

    existing = get_tenant_user_by_email(email)
    if existing is not None:
        if existing["role"] == "platform_admin":
            print(f"ok: {email} already exists as platform_admin (no-op)")
            return 0
        previous = existing["role"]
        updated = update_user_role(existing["id"], "platform_admin")
        if updated is None:
            print(f"error: failed to update user {email}", file=sys.stderr)
            return 2
        write_audit_event(
            actor_id=CLI_ACTOR_ID,
            action="admin.role_granted",
            entity_type="user",
            entity_id=existing["id"],
            summary=f"Role changed for {email}: {previous} → platform_admin (via seed-admin)",
        )
        print(f"elevated: existing user {email} is now platform_admin (was {previous})")
        return 0

    # User does not exist — create the tenant + user via the standard
    # register() flow, then elevate the role.
    if not tenant_name:
        tenant_name = f"{email.split('@')[0].title()} Tenant"
    if not display_name:
        display_name = email.split("@")[0].replace(".", " ").title()

    try:
        result = asyncio.run(
            register(
                email=email,
                password=password,
                display_name=display_name,
                tenant_name=tenant_name,
            )
        )
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    user_id = result["user"]["id"]
    tenant_id = result["tenant"]["id"]
    api_key = result.get("api_key")

    # Elevate to platform_admin
    update_user_role(user_id, "platform_admin")
    if must_change:
        from .tenant import set_must_change_password
        set_must_change_password(user_id, True)
        print("        must_change_password: set (forced change at first login)")
    write_audit_event(
        actor_id=CLI_ACTOR_ID,
        action="admin.bootstrap",
        entity_type="user",
        entity_id=user_id,
        summary=f"Seeded platform_admin {email} on tenant {tenant_name} (via seed-admin)",
    )
    print(f"seeded: created user {email} on tenant '{tenant_name}' ({tenant_id})")
    print(f"        role: platform_admin")
    if api_key:
        print(f"        api_key: {api_key}")
        print(f"        (save this — it will not be shown again)")
    return 0


def cmd_grant_admin(email: str) -> int:
    user = get_tenant_user_by_email(email)
    if user is None:
        print(f"error: no user with email {email}", file=sys.stderr)
        return 2
    if user["role"] == "platform_admin":
        print(f"ok: {email} is already a platform admin")
        return 0
    previous = user["role"]
    updated = update_user_role(user["id"], "platform_admin")
    if updated is None:
        print(f"error: failed to update user {email}", file=sys.stderr)
        return 2
    write_audit_event(
        actor_id=CLI_ACTOR_ID,
        action="admin.role_granted",
        entity_type="user",
        entity_id=user["id"],
        summary=f"Role changed for {email}: {previous} → platform_admin (via CLI bootstrap)",
    )
    print(f"granted: {email} is now platform_admin (was {previous})")
    return 0


def cmd_revoke_admin(email: str) -> int:
    user = get_tenant_user_by_email(email)
    if user is None:
        print(f"error: no user with email {email}", file=sys.stderr)
        return 2
    if user["role"] != "platform_admin":
        print(f"ok: {email} is not a platform admin (role={user['role']})")
        return 0
    admins = list_platform_admins()
    if len(admins) <= 1:
        print(
            "error: cannot revoke — this is the last platform admin. "
            "Grant another user first.",
            file=sys.stderr,
        )
        return 3
    updated = update_user_role(user["id"], "member")
    if updated is None:
        print(f"error: failed to update user {email}", file=sys.stderr)
        return 2
    write_audit_event(
        actor_id=CLI_ACTOR_ID,
        action="admin.role_revoked",
        entity_type="user",
        entity_id=user["id"],
        summary=f"Role changed for {email}: platform_admin → member (via CLI)",
    )
    print(f"revoked: {email} is now member")
    return 0


def cmd_list_admins() -> int:
    admins = list_platform_admins()
    if not admins:
        print("no platform admins")
        return 0
    print(f"{'EMAIL':40} {'DISPLAY NAME':30} {'TENANT ID':40}")
    for a in admins:
        print(f"{a['email']:40} {a['display_name']:30} {a['tenant_id']:40}")
    return 0


def cmd_list_users() -> int:
    users = list_all_users()
    if not users:
        print("no users")
        return 0
    print(f"{'EMAIL':40} {'ROLE':16} {'STATUS':10} {'TENANT ID':40}")
    for u in users:
        print(f"{u['email']:40} {u['role']:16} {u['status']:10} {u['tenant_id']:40}")
    return 0


def cmd_upgrade_plan(email: str, plan: str) -> int:
    if plan not in PLAN_TOKEN_ALLOCATION:
        print(
            f"error: invalid plan '{plan}'. Valid: {list(PLAN_TOKEN_ALLOCATION.keys())}",
            file=sys.stderr,
        )
        return 2
    user = get_tenant_user_by_email(email)
    if user is None:
        print(f"error: no user with email {email}", file=sys.stderr)
        return 2
    tenant_before = get_tenant(user["tenant_id"])
    previous_plan = tenant_before["plan"] if tenant_before else "unknown"
    updated = update_tenant_plan(user["tenant_id"], plan)
    if updated is None:
        print(f"error: tenant not found for {email}", file=sys.stderr)
        return 2
    write_audit_event(
        actor_id=CLI_ACTOR_ID,
        action="plan.updated",
        entity_type="tenant",
        entity_id=updated["id"],
        summary=f"Plan changed for {email}: {previous_plan} → {plan} (via CLI)",
    )
    print(f"upgraded: {email}'s tenant is now on plan={plan} (was {previous_plan})")
    return 0


def main(argv: Optional[list] = None) -> int:
    import os

    parser = argparse.ArgumentParser(prog="broker.cli", description="Vertirite broker operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_seed = sub.add_parser(
        "seed-admin",
        help="Create or elevate the first platform_admin (canonical first-install command).",
    )
    p_seed.add_argument("email", nargs="?", default=os.environ.get("VERTIRITE_SEED_ADMIN_EMAIL"))
    p_seed.add_argument(
        "password",
        nargs="?",
        default=os.environ.get("VERTIRITE_SEED_ADMIN_PASSWORD"),
    )
    p_seed.add_argument(
        "--tenant",
        default=os.environ.get("VERTIRITE_SEED_ADMIN_TENANT"),
        help="Tenant name to create (defaults to email local-part + ' Tenant')",
    )
    p_seed.add_argument(
        "--display-name",
        default=os.environ.get("VERTIRITE_SEED_ADMIN_DISPLAY_NAME"),
        help="Operator display name (defaults to email local-part)",
    )
    p_seed.add_argument(
        "--must-change",
        action="store_true",
        help="Require the user to change this (temporary) password at first login",
    )

    p_grant = sub.add_parser("grant-admin", help="Promote a user to platform_admin")
    p_grant.add_argument("email")

    p_revoke = sub.add_parser("revoke-admin", help="Demote a platform_admin to member")
    p_revoke.add_argument("email")

    sub.add_parser("list-admins", help="List all platform admins")
    sub.add_parser("list-users", help="List all users across all tenants")

    p_plan = sub.add_parser("upgrade-plan", help="Change a user's tenant plan")
    p_plan.add_argument("email")
    p_plan.add_argument("plan", choices=list(PLAN_TOKEN_ALLOCATION.keys()))

    args = parser.parse_args(argv)

    init_db()

    if args.command == "seed-admin":
        if not args.email or not args.password:
            print(
                "error: seed-admin requires both email and password (positional args or env vars "
                "VERTIRITE_SEED_ADMIN_EMAIL + VERTIRITE_SEED_ADMIN_PASSWORD)",
                file=sys.stderr,
            )
            return 2
        return cmd_seed_admin(
            email=args.email,
            password=args.password,
            tenant_name=args.tenant,
            display_name=args.display_name,
            must_change=args.must_change,
        )
    if args.command == "grant-admin":
        return cmd_grant_admin(args.email)
    if args.command == "revoke-admin":
        return cmd_revoke_admin(args.email)
    if args.command == "list-admins":
        return cmd_list_admins()
    if args.command == "list-users":
        return cmd_list_users()
    if args.command == "upgrade-plan":
        return cmd_upgrade_plan(args.email, args.plan)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
