# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Scheduled inventory report delivery (Gap #7).

Generates the monthly Inventory Report PDF for each active tenant (or
cross-tenant if no tenant filter is configured) and emails it to the
compliance contact. Designed to run from a systemd timer or cron once
per month; can also be triggered ad-hoc from the operator dashboard.

Configuration via env vars (all required for SMTP delivery to actually
fire — without them the runner writes the PDF to disk and logs the
intent, useful for dev):

  VERTIRITE_REPORT_SMTP_HOST        e.g. smtp.sendgrid.net
  VERTIRITE_REPORT_SMTP_PORT        e.g. 587
  VERTIRITE_REPORT_SMTP_USER
  VERTIRITE_REPORT_SMTP_PASSWORD
  VERTIRITE_REPORT_SMTP_FROM        e.g. compliance@example.com
  VERTIRITE_REPORT_SMTP_USE_TLS     "1" for STARTTLS (default 1)
  VERTIRITE_REPORT_OUTPUT_DIR       fallback / archive dir; default /tmp/vertirite-reports

Per-tenant compliance contact lookup:
  tenants table doesn't yet have a compliance_contact column. v1 reads
  from env: VERTIRITE_REPORT_RECIPIENT_<tenant_slug_upper> = email.
  Tenants without a configured contact get skipped with a logged warning.
  A follow-up PR can add tenants.compliance_email; this scheduler will
  prefer the DB value when present.
"""
from __future__ import annotations

import logging
import os
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vertirite.reports.scheduler")


def _smtp_config() -> Optional[Dict[str, Any]]:
    host = os.environ.get("VERTIRITE_REPORT_SMTP_HOST")
    sender = os.environ.get("VERTIRITE_REPORT_SMTP_FROM")
    if not host or not sender:
        return None
    return {
        "host": host,
        "port": int(os.environ.get("VERTIRITE_REPORT_SMTP_PORT", "587")),
        "user": os.environ.get("VERTIRITE_REPORT_SMTP_USER"),
        "password": os.environ.get("VERTIRITE_REPORT_SMTP_PASSWORD"),
        "sender": sender,
        "use_tls": os.environ.get("VERTIRITE_REPORT_SMTP_USE_TLS", "1") == "1",
    }


def _recipient_for(tenant: Dict[str, Any]) -> Optional[str]:
    """Look up the compliance email for a tenant.

    v1: env var VERTIRITE_REPORT_RECIPIENT_<TENANT_SLUG_UPPER>.
    Future: prefer tenants.compliance_email column when available.
    """
    slug = (tenant.get("slug") or "").upper().replace("-", "_")
    if not slug:
        return None
    return os.environ.get(f"VERTIRITE_REPORT_RECIPIENT_{slug}")


def _output_dir() -> Path:
    p = Path(os.environ.get("VERTIRITE_REPORT_OUTPUT_DIR", "/tmp/vertirite-reports"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def _send_pdf_email(
    smtp: Dict[str, Any],
    recipient: str,
    subject: str,
    body: str,
    pdf_filename: str,
    pdf_bytes: bytes,
) -> None:
    msg = EmailMessage()
    msg["From"] = smtp["sender"]
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)
    msg.add_attachment(
        pdf_bytes,
        maintype="application",
        subtype="pdf",
        filename=pdf_filename,
    )

    with smtplib.SMTP(smtp["host"], smtp["port"], timeout=30) as s:
        if smtp["use_tls"]:
            s.starttls()
        if smtp["user"] and smtp["password"]:
            s.login(smtp["user"], smtp["password"])
        s.send_message(msg)


def run_monthly_inventory_reports(
    actor_id: str = "scheduler",
    period_days: int = 30,
    write_to_disk: bool = True,
) -> List[Dict[str, Any]]:
    """Generate + deliver an inventory report for every active tenant.

    Returns a list of result records (one per tenant) with status:
        sent       — SMTP delivery succeeded
        no_contact — no recipient configured for this tenant
        no_smtp    — SMTP not configured (PDF written to disk only)
        error      — exception during render/send (logged)

    Designed to be invoked from systemd timer or cron. Safe to run
    multiple times in a month — the report chain just grows another
    link per run.
    """
    from datetime import datetime, timedelta, timezone
    from ..tenant import TenantTable
    from ..db import session_scope
    from sqlalchemy import select
    from ..fleet_manifest import coverage_summary
    from ..discovery.findings import list_findings
    from ..repository import list_audit_events
    from .inventory import build_inventory_payload, fingerprint, render_inventory_pdf
    from .runs import get_previous_fingerprint, record_report_run

    smtp = _smtp_config()
    out_dir = _output_dir()
    results: List[Dict[str, Any]] = []

    # Coerce naive datetimes from SQLite to UTC for safe comparison.
    def _aware(dt):
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    period_end = datetime.now(timezone.utc)
    period_start = period_end - timedelta(days=period_days)

    with session_scope() as db:
        tenants = db.execute(
            select(TenantTable).where(TenantTable.status == "active")
        ).scalars().all()
        active_tenants = [
            {
                "id": t.id,
                "name": t.name,
                "slug": t.slug,
                "plan": t.plan,
                "status": t.status,
            }
            for t in tenants
        ]

    for tenant in active_tenants:
        tid = tenant["id"]
        try:
            cov = coverage_summary(tenant_id=tid)
            findings = list_findings(tenant_id=tid, limit=10000)
            raw_events = list_audit_events(limit=10000, tenant_id=tid)
            audit_events = [
                {
                    "id": e.id,
                    "actor_id": e.actor_id,
                    "action": e.action,
                    "entity_type": e.entity_type,
                    "entity_id": e.entity_id,
                    "summary": e.summary,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                }
                for e in raw_events
                if e.created_at and period_start <= _aware(e.created_at) <= period_end
            ]

            payload = build_inventory_payload(
                coverage=cov,
                findings=findings,
                audit_events=audit_events,
                period_start=period_start,
                period_end=period_end,
                tenant_label=f"{tenant['name']} ({tenant['slug']})",
                generated_by=actor_id,
            )
            fp = fingerprint(payload)
            prev_fp = get_previous_fingerprint(report_type="inventory", tenant_id=tid)
            pdf_bytes = render_inventory_pdf(
                payload=payload,
                fingerprint_hex=fp,
                previous_fingerprint=prev_fp,
            )

            # Record the run in the chain
            record_report_run(
                report_type="inventory",
                tenant_id=tid,
                period_start=period_start,
                period_end=period_end,
                fingerprint=fp,
                previous_fingerprint=prev_fp,
                generated_by=actor_id,
                summary=(
                    f"Scheduled monthly inventory: {tenant['name']} — "
                    f"governed={cov['governed']}/{cov['governed']+cov['declared_not_governed']} "
                    f"({cov['coverage_pct']:.1f}%), witnessed={len(findings)}, "
                    f"audit_events={len(audit_events)}"
                ),
            )

            filename = (
                f"vertirite-inventory-{tenant['slug']}-"
                f"{period_end.strftime('%Y%m%d')}-{fp[:8]}.pdf"
            )

            if write_to_disk:
                disk_path = out_dir / filename
                disk_path.write_bytes(pdf_bytes)
                logger.info("Inventory PDF written to %s", disk_path)

            recipient = _recipient_for(tenant)
            if recipient is None:
                results.append({"tenant_id": tid, "status": "no_contact", "filename": filename})
                logger.warning(
                    "No compliance recipient configured for tenant %s (slug=%s) — "
                    "set VERTIRITE_REPORT_RECIPIENT_%s to enable monthly delivery",
                    tenant["name"], tenant["slug"], tenant["slug"].upper().replace("-", "_"),
                )
                continue

            if smtp is None:
                results.append({"tenant_id": tid, "status": "no_smtp", "filename": filename})
                logger.warning(
                    "SMTP not configured (VERTIRITE_REPORT_SMTP_* env vars) — "
                    "PDF for %s written to disk only", tenant["name"],
                )
                continue

            subject = (
                f"Vertirite inventory report — {tenant['name']} — "
                f"{period_start.strftime('%Y-%m-%d')} to {period_end.strftime('%Y-%m-%d')}"
            )
            body = (
                f"Attached is the {period_days}-day Vertirite governance inventory report\n"
                f"for {tenant['name']} ({tenant['slug']}).\n\n"
                f"Document fingerprint: {fp}\n"
                f"Previous fingerprint: {prev_fp or '(chain root — first scheduled report)'}\n\n"
                f"Coverage: {cov['coverage_pct']:.1f}% "
                f"({cov['governed']}/{cov['governed']+cov['declared_not_governed']} in-scope hosts governed)\n"
                f"Witnessed findings: {len(findings)} total\n"
                f"Audit events in period: {len(audit_events)}\n\n"
                f"Verification: the canonical JSON body that produced this fingerprint\n"
                f"is available at GET /v1/admin/reports/inventory.json?period_days={period_days}\n"
                f"&tenant_id={tid}\n\n"
                f"— Vertirite (SurgeXi Business Intelligence)\n"
            )
            _send_pdf_email(smtp, recipient, subject, body, filename, pdf_bytes)
            results.append({"tenant_id": tid, "status": "sent", "recipient": recipient, "filename": filename})
            logger.info(
                "Sent monthly inventory report to %s for tenant %s (fp=%s)",
                recipient, tenant["name"], fp[:16],
            )

        except Exception as exc:  # noqa: BLE001
            logger.exception("monthly_inventory failed for tenant %s", tid)
            results.append({"tenant_id": tid, "status": "error", "error": str(exc)})

    return results


# ---------------------------------------------------------------------------
# CLI entry point — for cron / systemd timer
# ---------------------------------------------------------------------------
def main():
    """Invoke from cron / systemd timer: python -m broker.reports.scheduler."""
    import json
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    results = run_monthly_inventory_reports()
    print(json.dumps({"runs": results, "count": len(results)}, indent=2))
    # Exit non-zero if any tenant errored, so cron-mailer flags it
    if any(r["status"] == "error" for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
