# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Inventory Report — combines Pillar A (coverage) + Pillar B (witnessed)
+ audit-chain summary into a single tamper-evident PDF.

The PDF is the auditor deliverable. Each report carries:
- Vertirite wordmark + report metadata header
- Executive summary
- Coverage Map table (per host)
- Witnessed-but-unsanctioned table (per finding)
- Audit summary for the period (top actions, operators, lockdown events)
- Footer with the document fingerprint + chain pointer

Document fingerprint = SHA-256 hex of the canonical JSON body. Auditors
can verify by recomputing.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

logger = logging.getLogger("vertirite.reports.inventory")

# Vertirite palette — kept in sync with docs/BRAND.md.
SNOW = colors.HexColor("#FCFCFA")
IVORY = colors.HexColor("#F5F2E9")
GOLD = colors.HexColor("#C8A24A")
GOLD_DEEP = colors.HexColor("#8C6F2A")
INK = colors.HexColor("#0E0E10")
INK_DEEP = colors.HexColor("#000000")
INK_SOFT = colors.HexColor("#3A3A40")
INK_MUTE = colors.HexColor("#6B6B73")
APPROVED = colors.HexColor("#1F8A4C")
BLOCKED = colors.HexColor("#B82929")
PENDING = colors.HexColor("#C8A24A")
LINE = colors.HexColor("#E8E2D0")


def _canonical_json(payload: Dict[str, Any]) -> str:
    """Stable JSON encoding for hashing — sorted keys, no whitespace."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def fingerprint(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode()).hexdigest()


def _styles():
    s = getSampleStyleSheet()
    s["Normal"].fontName = "Helvetica"
    s["Normal"].fontSize = 9.5
    s["Normal"].leading = 13
    s["Normal"].textColor = INK
    s.add(
        ParagraphStyle(
            name="ReportTitle",
            fontName="Times-Bold",
            fontSize=22,
            leading=26,
            textColor=INK_DEEP,
            spaceAfter=2,
        )
    )
    s.add(
        ParagraphStyle(
            name="ReportSubtitle",
            fontName="Times-Roman",
            fontSize=12,
            leading=16,
            textColor=INK_SOFT,
            spaceAfter=18,
        )
    )
    s.add(
        ParagraphStyle(
            name="SectionTitle",
            fontName="Times-Bold",
            fontSize=14,
            leading=18,
            textColor=INK_DEEP,
            spaceBefore=18,
            spaceAfter=8,
        )
    )
    s.add(
        ParagraphStyle(
            name="Eyebrow",
            fontName="Courier-Bold",
            fontSize=7.5,
            leading=10,
            textColor=GOLD_DEEP,
            spaceAfter=4,
        )
    )
    s.add(
        ParagraphStyle(
            name="Mono",
            fontName="Courier",
            fontSize=8,
            leading=11,
            textColor=INK_SOFT,
        )
    )
    s.add(
        ParagraphStyle(
            name="MuteFoot",
            fontName="Helvetica",
            fontSize=7,
            leading=9,
            textColor=INK_MUTE,
        )
    )
    return s


def _make_header_footer(meta: Dict[str, Any]):
    """Closure returns the canvas callback for header/footer on each page."""
    fp = meta["fingerprint"]
    prev = meta.get("previous_fingerprint") or "(chain root)"
    period_start = meta["period_start"]
    period_end = meta["period_end"]
    generated_at = meta["generated_at"]

    def draw(canvas, doc):
        canvas.saveState()

        # Header — Vertirite wordmark
        canvas.setFont("Times-Bold", 14)
        canvas.setFillColor(INK_DEEP)
        x = doc.leftMargin
        y = LETTER[1] - 0.5 * inch
        canvas.drawString(x, y, "VERTI")
        v_width = canvas.stringWidth("VERTI", "Times-Bold", 14)
        canvas.setFillColor(GOLD)
        canvas.drawString(x + v_width, y, "RITE")

        # top-right
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(INK_MUTE)
        canvas.drawRightString(
            LETTER[0] - doc.rightMargin,
            y,
            "INVENTORY REPORT · OF-RECORD",
        )

        # gold rule under the header
        canvas.setStrokeColor(GOLD)
        canvas.setLineWidth(1.4)
        canvas.line(doc.leftMargin, y - 6, LETTER[0] - doc.rightMargin, y - 6)

        # Footer
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.4)
        footer_top = 0.65 * inch
        canvas.line(doc.leftMargin, footer_top, LETTER[0] - doc.rightMargin, footer_top)

        canvas.setFont("Courier", 7)
        canvas.setFillColor(INK_MUTE)
        canvas.drawString(doc.leftMargin, footer_top - 12, f"period {period_start} → {period_end}")
        canvas.drawString(doc.leftMargin, footer_top - 22, f"generated {generated_at}")

        canvas.drawCentredString(LETTER[0] / 2, footer_top - 12, f"page {doc.page}")

        canvas.drawRightString(LETTER[0] - doc.rightMargin, footer_top - 12, f"sha256: {fp[:16]}…")
        canvas.drawRightString(LETTER[0] - doc.rightMargin, footer_top - 22, f"prev:   {prev[:16]}{'…' if prev != '(chain root)' else ''}")

        canvas.restoreState()

    return draw


def _coverage_table(coverage: Dict[str, Any], styles) -> Tuple[Table, Table]:
    """Returns (summary_table, hosts_table) for the Coverage section."""
    summary_rows = [
        ["Coverage %", f"{coverage['coverage_pct']:.1f}%"],
        ["Hosts governed", str(coverage["governed"])],
        ["Declared, not governed", str(coverage["declared_not_governed"])],
        ["Archived", str(coverage["archived"])],
        ["Total in scope", str(coverage["governed"] + coverage["declared_not_governed"])],
    ]
    summary = Table(summary_rows, colWidths=[2.5 * inch, 1.5 * inch])
    summary.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (0, 0), (-1, -1), INK),
                ("TEXTCOLOR", (1, 0), (1, 0), GOLD_DEEP),
                ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("LINEBELOW", (0, 0), (-1, 0), 0.6, GOLD),
                ("LINEBELOW", (0, 1), (-1, -2), 0.3, LINE),
            ]
        )
    )

    rows = [["Hostname", "Role", "Lifecycle", "Last heartbeat"]]
    for h in coverage["hosts"]:
        rows.append(
            [
                h["hostname"],
                h["role"],
                h["lifecycle_status"],
                (h.get("agentd_last_heartbeat") or "—")[:19].replace("T", " "),
            ]
        )

    hosts = Table(rows, colWidths=[2.6 * inch, 1.4 * inch, 1.1 * inch, 1.6 * inch], repeatRows=1)
    style = [
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("BACKGROUND", (0, 0), (-1, 0), IVORY),
        ("TEXTCOLOR", (0, 0), (-1, 0), INK_DEEP),
        ("LINEBELOW", (0, 0), (-1, 0), 1.2, GOLD),
        ("LINEBELOW", (0, 1), (-1, -1), 0.3, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    # color lifecycle column per status
    for i, h in enumerate(coverage["hosts"], start=1):
        c = APPROVED if h["lifecycle_status"] == "governed" else (PENDING if h["lifecycle_status"] == "declared" else INK_MUTE)
        style.append(("TEXTCOLOR", (2, i), (2, i), c))
        style.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
    hosts.setStyle(TableStyle(style))
    return summary, hosts


def _witnessed_table(findings: List[Dict[str, Any]], styles) -> Table:
    rows = [["Pattern", "Target", "Signal", "Conf.", "Seen", "Status"]]
    for f in findings:
        rows.append(
            [
                f["pattern_name"][:32],
                f["target_hostname"][:30],
                f["signal_type"],
                f["confidence"],
                str(f["occurrence_count"]),
                f["status"],
            ]
        )
    t = Table(
        rows,
        colWidths=[1.8 * inch, 1.8 * inch, 0.7 * inch, 0.6 * inch, 0.5 * inch, 0.9 * inch],
        repeatRows=1,
    )
    style = [
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (-1, 0), IVORY),
        ("TEXTCOLOR", (0, 0), (-1, 0), INK_DEEP),
        ("LINEBELOW", (0, 0), (-1, 0), 1.2, GOLD),
        ("LINEBELOW", (0, 1), (-1, -1), 0.3, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ALIGN", (4, 1), (4, -1), "RIGHT"),
    ]
    # status colored
    status_color = {
        "new": BLOCKED,
        "acknowledged": GOLD_DEEP,
        "governed": APPROVED,
        "dismissed": INK_MUTE,
    }
    for i, f in enumerate(findings, start=1):
        c = status_color.get(f["status"], INK)
        style.append(("TEXTCOLOR", (5, i), (5, i), c))
        style.append(("FONTNAME", (5, i), (5, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style))
    return t


def _audit_summary_table(events: List[Dict[str, Any]], styles) -> Table:
    actions = Counter(e.get("action", "") for e in events)
    actors = Counter(e.get("actor_id", "") for e in events)
    rows = [["Top actions in period", "Count"]]
    for action, n in actions.most_common(8):
        rows.append([action or "(unspecified)", str(n)])
    rows.append(["", ""])
    rows.append(["Top operators in period", "Count"])
    for actor, n in actors.most_common(6):
        rows.append([actor or "(unspecified)", str(n)])
    t = Table(rows, colWidths=[4.0 * inch, 1.0 * inch], repeatRows=1)
    style = [
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, len(actions.most_common(8)) + 1), (-1, len(actions.most_common(8)) + 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (-1, 0), IVORY),
        ("BACKGROUND", (0, len(actions.most_common(8)) + 1), (-1, len(actions.most_common(8)) + 1), IVORY),
        ("TEXTCOLOR", (0, 0), (-1, 0), INK_DEEP),
        ("LINEBELOW", (0, 0), (-1, 0), 1, GOLD),
        ("LINEBELOW", (0, len(actions.most_common(8)) + 1), (-1, len(actions.most_common(8)) + 1), 1, GOLD),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
    ]
    t.setStyle(TableStyle(style))
    return t


def build_inventory_payload(
    coverage: Dict[str, Any],
    findings: List[Dict[str, Any]],
    audit_events: List[Dict[str, Any]],
    period_start: datetime,
    period_end: datetime,
    tenant_label: Optional[str],
    generated_by: str,
) -> Dict[str, Any]:
    """Canonical JSON body — what gets hashed for the chain fingerprint."""
    findings_by_status: Counter = Counter(f["status"] for f in findings)
    return {
        "report_type": "inventory",
        "vertirite_version": "1",
        "tenant_label": tenant_label,
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "generated_by": generated_by,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "coverage": {
            "total_declared": coverage["total_declared"],
            "governed": coverage["governed"],
            "declared_not_governed": coverage["declared_not_governed"],
            "archived": coverage["archived"],
            "coverage_pct": coverage["coverage_pct"],
        },
        "hosts": [
            {
                "hostname": h["hostname"],
                "role": h["role"],
                "lifecycle_status": h["lifecycle_status"],
                "tenant_id": h["tenant_id"],
                "agentd_last_heartbeat": h.get("agentd_last_heartbeat"),
                "declared_at": h.get("declared_at"),
                "governed_at": h.get("governed_at"),
                "archived_at": h.get("archived_at"),
            }
            for h in coverage["hosts"]
        ],
        "witnessed": {
            "total": len(findings),
            "by_status": dict(findings_by_status),
        },
        "findings": [
            {
                "id": f["id"],
                "tenant_id": f["tenant_id"],
                "target_hostname": f["target_hostname"],
                "pattern_id": f["pattern_id"],
                "pattern_name": f["pattern_name"],
                "signal_type": f["signal_type"],
                "confidence": f["confidence"],
                "occurrence_count": f["occurrence_count"],
                "status": f["status"],
                "first_seen_at": f.get("first_seen_at"),
                "last_seen_at": f.get("last_seen_at"),
                "acknowledged_by": f.get("acknowledged_by"),
                "governed_host_id": f.get("governed_host_id"),
                "dismiss_reason": f.get("dismiss_reason"),
            }
            for f in findings
        ],
        "audit_summary": {
            "event_count": len(audit_events),
            "top_actions": dict(Counter(e.get("action", "") for e in audit_events).most_common(20)),
            "operators": sorted({e.get("actor_id", "") for e in audit_events if e.get("actor_id")}),
        },
    }


def render_inventory_pdf(
    payload: Dict[str, Any],
    fingerprint_hex: str,
    previous_fingerprint: Optional[str],
) -> bytes:
    """Produce the PDF bytes for the given canonical payload."""
    styles = _styles()
    buf = io.BytesIO()

    meta = {
        "fingerprint": fingerprint_hex,
        "previous_fingerprint": previous_fingerprint,
        "period_start": payload["period_start"][:10],
        "period_end": payload["period_end"][:10],
        "generated_at": payload["generated_at"][:19].replace("T", " "),
    }

    doc = BaseDocTemplate(
        buf,
        pagesize=LETTER,
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
        topMargin=0.85 * inch,
        bottomMargin=0.85 * inch,
        title="Vertirite Inventory Report",
        author="Vertirite (SurgeXi Business Intelligence)",
        subject=f"Inventory of governed and witnessed AI activity, {meta['period_start']}–{meta['period_end']}",
    )

    frame = Frame(
        doc.leftMargin,
        doc.bottomMargin,
        doc.width,
        doc.height,
        leftPadding=0,
        rightPadding=0,
        topPadding=0,
        bottomPadding=0,
    )
    doc.addPageTemplates(
        [PageTemplate(id="main", frames=frame, onPage=_make_header_footer(meta))]
    )

    flowables = []

    # ─── Cover ──────────────────────────────────────────────────────────
    flowables.append(Paragraph("OF-RECORD INVENTORY REPORT", styles["Eyebrow"]))
    title = "Vertirite — AI Governance Inventory"
    flowables.append(Paragraph(title, styles["ReportTitle"]))
    flowables.append(
        Paragraph(
            f"Tenant scope: <b>{payload['tenant_label'] or 'cross-tenant (all)'}</b> &nbsp;·&nbsp; "
            f"Period: {meta['period_start']} → {meta['period_end']}",
            styles["ReportSubtitle"],
        )
    )

    # Executive summary
    flowables.append(Paragraph("Executive summary", styles["SectionTitle"]))
    coverage = payload["coverage"]
    summary_text = (
        f"During this period, the tenant scope declared <b>{coverage['governed'] + coverage['declared_not_governed']}</b> "
        f"hosts as in-scope for AI governance. Of those, <b>{coverage['governed']}</b> are under continuous Vertirite "
        f"governance (signed audit trail attached) — a coverage of <b>{coverage['coverage_pct']:.1f}%</b>. "
        f"<b>{coverage['declared_not_governed']}</b> hosts are declared but pending the fleet agent install. "
        f"Vertirite&rsquo;s discovery probe additionally witnessed AI activity on hosts not previously declared: "
        f"<b>{payload['witnessed']['total']}</b> findings total, of which "
        f"<b>{payload['witnessed']['by_status'].get('new', 0)}</b> are pending operator review, "
        f"<b>{payload['witnessed']['by_status'].get('acknowledged', 0)}</b> acknowledged, "
        f"<b>{payload['witnessed']['by_status'].get('governed', 0)}</b> brought under governance, and "
        f"<b>{payload['witnessed']['by_status'].get('dismissed', 0)}</b> dismissed as out-of-scope or false-positive."
    )
    flowables.append(Paragraph(summary_text, styles["Normal"]))
    flowables.append(Spacer(1, 12))

    # Coverage Map
    flowables.append(Paragraph("Coverage Map", styles["SectionTitle"]))
    summary_t, hosts_t = _coverage_table(
        {
            **coverage,
            "hosts": payload["hosts"],
        },
        styles,
    )
    flowables.append(summary_t)
    flowables.append(Spacer(1, 10))
    flowables.append(hosts_t)

    flowables.append(PageBreak())

    # Witnessed
    flowables.append(Paragraph("Witnessed but unsanctioned", styles["SectionTitle"]))
    if payload["findings"]:
        flowables.append(
            Paragraph(
                "AI-shaped activity Vertirite&rsquo;s discovery probe observed on governed hosts that does NOT "
                "route through the broker. Each row is a candidate for governance; the table reflects the current "
                "lifecycle state.",
                styles["Normal"],
            )
        )
        flowables.append(Spacer(1, 6))
        flowables.append(_witnessed_table(payload["findings"], styles))
    else:
        flowables.append(
            Paragraph(
                "No witnessed findings during this period. Either the discovery probe has not yet executed, "
                "or no ungoverned AI activity was observed.",
                styles["Normal"],
            )
        )

    flowables.append(Spacer(1, 18))

    # Audit summary
    flowables.append(Paragraph("Audit-chain summary", styles["SectionTitle"]))
    flowables.append(
        Paragraph(
            f"During the period, the broker recorded <b>{payload['audit_summary']['event_count']}</b> audited "
            f"events. The top actions and operators by volume are listed below; the full event chain is "
            f"available via <i>GET /v1/admin/audit</i> and is cryptographically attributable to the originating "
            f"operator.",
            styles["Normal"],
        )
    )
    flowables.append(Spacer(1, 6))
    flowables.append(_audit_summary_table(audit_events_for_summary(payload), styles))

    # Verification footer
    flowables.append(PageBreak())
    flowables.append(Paragraph("Verification", styles["SectionTitle"]))
    flowables.append(
        Paragraph(
            "This document is part of a tamper-evident chain. To verify integrity, recompute the SHA-256 of the "
            "canonical JSON body (available via <i>GET /v1/admin/reports/inventory.json</i> for this same period) "
            "and compare against the fingerprint printed in the footer of every page.",
            styles["Normal"],
        )
    )
    flowables.append(Spacer(1, 8))
    flowables.append(
        Paragraph(
            f"<b>This report&rsquo;s fingerprint:</b><br/><font face='Courier' size='8'>{fingerprint_hex}</font>",
            styles["Normal"],
        )
    )
    flowables.append(Spacer(1, 6))
    prev_label = previous_fingerprint or "(chain root — first inventory report for this scope)"
    flowables.append(
        Paragraph(
            f"<b>Previous report&rsquo;s fingerprint:</b><br/><font face='Courier' size='8'>{prev_label}</font>",
            styles["Normal"],
        )
    )
    flowables.append(Spacer(1, 18))
    flowables.append(
        Paragraph(
            "Vertirite is operated by SurgeXi Business Intelligence, United States. "
            "Issued under the Vertirite governance attestation policy. No payload or PII is included in this "
            "document; the report is metadata-only.",
            styles["MuteFoot"],
        )
    )

    doc.build(flowables)
    return buf.getvalue()


def audit_events_for_summary(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Reconstruct a minimal event list from the canonical payload for the
    table renderer. Keeps the renderer pure (just needs an iterable of
    actor/action dicts); the payload stores the same Counter shape."""
    events: List[Dict[str, Any]] = []
    top = payload["audit_summary"]["top_actions"]
    for action, count in top.items():
        for _ in range(count):
            events.append({"action": action, "actor_id": ""})
    # Make the actor list visible too
    for op in payload["audit_summary"]["operators"]:
        events.append({"action": "", "actor_id": op})
    return events
