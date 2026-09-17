# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Exposure Report — the FREE-TIER deliverable (§8.1).

The free tier SEES: this is the artifact it produces. It tells the exposure story
from discovery/coverage data alone — governed vs. ungoverned %, and the ungoverned
gap ranked highest-signal-first — with no audit-chain or governance-action content
(that belongs to the pilot). It's designed to be forwarded to a CISO, board or
auditor: it makes the case for governing without us in the room.

Reuses the inventory report's rendering infrastructure (palette, styles, header/
footer, canonical-JSON fingerprint) so the two deliverables stay visually identical
and both tamper-evident. Metadata-only; no payload or PII.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reportlab.lib.pagesizes import LETTER
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from .inventory import (
    APPROVED,
    BLOCKED,
    GOLD,
    GOLD_DEEP,
    INK,
    INK_DEEP,
    INK_MUTE,
    IVORY,
    LINE,
    PENDING,
    _canonical_json,  # noqa: F401 — re-exported for symmetry with inventory
    _styles,
    fingerprint,
)

_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}


def _classify(f: Dict[str, Any]) -> str:
    """One primary label per finding, mirroring coverage_map's ranking tiers."""
    if f.get("suspicious"):
        return "threat"
    if f.get("is_ai_service"):
        return "AI service"
    if f.get("unclassified"):
        return "unknown"
    return "other"


def build_exposure_payload(
    coverage: Dict[str, Any],
    tenant_label: Optional[str],
    generated_by: str,
    top_n: int = 40,
) -> Dict[str, Any]:
    """Canonical JSON body for the exposure report (what gets fingerprinted).

    ``coverage`` is the dict returned by discovery.coverage.coverage_map().
    """
    counts = coverage.get("counts", {})
    ungoverned = coverage.get("ungoverned", []) or []
    ranked = [
        {
            "target_hostname": f.get("target_hostname", "—"),
            "pattern_name": f.get("pattern_name", "—"),
            "signal_type": f.get("signal_type", "—"),
            "plane": f.get("plane", "north-south"),
            "classification": _classify(f),
            "confidence": f.get("confidence", "medium"),
            "occurrence_count": int(f.get("occurrence_count", 1) or 1),
            "remediation": f.get("remediation", ""),
        }
        for f in ungoverned[:top_n]
    ]
    return {
        "report_type": "exposure",
        "vertirite_version": "1",
        "tenant_label": tenant_label,
        "generated_by": generated_by,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "coverage_pct": coverage.get("coverage_pct", 0.0),
        "counts": counts,
        "ranked_exposure": ranked,
        "truncated": len(ungoverned) > top_n,
        "ungoverned_total": len(ungoverned),
    }


def _exposure_header_footer(meta: Dict[str, Any]):
    fp = meta["fingerprint"]
    generated_at = meta["generated_at"]

    def draw(canvas, doc):
        canvas.saveState()
        canvas.setFont("Times-Bold", 14)
        canvas.setFillColor(INK_DEEP)
        x = doc.leftMargin
        y = LETTER[1] - 0.5 * inch
        canvas.drawString(x, y, "VERTI")
        v_width = canvas.stringWidth("VERTI", "Times-Bold", 14)
        canvas.setFillColor(GOLD)
        canvas.drawString(x + v_width, y, "RITE")

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(INK_MUTE)
        canvas.drawRightString(LETTER[0] - doc.rightMargin, y, "EXPOSURE REPORT · WHAT WE SEE")

        canvas.setStrokeColor(GOLD)
        canvas.setLineWidth(1.4)
        canvas.line(doc.leftMargin, y - 6, LETTER[0] - doc.rightMargin, y - 6)

        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.4)
        footer_top = 0.65 * inch
        canvas.line(doc.leftMargin, footer_top, LETTER[0] - doc.rightMargin, footer_top)
        canvas.setFont("Courier", 7)
        canvas.setFillColor(INK_MUTE)
        canvas.drawString(doc.leftMargin, footer_top - 12, f"generated {generated_at}")
        canvas.drawCentredString(LETTER[0] / 2, footer_top - 12, f"page {doc.page}")
        canvas.drawRightString(LETTER[0] - doc.rightMargin, footer_top - 12, f"sha256: {fp[:16]}…")
        canvas.restoreState()

    return draw


def _exposure_table(rows: List[Dict[str, Any]], styles) -> Table:
    header = ["Target", "Pattern", "Plane", "Class", "Conf.", "Seen"]
    data = [header]
    for r in rows:
        data.append([
            (r["target_hostname"] or "—")[:30],
            (r["pattern_name"] or "—")[:26],
            r["plane"],
            r["classification"],
            r["confidence"],
            str(r["occurrence_count"]),
        ])
    t = Table(
        data,
        colWidths=[1.7 * inch, 1.6 * inch, 0.95 * inch, 0.9 * inch, 0.6 * inch, 0.5 * inch],
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
        ("ALIGN", (5, 1), (5, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    class_color = {"threat": BLOCKED, "AI service": GOLD_DEEP, "unknown": PENDING, "other": INK_MUTE}
    for i, r in enumerate(rows, start=1):
        c = class_color.get(r["classification"], INK)
        style.append(("TEXTCOLOR", (3, i), (3, i), c))
        style.append(("FONTNAME", (3, i), (3, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style))
    return t


def render_exposure_pdf(payload: Dict[str, Any], fingerprint_hex: str) -> bytes:
    styles = _styles()
    buf = io.BytesIO()
    meta = {
        "fingerprint": fingerprint_hex,
        "generated_at": payload["generated_at"][:19].replace("T", " "),
    }
    doc = BaseDocTemplate(
        buf,
        pagesize=LETTER,
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
        topMargin=0.85 * inch,
        bottomMargin=0.85 * inch,
        title="Vertirite Exposure Report",
        author="Vertirite (SurgeXi Business Intelligence)",
        subject="What Vertirite sees: governed vs. ungoverned AI exposure, ranked.",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height,
                  leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([PageTemplate(id="main", frames=frame, onPage=_exposure_header_footer(meta))])

    counts = payload["counts"]
    cov = payload["coverage_pct"]
    ungoverned = counts.get("ungoverned", 0)
    witnessed = counts.get("witnessed", 0)

    flow: List[Any] = []
    flow.append(Paragraph("AI EXPOSURE REPORT — WHAT VERTIRITE SEES", styles["Eyebrow"]))
    flow.append(Paragraph("Vertirite — AI Exposure Report", styles["ReportTitle"]))
    flow.append(Paragraph(
        f"Scope: <b>{payload['tenant_label'] or 'this environment'}</b> &nbsp;·&nbsp; "
        f"Generated {meta['generated_at']}",
        styles["ReportSubtitle"],
    ))

    flow.append(Paragraph("Executive summary", styles["SectionTitle"]))
    flow.append(Paragraph(
        f"Vertirite witnessed <b>{witnessed}</b> AI / automation actors reaching systems in this scope. "
        f"<b>{counts.get('governed', 0)}</b> are under governance and <b>{ungoverned}</b> are <b>not</b> — "
        f"a governed coverage of <b>{cov:.1f}%</b>. Of the ungoverned exposure, "
        f"<b>{counts.get('ungoverned_ai_services', 0)}</b> are identifiable AI services, "
        f"<b>{counts.get('ungoverned_suspicious', 0)}</b> look like threats, and "
        f"<b>{counts.get('ungoverned_unknown', 0)}</b> are unclassified. By network path: "
        f"<b>{counts.get('north_south', 0)}</b> reach outbound (egress), "
        f"<b>{counts.get('east_west', 0)}</b> move laterally, and "
        f"<b>{counts.get('host_local', 0)}</b> are host-local.",
        styles["Normal"],
    ))
    flow.append(Spacer(1, 12))

    # Headline coverage figure
    figure = Table(
        [[f"{cov:.1f}%", f"{ungoverned}"],
         ["under governance", "ungoverned exposures"]],
        colWidths=[2.6 * inch, 2.6 * inch],
    )
    figure.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Times-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 30),
        ("TEXTCOLOR", (0, 0), (0, 0), APPROVED),
        ("TEXTCOLOR", (1, 0), (1, 0), BLOCKED),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, 1), 9),
        ("TEXTCOLOR", (0, 1), (-1, 1), INK_MUTE),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 0),
    ]))
    flow.append(figure)
    flow.append(Spacer(1, 16))

    flow.append(Paragraph("Ungoverned exposure — ranked", styles["SectionTitle"]))
    if payload["ranked_exposure"]:
        flow.append(Paragraph(
            "Highest-signal first: threats, then identifiable AI services, then unclassified activity. "
            "Each row is something reaching your systems that no human gate currently sits in front of.",
            styles["Normal"],
        ))
        flow.append(Spacer(1, 6))
        flow.append(_exposure_table(payload["ranked_exposure"], styles))
        if payload.get("truncated"):
            flow.append(Spacer(1, 6))
            flow.append(Paragraph(
                f"Showing the top {len(payload['ranked_exposure'])} of {payload['ungoverned_total']} "
                f"ungoverned exposures. The full worklist is available in the console.",
                styles["MuteFoot"],
            ))
    else:
        flow.append(Paragraph(
            "No ungoverned exposure witnessed in this scope. Either discovery has not yet run, or everything "
            "Vertirite sees is already under governance.",
            styles["Normal"],
        ))

    flow.append(PageBreak())
    flow.append(Paragraph("What this report is — and what comes next", styles["SectionTitle"]))
    flow.append(Paragraph(
        "This is what Vertirite <b>sees</b>. Producing it changed nothing on your systems — discovery is "
        "read-only. <b>Governing</b> this exposure — putting a human gate in front of the actions that can hurt "
        "you, containing an agent that drifts, and recording every decision in a signed, append-only audit — is "
        "done by the Vertirite broker, which is free and open-source. A Vertirite pilot adds the program that "
        "turns that into an audit an assessor accepts: capability-registry design, interpretation of this map, "
        "an artifact mapped to your framework (HIPAA, SOX, or IEC 62443), the licensed modules, and federation "
        "across sites.",
        styles["Normal"],
    ))
    flow.append(Spacer(1, 10))
    flow.append(Paragraph(
        "This document is tamper-evident: recompute the SHA-256 of its canonical JSON body (same scope, "
        "<i>GET /v1/discovery/exposure.json</i>) and compare against the fingerprint printed in every footer.",
        styles["Normal"],
    ))
    flow.append(Spacer(1, 8))
    flow.append(Paragraph(
        f"<b>This report&rsquo;s fingerprint:</b><br/><font face='Courier' size='8'>{fingerprint_hex}</font>",
        styles["Normal"],
    ))
    flow.append(Spacer(1, 18))
    flow.append(Paragraph(
        "Vertirite is operated by SurgeXi Business Intelligence, United States. "
        "No payload or PII is included in this document; the report is metadata-only.",
        styles["MuteFoot"],
    ))

    doc.build(flow)
    return buf.getvalue()


def build_and_render_exposure(
    coverage: Dict[str, Any],
    tenant_label: Optional[str],
    generated_by: str,
) -> bytes:
    payload = build_exposure_payload(coverage, tenant_label, generated_by)
    return render_exposure_pdf(payload, fingerprint(payload))
