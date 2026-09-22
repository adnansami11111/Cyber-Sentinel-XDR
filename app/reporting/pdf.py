from __future__ import annotations

from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


def _text(value: Any) -> str:
    if value is None:
        return "-"
    return str(value)


def _paragraph(value: Any, style) -> Paragraph:
    return Paragraph(
        _text(value).replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;"),
        style,
    )


def _section_title(title: str, styles):
    return Paragraph(title, styles["SectionTitle"])


def _make_table(
    data: list[list[Any]],
    styles,
    widths=None,
):
    converted = []

    for row in data:
        converted.append([
            _paragraph(cell, styles["TableCell"])
            for cell in row
        ])

    table = Table(
        converted,
        colWidths=widths,
        repeatRows=1,
        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9ca3af")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    return table


def _footer(canvas, doc):
    canvas.saveState()

    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#6b7280"))

    canvas.drawString(
        15 * mm,
        10 * mm,
        "Cyber Sentinel XDR — LAB Security Report",
    )

    canvas.drawRightString(
        A4[0] - 15 * mm,
        10 * mm,
        f"Page {doc.page}",
    )

    canvas.restoreState()


def render_incident_report_pdf(report: dict[str, Any]) -> bytes:
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=18 * mm,
        title="Cyber Sentinel XDR Incident Security Report",
        author="Cyber Sentinel XDR",
    )

    base = getSampleStyleSheet()

    styles = {
        "Title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontSize=20,
            leading=24,
            alignment=TA_CENTER,
            spaceAfter=8,
        ),
        "Subtitle": ParagraphStyle(
            "Subtitle",
            parent=base["Normal"],
            fontSize=9,
            leading=12,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#6b7280"),
            spaceAfter=15,
        ),
        "SectionTitle": ParagraphStyle(
            "SectionTitle",
            parent=base["Heading2"],
            fontSize=13,
            leading=16,
            spaceBefore=12,
            spaceAfter=7,
            textColor=colors.HexColor("#111827"),
        ),
        "Body": ParagraphStyle(
            "Body",
            parent=base["BodyText"],
            fontSize=9,
            leading=13,
            spaceAfter=6,
        ),
        "TableCell": ParagraphStyle(
            "TableCell",
            parent=base["BodyText"],
            fontSize=7.5,
            leading=10,
        ),
        "Small": ParagraphStyle(
            "Small",
            parent=base["BodyText"],
            fontSize=8,
            leading=11,
        ),
    }

    story = []

    metadata = report.get("metadata", {})
    incident = report.get("incident", {})
    risk = report.get("risk_assessment", {})
    detections = report.get("detections", [])
    mitre_mapping = report.get("mitre_mapping", [])
    evidence = report.get("evidence", [])
    timeline = report.get("timeline", [])
    response = report.get("response_summary", {})
    response_actions = report.get("response_actions", [])
    affected_assets = report.get("affected_assets", [])
    iocs = report.get("indicators_of_compromise", [])
    recommendations = report.get("recommendations", [])

    story.append(
        Paragraph(
            "Cyber Sentinel XDR",
            styles["Title"],
        )
    )

    story.append(
        Paragraph(
            "INCIDENT SECURITY REPORT",
            styles["Subtitle"],
        )
    )

    metadata_table = [
        ["Report ID", metadata.get("report_id", "-")],
        ["Generated At", metadata.get("generated_at", "-")],
        ["Report Type", metadata.get("report_type", "-")],
        ["Format", metadata.get("format", "PDF")],
        ["Mode", metadata.get("mode", "LAB")],
        ["Status", report.get("report_status", "-")],
    ]

    story.append(
        _make_table(
            metadata_table,
            styles,
            widths=[45 * mm, 135 * mm],
        )
    )

    story.append(Spacer(1, 8))

    story.append(_section_title("Executive Summary", styles))
    story.append(
        Paragraph(
            _text(report.get("executive_summary", "-")),
            styles["Body"],
        )
    )

    story.append(_section_title("Incident Details", styles))

    incident_table = [
        ["Field", "Value"],
        ["Incident ID", incident.get("incident_id", "-")],
        ["Incident Key", incident.get("incident_key", "-")],
        ["Title", incident.get("title", "-")],
        ["Severity", incident.get("severity", "-")],
        ["Risk Score", incident.get("risk_score", "-")],
        ["Status", incident.get("status", "-")],
        ["Source IP", incident.get("source_ip", "-")],
        ["Target Asset", incident.get("target_asset", "-")],
    ]

    story.append(
        _make_table(
            incident_table,
            styles,
            widths=[45 * mm, 135 * mm],
        )
    )

    story.append(_section_title("Risk Assessment", styles))

    risk_table = [
        ["Risk Metric", "Value"],
        ["Risk Score", risk.get("risk_score", "-")],
        ["Risk Level", risk.get("risk_level", "-")],
        ["Severity", risk.get("severity", "-")],
        ["Detection Count", risk.get("detection_count", 0)],
        ["MITRE Technique Count", risk.get("mitre_technique_count", 0)],
        ["IOC Count", risk.get("ioc_count", 0)],
        ["Response Action Count", risk.get("response_action_count", 0)],
    ]

    story.append(
        _make_table(
            risk_table,
            styles,
            widths=[75 * mm, 105 * mm],
        )
    )

    factors = risk.get("risk_factors", [])

    if factors:
        story.append(Spacer(1, 5))
        story.append(Paragraph("<b>Risk Factors</b>", styles["Body"]))

        for factor in factors:
            story.append(
                Paragraph(
                    f"• {_text(factor)}",
                    styles["Body"],
                )
            )

    story.append(_section_title("Detection Findings", styles))

    if detections:
        detection_table = [
            [
                "ID",
                "Detection",
                "Severity",
                "Confidence",
                "Risk",
                "MITRE",
            ]
        ]

        for item in detections:
            detection_table.append(
                [
                    item.get("detection_id", "-"),
                    item.get("detection_name", "-"),
                    item.get("severity", "-"),
                    item.get("confidence", "-"),
                    item.get("risk_score", "-"),
                    item.get("mitre_technique", "-"),
                ]
            )

        story.append(
            _make_table(
                detection_table,
                styles,
                widths=[
                    12 * mm,
                    55 * mm,
                    25 * mm,
                    22 * mm,
                    20 * mm,
                    25 * mm,
                ],
            )
        )
    else:
        story.append(
            Paragraph(
                "No detection findings recorded.",
                styles["Body"],
            )
        )

    story.append(_section_title("MITRE ATT&CK Mapping", styles))

    if mitre_mapping:
        mitre_table = [
            ["Technique", "Name", "Tactic", "Description"]
        ]

        for item in mitre_mapping:
            mitre_table.append(
                [
                    item.get("technique", "-"),
                    item.get("name", "-"),
                    item.get("tactic", "-"),
                    item.get("description", "-"),
                ]
            )

        story.append(
            _make_table(
                mitre_table,
                styles,
                widths=[
                    20 * mm,
                    35 * mm,
                    45 * mm,
                    80 * mm,
                ],
            )
        )
    else:
        story.append(
            Paragraph(
                "No MITRE ATT&CK techniques mapped.",
                styles["Body"],
            )
        )

    story.append(PageBreak())

    story.append(_section_title("Evidence", styles))

    if evidence:
        evidence_table = [
            [
                "Timestamp",
                "Event Type",
                "Source IP",
                "Destination IP",
                "Description",
            ]
        ]

        for item in evidence:
            evidence_table.append(
                [
                    item.get("timestamp", "-"),
                    item.get("event_type", "-"),
                    item.get("source_ip", "-"),
                    item.get("destination_ip", "-"),
                    item.get("description", "-"),
                ]
            )

        story.append(
            _make_table(
                evidence_table,
                styles,
                widths=[
                    30 * mm,
                    25 * mm,
                    28 * mm,
                    28 * mm,
                    69 * mm,
                ],
            )
        )
    else:
        story.append(
            Paragraph(
                "No evidence items recorded.",
                styles["Body"],
            )
        )

    story.append(_section_title("Event Timeline", styles))

    if timeline:
        timeline_table = [
            ["Timestamp", "Event", "Severity", "Source"]
        ]

        for item in timeline:
            timeline_table.append(
                [
                    item.get("timestamp", "-"),
                    item.get("event", "-"),
                    item.get("severity", "-"),
                    item.get("source", "-"),
                ]
            )

        story.append(
            _make_table(
                timeline_table,
                styles,
                widths=[
                    35 * mm,
                    90 * mm,
                    25 * mm,
                    30 * mm,
                ],
            )
        )
    else:
        story.append(
            Paragraph(
                "No timeline events recorded.",
                styles["Body"],
            )
        )

    story.append(_section_title("Response / Containment", styles))

    response_table = [
        ["Field", "Value"],
        ["Containment Status", response.get("containment_status", "-")],
        ["Incident Status", response.get("incident_status", "-")],
        ["Action Count", response.get("action_count", 0)],
        ["Action Types", ", ".join(response.get("action_types", [])) or "-"],
        ["Action Statuses", ", ".join(response.get("action_statuses", [])) or "-"],
        ["Targets", ", ".join(response.get("targets", [])) or "-"],
        ["LAB Only", response.get("lab_only", True)],
        ["Simulation Only", response.get("simulation_only", True)],
        ["Summary", response.get("summary", "-")],
    ]

    story.append(
        _make_table(
            response_table,
            styles,
            widths=[55 * mm, 125 * mm],
        )
    )

    if response_actions:
        story.append(Spacer(1, 8))
        story.append(Paragraph("<b>Recorded Actions</b>", styles["Body"]))

        action_table = [
            [
                "ID",
                "Action",
                "Target",
                "Mode",
                "Status",
                "Created",
            ]
        ]

        for item in response_actions:
            action_table.append(
                [
                    item.get("action_id", "-"),
                    item.get("action_type", "-"),
                    item.get("target", "-"),
                    item.get("mode", "-"),
                    item.get("status", "-"),
                    item.get("created_at", "-"),
                ]
            )

        story.append(
            _make_table(
                action_table,
                styles,
                widths=[
                    12 * mm,
                    35 * mm,
                    45 * mm,
                    18 * mm,
                    25 * mm,
                    45 * mm,
                ],
            )
        )

    story.append(_section_title("Affected Assets", styles))

    if affected_assets:
        for asset in affected_assets:
            story.append(
                Paragraph(
                    f"• {_text(asset)}",
                    styles["Body"],
                )
            )
    else:
        story.append(
            Paragraph(
                "No affected assets recorded.",
                styles["Body"],
            )
        )

    story.append(_section_title("Indicators of Compromise", styles))

    if iocs:
        for ioc in iocs:
            story.append(
                Paragraph(
                    f"• {_text(ioc)}",
                    styles["Body"],
                )
            )
    else:
        story.append(
            Paragraph(
                "No indicators of compromise recorded.",
                styles["Body"],
            )
        )

    story.append(_section_title("Recommendations", styles))

    if recommendations:
        for recommendation in recommendations:
            story.append(
                Paragraph(
                    f"• {_text(recommendation)}",
                    styles["Body"],
                )
            )
    else:
        story.append(
            Paragraph(
                "No recommendations recorded.",
                styles["Body"],
            )
        )

    story.append(Spacer(1, 12))

    story.append(
        Paragraph(
            "This report was generated by Cyber Sentinel XDR in LAB mode. "
            "Simulation and response data are intended for controlled "
            "security testing and investigation workflows.",
            styles["Small"],
        )
    )

    doc.build(
        story,
        onFirstPage=_footer,
        onLaterPages=_footer,
    )

    return buffer.getvalue()
