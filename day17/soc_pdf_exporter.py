import json
import re
import sys
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)

BASE_DIR = Path(__file__).resolve().parent
JSON_FILE = BASE_DIR / "data/soc_incident_reports.json"
PDF_DIR = BASE_DIR / "data/pdf_reports"

NAVY = colors.HexColor("#14253D")
BLUE = colors.HexColor("#1769AA")
LIGHT = colors.HexColor("#EEF3F8")
GREY = colors.HexColor("#566476")


def safe(value):
    if value is None:
        return "Not available"
    return escape(str(value))


styles = getSampleStyleSheet()

styles.add(ParagraphStyle(
    name="SOCTitle",
    parent=styles["Title"],
    fontSize=19,
    leading=24,
    textColor=NAVY,
    spaceAfter=12,
))

styles.add(ParagraphStyle(
    name="SOCHeading",
    parent=styles["Heading2"],
    fontSize=11,
    leading=15,
    textColor=BLUE,
    spaceBefore=15,
    spaceAfter=7,
))

styles.add(ParagraphStyle(
    name="SOCBody",
    parent=styles["BodyText"],
    fontSize=9,
    leading=14,
    spaceAfter=6,
    wordWrap="CJK",
))

styles.add(ParagraphStyle(
    name="SOCSmall",
    parent=styles["BodyText"],
    fontSize=8,
    leading=12,
    textColor=GREY,
    wordWrap="CJK",
))


def paragraph(value, style="SOCBody"):
    return Paragraph(safe(value), styles[style])


def section(story, title):
    story.append(Paragraph(
        escape(title), styles["SOCHeading"]
    ))


def info_table(items):
    rows = [
        [paragraph(key, "SOCSmall"), paragraph(value)]
        for key, value in items
    ]

    table = Table(
        rows,
        colWidths=[48 * mm, 126 * mm],
        hAlign="LEFT",
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1),
         0.3, colors.HexColor("#D6E0EA")),
    ]))

    return table


def page_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(GREY)
    canvas.drawString(
        18 * mm, 13 * mm,
        "ROBOT SECURITY SOC | Historical forensic snapshot"
    )
    canvas.drawRightString(
        192 * mm, 13 * mm,
        f"Page {doc.page}"
    )
    canvas.restoreState()


def export_incident(report, generated_at):
    incident_id = report["incident_id"]

    if not re.fullmatch(r"INC-\d{4,}", incident_id):
        raise ValueError("Invalid incident ID")

    PDF_DIR.mkdir(parents=True, exist_ok=True)

    output = PDF_DIR / f"{incident_id}_SOC_Report.pdf"

    doc = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=21 * mm,
        title=f"SOC Incident Report {incident_id}",
        author="Robot Security SOC",
    )

    story = []

    story.append(Paragraph(
        "ROBOT SECURITY SOC",
        styles["SOCSmall"]
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Security Incident Report",
        styles["SOCTitle"]
    ))

    story.append(paragraph(
        f"Incident: {incident_id} | "
        f"Report generated: {generated_at}",
        "SOCSmall"
    ))

    section(story, "01 / Executive Summary")

    story.append(info_table([
        ("Incident ID", incident_id),
        ("Source", report.get("source")),
        ("Incident Type", report.get("incident_type")),
        ("Severity", report.get("severity")),
        ("Operational Status",
         report.get("operational_status")),
        ("Created At", report.get("created_at")),
        ("Resolved At", report.get("resolved_at")),
    ]))

    story.append(Spacer(1, 10))
    story.append(paragraph(
        report.get("description")
        or "No incident description available."
    ))

    investigation = report.get("investigation", {})
    forensics = report.get("forensics", {})

    section(story, "02 / Investigation Assessment")

    story.append(info_table([
        ("Priority", investigation.get("priority")),
        ("Investigation Status",
         investigation.get("status")),
        ("Evidence Status",
         investigation.get("evidence_status")),
        ("Review Required",
         "YES" if report.get("review_required")
         else "NO"),
    ]))

    section(story, "03 / Evidence Verification")

    story.append(info_table([
        ("Verification Status",
         forensics.get("verification_status")),
        ("Evidence References",
         forensics.get("evidence_count", 0)),
        ("Verified References",
         forensics.get("verified_count", 0)),
    ]))

    evidence = forensics.get("evidence") or []

    if evidence:
        for entry in evidence:
            story.append(paragraph(
                f"{entry.get('status', 'UNKNOWN')} | "
                f"{entry.get('event_key', 'Unknown key')}",
                "SOCSmall"
            ))
    else:
        story.append(paragraph(
            "No linked evidence available."
        ))

    section(story, "04 / Forensic Timeline")

    story.append(info_table([
        ("Timeline Status",
         forensics.get("timeline_status")),
        ("Duration (seconds)",
         forensics.get("duration_seconds")),
    ]))

    story.append(Spacer(1, 8))

    events = forensics.get("events") or []

    if events:
        for event in events:
            story.append(paragraph(
                f"{event.get('timestamp', '--')} | "
                f"{event.get('event_type', '--')} | "
                f"{event.get('message', '')}",
                "SOCSmall"
            ))
    else:
        story.append(paragraph(
            "No verified timeline events available."
        ))

    section(story, "05 / Analyst Findings")

    findings = report.get("analyst_findings") or []

    if findings:
        for finding in findings:
            story.append(paragraph(
                f"- {finding}"
            ))
    else:
        story.append(paragraph(
            "No analyst findings recorded."
        ))

    section(story, "06 / Reporting Limitations")

    story.append(paragraph(
        "This report is generated from historical local "
        "snapshots. Evidence verification confirms matches "
        "against available source logs; it does not establish "
        "cryptographic integrity or independently prove the "
        "root cause of an incident."
    ))

    doc.build(
        story,
        onFirstPage=page_footer,
        onLaterPages=page_footer,
    )

    return output


def main():
    data = json.loads(
        JSON_FILE.read_text(encoding="utf-8")
    )

    reports = data["reports"]

    if len(sys.argv) > 1:
        requested_id = sys.argv[1]
        reports = [
            item for item in reports
            if item["incident_id"] == requested_id
        ]

        if not reports:
            raise SystemExit(
                f"Incident not found: {requested_id}"
            )

    for report in reports:
        output = export_incident(
            report,
            data.get("generated_at_utc", "Unknown")
        )
        print(f"[PDF CREATED] {output}")

    print(f"Total PDFs created: {len(reports)}")


if __name__ == "__main__":
    main()
