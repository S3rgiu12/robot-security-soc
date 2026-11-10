import json
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

REPORTS_JSON = (
    BASE_DIR / "day17/data/soc_incident_reports.json"
)

PDF_DIR = (
    BASE_DIR / "day17/data/pdf_reports"
)

INCIDENT_PATTERN = re.compile(r"INC-\d{4,}")


def get_soc_reports():
    try:
        data = json.loads(
            REPORTS_JSON.read_text(encoding="utf-8")
        )

        reports = data.get("reports", [])

        result = []

        for report in reports:
            incident_id = report.get("incident_id", "")

            if not INCIDENT_PATTERN.fullmatch(incident_id):
                continue

            filename = f"{incident_id}_SOC_Report.pdf"

            result.append({
                "incident_id": incident_id,
                "severity": report.get("severity"),
                "operational_status": report.get(
                    "operational_status"
                ),
                "review_required": report.get(
                    "review_required", False
                ),
                "verification_status": report.get(
                    "forensics", {}
                ).get("verification_status"),
                "pdf_available": (
                    PDF_DIR / filename
                ).is_file(),
            })

        return {
            "status": "OK",
            "generated_at_utc": data.get(
                "generated_at_utc"
            ),
            "summary": {
                "total_reports": len(result),
                "pdf_available": sum(
                    item["pdf_available"]
                    for item in result
                ),
                "review_required": sum(
                    item["review_required"]
                    for item in result
                ),
            },
            "reports": result,
        }

    except (OSError, ValueError, TypeError) as error:
        return {
            "status": "UNAVAILABLE",
            "error": str(error),
            "reports": [],
        }


def get_pdf_path(incident_id):
    if not INCIDENT_PATTERN.fullmatch(incident_id):
        return None

    filename = f"{incident_id}_SOC_Report.pdf"
    path = PDF_DIR / filename

    if not path.is_file():
        return None

    return path
