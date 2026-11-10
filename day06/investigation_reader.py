import json
from pathlib import Path

REPORT_FILE = (
    Path(__file__).resolve().parent.parent
    / "day15/data/incident_investigation.json"
)


def get_incident_investigations():
    if not REPORT_FILE.exists():
        return {
            "status": "UNAVAILABLE",
            "total": 0,
            "summary": {},
            "investigations": [],
            "error": "Investigation report not found"
        }

    try:
        with REPORT_FILE.open("r", encoding="utf-8") as file:
            report = json.load(file)

        if not isinstance(report, dict):
            raise ValueError("Investigation report must be an object")

        investigations = report.get("investigations")
        summary = report.get("summary")

        if not isinstance(investigations, list):
            raise ValueError("Invalid investigations list")

        if not isinstance(summary, dict):
            raise ValueError("Invalid investigation summary")

        if any(not isinstance(item, dict) for item in investigations):
            raise ValueError("Invalid investigation record")

        return {
            "status": "OK",
            "total": len(investigations),
            "generated_at_utc": report.get("generated_at_utc"),
            "summary": summary,
            "investigations": investigations
        }

    except (OSError, ValueError, TypeError) as error:
        return {
            "status": "ERROR",
            "total": 0,
            "summary": {},
            "investigations": [],
            "error": str(error)
        }
