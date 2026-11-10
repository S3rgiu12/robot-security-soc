import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DAY16_DIR = BASE_DIR.parent / "day16" / "data"

VERIFICATION_FILE = DAY16_DIR / "evidence_verification.json"
TIMELINE_FILE = DAY16_DIR / "incident_timelines.json"


def load_json(path):
    if not path.is_file():
        raise FileNotFoundError(f"Missing report: {path.name}")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def get_day16_forensics():
    try:
        verification = load_json(VERIFICATION_FILE)
        timelines = load_json(TIMELINE_FILE)

        if not isinstance(verification, dict):
            raise ValueError("Invalid verification report")

        if not isinstance(timelines, dict):
            raise ValueError("Invalid timeline report")

        verification_incidents = verification.get("incidents", [])
        timeline_incidents = timelines.get("incidents", [])

        if not isinstance(verification_incidents, list):
            raise ValueError("Invalid verification incidents")

        if not isinstance(timeline_incidents, list):
            raise ValueError("Invalid timeline incidents")

        timeline_by_id = {
            item["incident_id"]: item
            for item in timeline_incidents
        }

        combined = []

        for item in verification_incidents:
            incident_id = item.get("incident_id")
            timeline = timeline_by_id.get(incident_id, {})

            combined.append({
                "incident_id": incident_id,
                "operational_status": item.get("operational_status"),
                "verification_status": item.get("verification_status"),
                "evidence_count": item.get("evidence_count", 0),
                "verified_count": item.get("verified_count", 0),
                "evidence": item.get("evidence", []),
                "verification_findings": item.get("findings", []),
                "timeline_status": timeline.get(
                    "timeline_status", "INCOMPLETE"
                ),
                "duration_seconds": timeline.get("duration_seconds"),
                "events": timeline.get("events", []),
                "timeline_findings": timeline.get("findings", [])
            })

        return {
            "status": "OK",
            "generated_at_utc": verification.get("generated_at_utc"),
            "timeline_generated_at_utc": timelines.get(
                "generated_at_utc"
            ),
            "summary": {
                "total_incidents": len(combined),
                "verified_incidents": sum(
                    x["verification_status"] == "VERIFIED"
                    for x in combined
                ),
                "reconstructed_timelines": sum(
                    x["timeline_status"] == "RECONSTRUCTED"
                    for x in combined
                ),
                "review_required": sum(
                    x["verification_status"] != "VERIFIED"
                    or x["timeline_status"] != "RECONSTRUCTED"
                    for x in combined
                ),
                "verified_evidence": sum(
                    x["verified_count"] for x in combined
                )
            },
            "incidents": combined
        }

    except (OSError, ValueError, TypeError, KeyError) as exc:
        return {
            "status": "ERROR",
            "message": str(exc),
            "summary": {},
            "incidents": []
        }
