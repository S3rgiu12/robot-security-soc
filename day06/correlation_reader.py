import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

INCIDENTS_FILE = (
    ROOT / "day14/data/correlated_incidents.json"
)


def get_correlated_incidents():
    if not INCIDENTS_FILE.exists():
        return {
            "status": "UNAVAILABLE",
            "total": 0,
            "incidents": [],
            "summary": {},
            "error": "Correlated incidents file not found"
        }

    try:
        with INCIDENTS_FILE.open(
            "r", encoding="utf-8"
        ) as file:
            incidents = json.load(file)

        if not isinstance(incidents, list):
            raise ValueError(
                "Correlated incidents must be a JSON list"
            )

        required = {
            "incident_id",
            "incident_type",
            "status",
            "severity",
            "started_at_utc",
            "evidence"
        }

        for incident in incidents:
            if not isinstance(incident, dict):
                raise ValueError("Invalid incident record")

            if not required.issubset(incident):
                raise ValueError(
                    "Incident is missing required fields"
                )

        incidents = sorted(
            incidents,
            key=lambda item: item["started_at_utc"],
            reverse=True
        )

        return {
            "status": "OK",
            "total": len(incidents),
            "incidents": incidents,
            "summary": {
                "by_type": dict(Counter(
                    item["incident_type"]
                    for item in incidents
                )),
                "by_severity": dict(Counter(
                    item["severity"]
                    for item in incidents
                )),
                "by_status": dict(Counter(
                    item["status"]
                    for item in incidents
                )),
                "simulated": sum(
                    bool(item.get("simulated", False))
                    for item in incidents
                )
            }
        }

    except (OSError, ValueError, TypeError) as exc:
        return {
            "status": "ERROR",
            "total": 0,
            "incidents": [],
            "summary": {},
            "error": str(exc)
        }
