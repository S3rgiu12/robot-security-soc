
import json
from pathlib import Path
from datetime import datetime
from statistics import mean

BASE_DIR = Path(__file__).resolve().parent
INCIDENTS_FILE = BASE_DIR.parent / "day09/data/incidents.json"


def load_incidents():
    with INCIDENTS_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError("Incident registry must contain a list")

    return data


def analyze_incidents():
    incidents = load_incidents()
    results = []
    durations = []
    skipped = []

    for incident in incidents:
        incident_id = incident.get("incident_id", "UNKNOWN")

        # Exclude manually created demonstration incidents
        if not incident.get("event_keys"):
            skipped.append(incident_id)
            continue

        if incident.get("source") != "IDS_AVAILABILITY":
            skipped.append(incident_id)
            continue

        if incident.get("status") != "RESOLVED":
            skipped.append(incident_id)
            continue

        try:
            created = datetime.fromisoformat(
                incident["created_at"]
            )
            resolved = datetime.fromisoformat(
                incident["resolved_at"]
            )

            # Do not mix naive and timezone-aware timestamps
            if (created.tzinfo is None) != (resolved.tzinfo is None):
                raise ValueError("Mixed timezone conventions")

            duration = (resolved - created).total_seconds()

            if duration < 0:
                raise ValueError("Negative incident duration")

            durations.append(duration)

            results.append({
                "incident_id": incident_id,
                "severity": incident.get("severity"),
                "created_at": incident["created_at"],
                "resolved_at": incident["resolved_at"],
                "duration_seconds": duration,
                "duration_minutes": round(duration / 60, 2)
            })

        except (ValueError, TypeError, KeyError) as error:
            skipped.append(f"{incident_id}: {error}")

    mttr = mean(durations) if durations else None

    return {
        "total_registry_incidents": len(incidents),
        "analyzed_incidents": len(results),
        "skipped_incidents": skipped,
        "mttr_seconds": round(mttr, 2) if mttr is not None else None,
        "mttr_minutes": round(mttr / 60, 2) if mttr is not None else None,
        "incidents": results
    }


if __name__ == "__main__":
    report = analyze_incidents()

    print("=== ROBOT INCIDENT RESPONSE ANALYZER V1 ===")
    print("Analyzed incidents:", report["analyzed_incidents"])
    print("Skipped incidents:", report["skipped_incidents"])
    print("MTTR (seconds):", report["mttr_seconds"])
    print("MTTR (minutes):", report["mttr_minutes"])

    print("\n=== INCIDENT DURATIONS ===")

    for incident in report["incidents"]:
        print(
            f"{incident['incident_id']} | "
            f"{incident['duration_seconds']} seconds | "
            f"{incident['duration_minutes']} minutes"
        )
