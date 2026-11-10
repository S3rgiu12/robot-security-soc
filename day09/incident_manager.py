
import json
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INCIDENTS_FILE = BASE_DIR / "data" / "incidents.json"


def load_incidents():
    if not INCIDENTS_FILE.exists():
        return []

    with open(INCIDENTS_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def save_incidents(incidents):
    INCIDENTS_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(INCIDENTS_FILE, "w", encoding="utf-8") as file:
        json.dump(incidents, file, indent=4, ensure_ascii=False)


def create_incident(source, incident_type, severity, description):
    incidents = load_incidents()

    next_id = max(
        (int(item["incident_id"].split("-")[1]) for item in incidents),
        default=0
    ) + 1

    incident = {
        "incident_id": f"INC-{next_id:04d}",
        "source": source,
        "type": incident_type,
        "severity": severity,
        "status": "OPEN",
        "description": description,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "resolved_at": None
    }

    incidents.append(incident)
    save_incidents(incidents)

    return incident


if __name__ == "__main__":
    incident = create_incident(
        source="IDS_AVAILABILITY",
        incident_type="SERVICE_UNAVAILABLE",
        severity="HIGH",
        description="Robot IDS v3 heartbeat timeout"
    )

    print("=== SECURITY INCIDENT MANAGER V1 ===")
    print(json.dumps(incident, indent=4))
