
from pathlib import Path
from datetime import datetime
import json

from incident_manager import (
    load_incidents,
    save_incidents
)

BASE_DIR = Path(__file__).resolve().parent

AVAILABILITY_LOG = (
    BASE_DIR.parent
    / "day08"
    / "logs"
    / "ids_availability.log"
)


def import_availability_events():
    if not AVAILABILITY_LOG.exists():
        print("ERROR: Availability log not found.")
        return

    incidents = load_incidents()

    created = 0
    resolved = 0

    with open(AVAILABILITY_LOG, "r", encoding="utf-8") as file:
        lines = file.readlines()

    for line in lines:
        parts = line.strip().split(" | ", 2)

        if len(parts) != 3:
            continue

        timestamp, level, message = parts

        try:
            event_time = datetime.strptime(
                timestamp, "%Y-%m-%d %H:%M:%S"
            ).isoformat()
        except ValueError:
            continue

        event_key = f"IDS_AVAILABILITY|{line.strip()}"

        # Prevent importing the same event twice
        if any(
            event_key in item.get("event_keys", [])
            for item in incidents
        ):
            continue

        if level == "OFFLINE":
            next_id = max(
                (
                    int(item["incident_id"].split("-")[1])
                    for item in incidents
                ),
                default=0
            ) + 1

            incident = {
                "incident_id": f"INC-{next_id:04d}",
                "source": "IDS_AVAILABILITY",
                "type": "SERVICE_UNAVAILABLE",
                "severity": "HIGH",
                "status": "OPEN",
                "description": message,
                "created_at": event_time,
                "resolved_at": None,
                "event_keys": [event_key]
            }

            incidents.append(incident)
            created += 1

        elif level == "RECOVERY":
            open_incidents = [
                item for item in incidents
                if item.get("source") == "IDS_AVAILABILITY"
                and item.get("status") == "OPEN"
                and item.get("type") == "SERVICE_UNAVAILABLE"
                and item.get("event_keys")
            ]

            if open_incidents:
                incident = open_incidents[-1]
                incident["status"] = "RESOLVED"
                incident["resolved_at"] = event_time
                incident["event_keys"].append(event_key)
                resolved += 1

    save_incidents(incidents)

    print("=== AVAILABILITY INCIDENT IMPORTER ===")
    print(f"Created incidents: {created}")
    print(f"Resolved incidents: {resolved}")
    print(f"Total incidents: {len(incidents)}")


if __name__ == "__main__":
    import_availability_events()
