
import json
from pathlib import Path
from collections import Counter

BASE_DIR = Path(__file__).resolve().parent

INCIDENTS_FILE = (
    BASE_DIR.parent / "day09" / "data" / "incidents.json"
)


def get_incidents_summary():
    if not INCIDENTS_FILE.exists():
        return {
            "total": 0,
            "open_count": 0,
            "resolved_count": 0,
            "incidents": []
        }

    with open(INCIDENTS_FILE, "r", encoding="utf-8") as file:
        incidents = json.load(file)

    if not isinstance(incidents, list):
        raise ValueError("Incidents file must contain a JSON list")

    counts = Counter(
        incident.get("status")
        for incident in incidents
    )

    return {
        "total": len(incidents),
        "open_count": counts["OPEN"],
        "resolved_count": counts["RESOLVED"],
        "incidents": list(reversed(incidents))
    }


if __name__ == "__main__":
    print(json.dumps(get_incidents_summary(), indent=4))
