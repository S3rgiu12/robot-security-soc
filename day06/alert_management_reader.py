
import json
from collections import Counter
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
DAY13_DATA = PROJECT_DIR / "day13" / "data"


def read_json(filename):
    path = DAY13_DATA / filename

    with path.open(encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError(f"Invalid JSON list: {filename}")

    return data


def get_alert_management():
    records = read_json("alert_management.json")

    counts = Counter(
        record["status"] for record in records
    )

    return {
        "status": "OK",
        "total": len(records),
        "summary": {
            "NEW": counts["NEW"],
            "ACKNOWLEDGED": counts["ACKNOWLEDGED"],
            "RESOLVED": counts["RESOLVED"]
        },
        "alerts": records
    }


def get_security_notifications():
    notifications = read_json("notifications.json")

    return {
        "status": "OK",
        "total": len(notifications),
        "notifications": notifications
    }
