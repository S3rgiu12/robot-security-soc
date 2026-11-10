
from pathlib import Path
from datetime import datetime, timezone
import json

BASE_DIR = Path(__file__).resolve().parent

HEARTBEAT_FILE = (
    BASE_DIR / "logs" / "ids_heartbeat.json"
)

TIMEOUT_SECONDS = 15
EXPECTED_SERVICE = "robot_ids_v3"


def get_heartbeat_status():
    if not HEARTBEAT_FILE.is_file():
        return {
            "status": "OFFLINE",
            "reason": "Heartbeat file missing",
            "age_seconds": None
        }

    try:
        with HEARTBEAT_FILE.open("r", encoding="utf-8") as file:
            heartbeat = json.load(file)

        if heartbeat.get("service") != EXPECTED_SERVICE:
            raise ValueError("Unexpected heartbeat service")

        timestamp = datetime.fromisoformat(
            heartbeat["timestamp"]
        )

        if timestamp.tzinfo is None:
            raise ValueError("Heartbeat timestamp has no timezone")

        now = datetime.now(timezone.utc)
        age = (now - timestamp).total_seconds()

        if age < -5:
            return {
                "status": "OFFLINE",
                "reason": "Heartbeat timestamp is in the future",
                "age_seconds": round(age, 2)
            }

        if age <= TIMEOUT_SECONDS:
            status = "ONLINE"
            reason = "Heartbeat received recently"
        else:
            status = "OFFLINE"
            reason = "Heartbeat timeout exceeded"

        return {
            "status": status,
            "reason": reason,
            "age_seconds": round(age, 2),
            "last_heartbeat": timestamp.isoformat()
        }

    except (OSError, ValueError, KeyError, TypeError):
        return {
            "status": "OFFLINE",
            "reason": "Invalid or unreadable heartbeat",
            "age_seconds": None
        }


if __name__ == "__main__":
    result = get_heartbeat_status()

    print("=== ROBOT HEARTBEAT MONITOR ===")
    print("Status:", result["status"])
    print("Reason:", result["reason"])
    print("Age:", result["age_seconds"], "seconds")
