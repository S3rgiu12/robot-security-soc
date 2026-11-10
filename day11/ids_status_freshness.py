import json
from datetime import datetime, timezone
from pathlib import Path

STATUS_FILE = (
    Path(__file__).resolve().parent
    / "data"
    / "ids_process_status.json"
)

MAX_STATUS_AGE_SECONDS = 30


def get_ids_status_freshness():
    if not STATUS_FILE.exists():
        return {
            "freshness": "UNKNOWN",
            "recorded_state": "UNKNOWN",
            "age_seconds": None,
            "reason": "Process status file missing"
        }

    try:
        with STATUS_FILE.open(encoding="utf-8") as file:
            data = json.load(file)

        timestamp = datetime.fromisoformat(
            data["checked_at_utc"].replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            raise ValueError("Timestamp has no timezone")

        age = (
            datetime.now(timezone.utc) - timestamp
        ).total_seconds()

        if age < 0:
            freshness = "UNKNOWN"
            reason = "Process status timestamp is in the future"
        elif age <= MAX_STATUS_AGE_SECONDS:
            freshness = "FRESH"
            reason = "Process status recently updated"
        else:
            freshness = "STALE"
            reason = "Process status update timeout exceeded"

        return {
            "freshness": freshness,
            "recorded_state": data.get("state", "UNKNOWN"),
            "age_seconds": round(age, 2),
            "threshold_seconds": MAX_STATUS_AGE_SECONDS,
            "reason": reason
        }

    except (OSError, ValueError, KeyError, TypeError) as error:
        return {
            "freshness": "UNKNOWN",
            "recorded_state": "UNKNOWN",
            "age_seconds": None,
            "reason": f"Invalid process status data: {error}"
        }


if __name__ == "__main__":
    result = get_ids_status_freshness()

    print("=== IDS STATUS FRESHNESS MONITOR ===")

    for key, value in result.items():
        print(f"{key}: {value}")
