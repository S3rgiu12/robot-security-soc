
from pathlib import Path
from datetime import datetime

LOG_FILE = (
    Path(__file__).resolve().parent.parent
    / "day08"
    / "logs"
    / "ids_availability.log"
)

VALID_LEVELS = {"OFFLINE", "RECOVERY"}


def get_availability_summary():
    events = []

    if LOG_FILE.is_file():
        with LOG_FILE.open("r", encoding="utf-8") as file:
            for line in file:
                parts = line.strip().split(" | ", 2)

                if len(parts) != 3:
                    continue

                timestamp, level, message = parts

                if level not in VALID_LEVELS:
                    continue

                try:
                    parsed_time = datetime.strptime(
                        timestamp,
                        "%Y-%m-%d %H:%M:%S"
                    )
                except ValueError:
                    continue

                events.append({
                    "timestamp": parsed_time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "level": level,
                    "message": message
                })

    events.reverse()

    return {
        "offline_count": sum(
            event["level"] == "OFFLINE"
            for event in events
        ),
        "recovery_count": sum(
            event["level"] == "RECOVERY"
            for event in events
        ),
        "total_events": len(events),
        "events": events
    }


if __name__ == "__main__":
    import json

    print(json.dumps(
        get_availability_summary(),
        indent=4
    ))
