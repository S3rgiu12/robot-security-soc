
from pathlib import Path
from datetime import datetime

LOG_FILE = (
    Path(__file__).resolve().parent.parent
    / "day05"
    / "logs"
    / "robot_ids_alerts_v3.log"
)

VALID_LEVELS = {"CRITICAL", "RECOVERY"}


def read_ids_events():
    events = []

    if not LOG_FILE.is_file():
        return events

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            parts = line.strip().split(" | ", 2)

            if len(parts) != 3:
                continue

            timestamp, level, message = parts

            if level not in VALID_LEVELS:
                continue

            try:
                parsed_time = datetime.fromisoformat(timestamp)
            except ValueError:
                continue

            events.append({
                "timestamp": parsed_time.isoformat(
                    sep=" ", timespec="seconds"
                ),
                "level": level,
                "message": message
            })

    return events


def get_ids_summary():
    events = read_ids_events()

    critical_count = sum(
        event["level"] == "CRITICAL"
        for event in events
    )

    recovery_count = sum(
        event["level"] == "RECOVERY"
        for event in events
    )

    if not events:
        status = "UNKNOWN"
    elif events[-1]["level"] == "CRITICAL":
        status = "CRITICAL"
    else:
        status = "NORMAL"

    return {
        "status": status,
        "critical_count": critical_count,
        "recovery_count": recovery_count,
        "total_events": len(events),
        "events": list(reversed(events))
    }


if __name__ == "__main__":
    summary = get_ids_summary()

    print("=== ROBOT IDS LOG READER ===")
    print("Log file:", LOG_FILE)
    print("IDS status:", summary["status"])
    print("Critical events:", summary["critical_count"])
    print("Recovery events:", summary["recovery_count"])
    print("Total events:", summary["total_events"])

    for event in summary["events"]:
        print(
            event["timestamp"],
            event["level"],
            event["message"],
            sep=" | "
        )
