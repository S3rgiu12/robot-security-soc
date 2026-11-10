import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent

ALERTS_FILE = ROOT / "day12/data/security_alerts.json"
RECOVERY_LOG = ROOT / "day11/logs/recovery.log"
OUTPUT_FILE = ROOT / "day14/data/normalized_events.json"


def normalize_timestamp(value):
    if not isinstance(value, str):
        return None

    try:
        timestamp = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(
                tzinfo=ZoneInfo("Europe/Bucharest")
            )

        return timestamp.astimezone(timezone.utc).isoformat()

    except ValueError:
        return None


def make_event_id(source, raw_key):
    value = f"{source}|{raw_key}"

    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()[:20]


def normalize_alerts():
    if not ALERTS_FILE.exists():
        return []

    data = json.loads(
        ALERTS_FILE.read_text(encoding="utf-8")
    )

    if not isinstance(data, list):
        raise ValueError("Security alerts must be a JSON list")

    events = []

    for alert in data:
        if not isinstance(alert, dict):
            continue

        timestamp = normalize_timestamp(
            alert.get("event_timestamp")
        )

        if timestamp is None:
            continue

        source = str(alert.get("source", "UNKNOWN"))
        event_type = str(alert.get("type", "UNKNOWN"))
        message = str(alert.get("message", ""))

        raw_key = str(
            alert.get("alert_id")
            or alert.get("event_key")
            or f"{timestamp}|{event_type}|{message}"
        )

        simulated = "DAY12_TEST_SIMULATION" in message

        events.append({
            "event_id": make_event_id(
                "security_alert",
                raw_key
            ),
            "timestamp_utc": timestamp,
            "timestamp_original": alert.get("event_timestamp"),
            "timezone_assumed": (
                "Europe/Bucharest"
                if datetime.fromisoformat(
                    alert["event_timestamp"].replace("Z", "+00:00")
                ).tzinfo is None
                else None
            ),
            "source": source,
            "event_type": event_type,
            "severity": str(
                alert.get("severity", "UNKNOWN")
            ).upper(),
            "service": "robot_ids_v3",
            "message": message,
            "simulated": simulated,
            "source_file": str(
                ALERTS_FILE.relative_to(ROOT)
            ),
            "source_record_id": alert.get("alert_id")
        })

    return events


def normalize_recovery():
    if not RECOVERY_LOG.exists():
        return []

    events = []

    for line_number, line in enumerate(
        RECOVERY_LOG.read_text(
            encoding="utf-8"
        ).splitlines(),
        start=1
    ):
        parts = line.split(" | ", 2)

        if len(parts) < 3:
            continue

        timestamp = normalize_timestamp(parts[0])

        if timestamp is None:
            continue

        event_type = parts[1].strip().upper()
        message = parts[2].strip()

        severity_map = {
            "STARTING": "INFO",
            "STARTED": "INFO",
            "RECOVERED": "INFO",
            "FAILED": "CRITICAL",
            "BLOCKED": "CRITICAL"
        }

        if event_type not in severity_map:
            continue

        simulated = "DAY12_TEST_SIMULATION" in message

        events.append({
            "event_id": make_event_id(
                "recovery_log",
                f"{line_number}|{line}"
            ),
            "timestamp_utc": timestamp,
            "source": "RECOVERY_CONTROLLER",
            "event_type": event_type,
            "severity": severity_map[event_type],
            "service": "robot_ids_v3",
            "message": message,
            "simulated": simulated,
            "source_file": str(
                RECOVERY_LOG.relative_to(ROOT)
            ),
            "source_line": line_number
        })

    return events


def main():
    events = normalize_alerts() + normalize_recovery()

    events.sort(
        key=lambda event: (
            event["timestamp_utc"],
            event["event_id"]
        )
    )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    OUTPUT_FILE.write_text(
        json.dumps(
            events,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    print("=== DAY 14 SECURITY EVENT NORMALIZER ===")
    print("Security alerts:", len(normalize_alerts()))
    print("Recovery events:", len(normalize_recovery()))
    print("Total normalized events:", len(events))
    print("Simulated events:", sum(
        1 for event in events if event["simulated"]
    ))
    print("Output:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
