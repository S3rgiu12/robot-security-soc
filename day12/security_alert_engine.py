
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

ALERT_FILE = BASE_DIR / "data/security_alerts.json"

SOURCES = {
    "RECOVERY_CONTROLLER": PROJECT_DIR / "day11/logs/recovery.log",
    "RECOVERY_SUPERVISOR": PROJECT_DIR / "day11/logs/recovery_supervisor.log",
    "IDS_AVAILABILITY": PROJECT_DIR / "day08/logs/ids_availability.log",
}

EVENT_RULES = {
    "RECOVERY_CONTROLLER": {
        "RECOVERED": ("INFO", "IDS_RECOVERED"),
        "FAILED": ("CRITICAL", "RECOVERY_FAILED"),
        "BLOCKED": ("CRITICAL", "RECOVERY_BLOCKED"),
    },
    "RECOVERY_SUPERVISOR": {
        "RECOVERY_REQUESTED": ("WARNING", "RECOVERY_REQUESTED"),
        "RECOVERY_SUCCESS": ("INFO", "RECOVERY_SUCCESS"),
        "RECOVERY_FAILED": ("CRITICAL", "RECOVERY_FAILED"),
    },
    "IDS_AVAILABILITY": {
        "OFFLINE": ("CRITICAL", "IDS_OFFLINE"),
        "RECOVERY": ("INFO", "IDS_ONLINE"),
    },
}


def load_alerts():
    if not ALERT_FILE.exists():
        return []

    with ALERT_FILE.open(encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError("Alert registry must contain a list")

    return data


def save_alerts(alerts):
    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    temp_file = ALERT_FILE.with_suffix(".json.tmp")

    with temp_file.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4, ensure_ascii=False)

    temp_file.replace(ALERT_FILE)


def parse_event(source, line):
    parts = [part.strip() for part in line.split("|", 2)]

    if len(parts) != 3:
        return None

    timestamp, event, message = parts

    rule = EVENT_RULES.get(source, {}).get(event)

    if rule is None:
        return None

    severity, alert_type = rule

    event_key = f"{source}|{line.strip()}"

    alert_id = hashlib.sha256(
        event_key.encode("utf-8")
    ).hexdigest()[:16]

    return {
        "alert_id": alert_id,
        "source": source,
        "type": alert_type,
        "severity": severity,
        "event": event,
        "message": message,
        "event_timestamp": timestamp,
        "detected_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "event_key": event_key,
    }


def collect_alerts():
    alerts = load_alerts()

    known_keys = {
        alert["event_key"]
        for alert in alerts
    }

    new_alerts = []

    for source, path in SOURCES.items():
        if not path.is_file():
            print(f"[WARNING] Missing source: {path}")
            continue

        with path.open(encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                alert = parse_event(source, line)

                if alert is None:
                    continue

                if alert["event_key"] in known_keys:
                    continue

                known_keys.add(alert["event_key"])
                new_alerts.append(alert)

    alerts.extend(new_alerts)

    alerts.sort(
        key=lambda alert: (
            alert["event_timestamp"],
            alert["alert_id"]
        ),
        reverse=True
    )

    save_alerts(alerts)

    return alerts, new_alerts


def main():
    print("=== ROBOT SECURITY ALERT ENGINE V1 ===")

    alerts, new_alerts = collect_alerts()

    counts = Counter(
        alert["severity"]
        for alert in alerts
    )

    print("New alerts:", len(new_alerts))
    print("Total alerts:", len(alerts))
    print("CRITICAL:", counts["CRITICAL"])
    print("WARNING:", counts["WARNING"])
    print("INFO:", counts["INFO"])
    print("Registry:", ALERT_FILE)


if __name__ == "__main__":
    main()
