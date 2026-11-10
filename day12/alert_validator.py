
import json
import hashlib
from collections import Counter
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ALERT_FILE = BASE_DIR / "data/security_alerts.json"

VALID_SEVERITIES = {"INFO", "WARNING", "CRITICAL"}
VALID_SOURCES = {
    "RECOVERY_CONTROLLER",
    "RECOVERY_SUPERVISOR",
    "IDS_AVAILABILITY",
}

REQUIRED_FIELDS = {
    "alert_id",
    "source",
    "type",
    "severity",
    "event",
    "message",
    "event_timestamp",
    "detected_at_utc",
    "event_key",
}


def validate_alerts():
    with ALERT_FILE.open(encoding="utf-8") as file:
        alerts = json.load(file)

    if not isinstance(alerts, list):
        raise ValueError("Alert registry must be a list")

    errors = []
    ids = set()
    event_keys = set()

    for index, alert in enumerate(alerts, start=1):
        if not isinstance(alert, dict):
            errors.append(f"Alert {index}: invalid object")
            continue

        missing = REQUIRED_FIELDS - alert.keys()

        if missing:
            errors.append(
                f"Alert {index}: missing {sorted(missing)}"
            )
            continue

        if alert["severity"] not in VALID_SEVERITIES:
            errors.append(
                f"Alert {index}: invalid severity"
            )

        if alert["source"] not in VALID_SOURCES:
            errors.append(
                f"Alert {index}: invalid source"
            )

        if alert["alert_id"] in ids:
            errors.append(
                f"Alert {index}: duplicate alert ID"
            )

        if alert["event_key"] in event_keys:
            errors.append(
                f"Alert {index}: duplicate event key"
            )

        ids.add(alert["alert_id"])
        event_keys.add(alert["event_key"])

        expected_id = hashlib.sha256(
            alert["event_key"].encode("utf-8")
        ).hexdigest()[:16]

        if alert["alert_id"] != expected_id:
            errors.append(
                f"Alert {index}: incorrect alert ID"
            )

        try:
            datetime.fromisoformat(
                alert["event_timestamp"]
            )
            detected = datetime.fromisoformat(
                alert["detected_at_utc"]
            )
            if detected.tzinfo is None:
                raise ValueError("UTC timezone missing")
        except (ValueError, TypeError):
            errors.append(
                f"Alert {index}: invalid timestamp"
            )

    counts = Counter(
        alert.get("severity")
        for alert in alerts
        if isinstance(alert, dict)
    )

    print("=== SECURITY ALERT REGISTRY VALIDATOR ===")
    print("Total alerts:", len(alerts))
    print("CRITICAL:", counts["CRITICAL"])
    print("WARNING:", counts["WARNING"])
    print("INFO:", counts["INFO"])
    print("Validation errors:", len(errors))

    for error in errors:
        print("[ERROR]", error)

    if errors:
        print("Final status: VALIDATION FAILED")
        return False

    print("Final status: VALIDATION PASSED")
    return True


if __name__ == "__main__":
    raise SystemExit(0 if validate_alerts() else 1)
