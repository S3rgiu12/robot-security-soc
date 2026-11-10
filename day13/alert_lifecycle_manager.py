
import argparse
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REGISTRY = BASE_DIR / "data/alert_management.json"
AUDIT_LOG = BASE_DIR / "logs/alert_actions.jsonl"

VALID_STATES = {"NEW", "ACKNOWLEDGED", "RESOLVED"}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_records():
    with REGISTRY.open(encoding="utf-8") as file:
        records = json.load(file)

    if not isinstance(records, list):
        raise ValueError("Invalid alert management registry")

    return records


def save_records(records):
    REGISTRY.parent.mkdir(parents=True, exist_ok=True)

    fd, temp_path = tempfile.mkstemp(
        dir=REGISTRY.parent,
        prefix=".alert_management_",
        suffix=".tmp"
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(records, file, indent=4, ensure_ascii=False)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_path, REGISTRY)

    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def write_audit(action, alert_id, old_status, new_status):
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

    event = {
        "timestamp_utc": utc_now(),
        "action": action,
        "alert_id": alert_id,
        "old_status": old_status,
        "new_status": new_status,
    }

    with AUDIT_LOG.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


def update_alert(alert_id, action, note=None):
    records = load_records()

    matches = [
        record for record in records
        if record["alert_id"] == alert_id
    ]

    if len(matches) != 1:
        raise ValueError(
            "Alert not found or duplicate alert ID"
        )

    record = matches[0]
    old_status = record["status"]

    if old_status not in VALID_STATES:
        raise ValueError("Invalid current status")

    if old_status == "RESOLVED":
        raise ValueError("Resolved alerts cannot be modified")

    if action == "acknowledge":
        if old_status != "NEW":
            raise ValueError("Only NEW alerts can be acknowledged")

        record["status"] = "ACKNOWLEDGED"
        record["acknowledged_at_utc"] = utc_now()

    elif action == "resolve":
        if old_status != "ACKNOWLEDGED":
            raise ValueError(
                "Alert must be acknowledged before resolution"
            )

        if not note or not note.strip():
            raise ValueError("Resolution note is required")

        record["status"] = "RESOLVED"
        record["resolved_at_utc"] = utc_now()
        record["resolution_note"] = note.strip()

    else:
        raise ValueError("Unknown action")

    save_records(records)

    write_audit(
        action,
        alert_id,
        old_status,
        record["status"]
    )

    return record


def main():
    parser = argparse.ArgumentParser(
        description="Robot Security Alert Lifecycle Manager"
    )

    parser.add_argument(
        "action",
        choices=["list", "acknowledge", "resolve"]
    )

    parser.add_argument("--id", dest="alert_id")
    parser.add_argument("--note")

    args = parser.parse_args()

    if args.action == "list":
        for record in load_records():
            print(
                record["alert_id"],
                record["severity"],
                record["status"],
                record["type"]
            )
        return

    if not args.alert_id:
        parser.error("--id is required")

    try:
        result = update_alert(
            args.alert_id,
            args.action,
            args.note
        )

        print("=== ALERT LIFECYCLE MANAGER ===")
        print("Alert ID:", result["alert_id"])
        print("Severity:", result["severity"])
        print("Status:", result["status"])
        print("Action:", args.action.upper())
        print("Result: SUCCESS")

    except ValueError as error:
        print("Result: FAILED")
        print("Reason:", error)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
