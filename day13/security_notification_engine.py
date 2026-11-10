
import json
import os
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

ALERTS_FILE = BASE_DIR / "data/security_alerts_snapshot.json"
MANAGEMENT_FILE = BASE_DIR / "data/alert_management.json"
NOTIFICATIONS_FILE = BASE_DIR / "data/notifications.json"
NOTIFICATION_LOG = BASE_DIR / "logs/security_notifications.log"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_json(path, default):
    if not path.exists():
        return default

    with path.open(encoding="utf-8") as file:
        return json.load(file)


def save_json_atomic(path, data):
    temp_path = path.with_suffix(".tmp")

    with temp_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)
        file.flush()
        os.fsync(file.fileno())

    os.replace(temp_path, path)


def generate_notifications():
    alerts = load_json(ALERTS_FILE, [])
    management = load_json(MANAGEMENT_FILE, [])
    notifications = load_json(NOTIFICATIONS_FILE, [])

    status_by_id = {
        record["alert_id"]: record["status"]
        for record in management
    }

    notified_ids = {
        notification["alert_id"]
        for notification in notifications
    }

    new_notifications = []

    for alert in alerts:
        alert_id = alert["alert_id"]

        if alert["severity"] != "CRITICAL":
            continue

        if status_by_id.get(alert_id) != "NEW":
            continue

        if alert_id in notified_ids:
            continue

        notification = {
            "notification_id": f"NOTIF-{alert_id}",
            "alert_id": alert_id,
            "severity": alert["severity"],
            "type": alert["type"],
            "message": alert["message"],
            "created_at_utc": utc_now(),
            "delivery_channel": "LOCAL",
            "delivery_status": "GENERATED"
        }

        notifications.append(notification)
        new_notifications.append(notification)
        notified_ids.add(alert_id)

    if new_notifications:
        save_json_atomic(NOTIFICATIONS_FILE, notifications)

        with NOTIFICATION_LOG.open("a", encoding="utf-8") as log:
            for notification in new_notifications:
                log.write(
                    f"{notification['created_at_utc']} | "
                    f"CRITICAL | "
                    f"{notification['alert_id']} | "
                    f"{notification['type']}\n"
                )

    return notifications, new_notifications


def main():
    notifications, new_notifications = generate_notifications()

    print("=== SECURITY NOTIFICATION ENGINE V1 ===")
    print("Total notifications:", len(notifications))
    print("New notifications:", len(new_notifications))

    for notification in new_notifications:
        print(
            "[CRITICAL]",
            notification["type"],
            "|",
            notification["message"]
        )

    print("Result: SUCCESS")


if __name__ == "__main__":
    main()
