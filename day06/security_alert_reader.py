
import json
from collections import Counter
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ALERT_FILE = BASE_DIR.parent / "day12/data/security_alerts.json"

VALID_SEVERITIES = {"INFO", "WARNING", "CRITICAL"}


def get_security_alerts(severity=None, limit=100):
    if severity:
        severity = severity.upper()

        if severity not in VALID_SEVERITIES:
            raise ValueError("Invalid severity")

    if not isinstance(limit, int) or not 1 <= limit <= 1000:
        raise ValueError("Limit must be between 1 and 1000")

    if not ALERT_FILE.exists():
        alerts = []
    else:
        with ALERT_FILE.open(encoding="utf-8") as file:
            alerts = json.load(file)

        if not isinstance(alerts, list):
            raise ValueError("Invalid alert registry")

    counts = Counter(
        alert.get("severity")
        for alert in alerts
    )

    filtered = [
        alert for alert in alerts
        if severity is None or alert.get("severity") == severity
    ]

    filtered.sort(
        key=lambda alert: alert.get("event_timestamp", ""),
        reverse=True
    )

    return {
        "status": "OK",
        "total_alerts": len(alerts),
        "summary": {
            "CRITICAL": counts["CRITICAL"],
            "WARNING": counts["WARNING"],
            "INFO": counts["INFO"],
        },
        "filtered_total": len(filtered),
        "returned": min(len(filtered), limit),
        "alerts": filtered[:limit],
    }
