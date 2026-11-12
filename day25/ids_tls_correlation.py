"""Correlate IDS V3 critical alerts with TLS security events."""

import re
from datetime import datetime, timedelta
from pathlib import Path

from day25.ids_evidence_validator import (
    ALERT_MARKER,
    create_ids_alert_id,
)

THRESHOLD = 3
TIME_WINDOW = 60

ALERT_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}\.\d{6})"
    r" \| CRITICAL \| "
    + re.escape(ALERT_MARKER)
    + r" Events: (\d+) within 60 seconds$"
)

EVENT_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2},\d{3})"
    r" \| WARNING \| SECURITY ALERT: "
    r"TLS certificate rejected: .+$"
)


def validate_tls_correlation(
    alert_id,
    alert_log_path,
    security_log_path,
):
    """Find a critical IDS alert and corroborating TLS events."""

    alert_path = Path(alert_log_path)
    security_path = Path(security_log_path)

    if not alert_path.is_file():
        raise ValueError("IDS alert log not found")

    if not security_path.is_file():
        raise ValueError("TLS security log not found")

    matched_alert = None

    for line in alert_path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines():
        if create_ids_alert_id(line) != alert_id:
            continue

        match = ALERT_PATTERN.fullmatch(line)

        if match is None:
            raise ValueError("Invalid IDS alert format")

        matched_alert = match
        break

    if matched_alert is None:
        raise ValueError("IDS alert not found")

    alert_time = datetime.strptime(
        matched_alert.group(1),
        "%Y-%m-%d %H:%M:%S.%f",
    )

    declared_count = int(matched_alert.group(2))

    if declared_count < THRESHOLD:
        raise ValueError("IDS threshold not reached")

    cutoff = alert_time - timedelta(seconds=TIME_WINDOW)
    events = []

    for line in security_path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines():
        match = EVENT_PATTERN.fullmatch(line)

        if match is None:
            continue

        event_time = datetime.strptime(
            match.group(1),
            "%Y-%m-%d %H:%M:%S,%f",
        )

        if cutoff <= event_time <= alert_time:
            events.append(line)

    if len(events) < THRESHOLD:
        raise ValueError(
            "Insufficient TLS events for IDS alert"
        )

    return {
        "alert_id": alert_id,
        "declared_events": declared_count,
        "correlated_events": len(events),
        "window_seconds": TIME_WINDOW,
        "status": "CORROBORATED",
    }
