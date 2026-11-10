
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path

LOG_FILE = Path("logs/robot_security.log")
ALERT_FILE = Path("logs/robot_ids_alerts.log")

THRESHOLD = 3
TIME_WINDOW = 60

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S,%f"
CERTIFICATE_EVENT = "TLS certificate rejected:"


def detect_tls_attacks():
    print("=== ROBOT INTRUSION DETECTION SYSTEM V1 ===")

    if not LOG_FILE.exists():
        print("ERROR: Security log not found!")
        return

    events = []

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            if CERTIFICATE_EVENT not in line:
                continue

            try:
                timestamp_text = line.split(" | ", 1)[0]
                timestamp = datetime.strptime(
                    timestamp_text, TIMESTAMP_FORMAT
                )
                events.append(timestamp)
            except ValueError:
                print("WARNING: Invalid log timestamp")

    events.sort()
    recent_events = deque()
    alert_count = 0

    for timestamp in events:
        recent_events.append(timestamp)

        while (
            recent_events
            and timestamp - recent_events[0]
            > timedelta(seconds=TIME_WINDOW)
        ):
            recent_events.popleft()

        
        if len(recent_events) == THRESHOLD:
            alert_count += 1

            alert_message = (
                f"{timestamp} | CRITICAL | "
                f"Multiple TLS certificate rejections detected! "
                f"Events: {len(recent_events)} "
                f"within {TIME_WINDOW} seconds"
            )

            print("\nSECURITY ALERT!")
            print(alert_message)

            ALERT_FILE.parent.mkdir(
                parents=True, exist_ok=True
            )

            with ALERT_FILE.open(
                "a", encoding="utf-8"
            ) as alert_log:
                alert_log.write(alert_message + "\n")


if __name__ == "__main__":
    detect_tls_attacks()
