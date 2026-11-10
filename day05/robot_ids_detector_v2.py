
from pathlib import Path
from collections import deque
from datetime import datetime, timedelta
import time

LOG_FILE = Path("logs/robot_security.log")
ALERT_FILE = Path("logs/robot_ids_alerts_v2.log")

THRESHOLD = 3
TIME_WINDOW = 60
CHECK_INTERVAL = 2

EVENT_MARKER = "TLS certificate rejected:"

recent_events = deque()
alert_active = False


def process_event(line):
    global alert_active

    if EVENT_MARKER not in line:
        return

    try:
        timestamp_text = line.split(" | ", 1)[0]
        timestamp = datetime.strptime(
            timestamp_text,
            "%Y-%m-%d %H:%M:%S,%f"
        )
    except ValueError:
        print("WARNING: Invalid timestamp")
        return

    recent_events.append(timestamp)

    cutoff = timestamp - timedelta(seconds=TIME_WINDOW)

    while recent_events and recent_events[0] < cutoff:
        recent_events.popleft()

    if len(recent_events) >= THRESHOLD:
        if not alert_active:
            alert_active = True

            message = (
                f"{timestamp} | CRITICAL | "
                f"Multiple TLS certificate rejections! "
                f"Events: {len(recent_events)} "
                f"within {TIME_WINDOW} seconds"
            )

            print("\nSECURITY ALERT!")
            print(message)

            ALERT_FILE.parent.mkdir(
                parents=True, exist_ok=True
            )

            with ALERT_FILE.open(
                "a", encoding="utf-8"
            ) as file:
                file.write(message + "\n")

    else:
        alert_active = False


def monitor_logs():
    print("=== ROBOT IDS V2 ===")
    print("Real-time monitoring enabled")
    print(f"Monitoring: {LOG_FILE}")
    print("Press CTRL+C to stop\n")

    if not LOG_FILE.exists():
        print("ERROR: Security log not found!")
        return

    with LOG_FILE.open("r", encoding="utf-8") as file:
        file.seek(0, 2)

        try:
            while True:
                line = file.readline()

                if line:
                    process_event(line)
                else:
                    time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            print("\nMonitoring stopped.")


if __name__ == "__main__":
    monitor_logs()
