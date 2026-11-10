from datetime import timezone
import json
from pathlib import Path
from collections import deque
from datetime import datetime, timedelta
import time

LOG_FILE = Path("logs/robot_security.log")
ALERT_FILE = Path("logs/robot_ids_alerts_v3.log")

THRESHOLD = 3
TIME_WINDOW = 60
CHECK_INTERVAL = 2

HEARTBEAT_INTERVAL = 5

HEARTBEAT_FILE = (
    Path(__file__).resolve().parent.parent
    / "day07"
    / "logs"
    / "ids_heartbeat.json"
)

EVENT_MARKER = "TLS certificate rejected:"

recent_events = deque()
alert_active = False


def write_alert(level, message):
    timestamp = datetime.now()

    entry = (
        f"{timestamp} | {level} | {message}"
    )

    print(entry, flush=True)

    ALERT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with ALERT_FILE.open(
        "a", encoding="utf-8"
    ) as file:
        file.write(entry + "\n")


def check_recovery():
    global alert_active

    now = datetime.now()
    cutoff = now - timedelta(seconds=TIME_WINDOW)

    while recent_events and recent_events[0] < cutoff:
        recent_events.popleft()

    if alert_active and not recent_events:
        alert_active = False

        write_alert(
            "RECOVERY",
            "TLS certificate rejection activity stopped. "
            "IDS returned to NORMAL."
        )

        print("STATUS: NORMAL\n", flush=True)


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

    # Ignore events outside the current monitoring window.
    now = datetime.now()
    if timestamp < now - timedelta(seconds=TIME_WINDOW):
        return

    if timestamp > now + timedelta(seconds=5):
        print("WARNING: Future timestamp ignored")
        return

    recent_events.append(timestamp)

    check_recovery()

    if len(recent_events) >= THRESHOLD and not alert_active:
        alert_active = True

        write_alert(
            "CRITICAL",
            "Multiple TLS certificate rejections detected! "
            f"Events: {len(recent_events)} "
            f"within {TIME_WINDOW} seconds"
        )

        print("STATUS: CRITICAL\n", flush=True)

def write_heartbeat():
    heartbeat = {
        "service": "robot_ids_v3",
        "timestamp": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        )
    }

    HEARTBEAT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    temporary_file = HEARTBEAT_FILE.with_suffix(".tmp")

    temporary_file.write_text(
        json.dumps(heartbeat, indent=4),
        encoding="utf-8"
    )

    temporary_file.replace(HEARTBEAT_FILE)


def monitor_logs():
    print("=== ROBOT IDS V3 ===")
    print("Real-time monitoring enabled")
    print("Alert deduplication: ENABLED")
    print("Automatic recovery: ENABLED")
    print(f"Monitoring: {LOG_FILE}")
    print("Press CTRL+C to stop\n")

    if not LOG_FILE.exists():
        print("ERROR: Security log not found!")
        return

    
    with LOG_FILE.open("r", encoding="utf-8") as file:
        file.seek(0, 2)

        last_heartbeat = 0

        try:
            while True:
                now = time.monotonic()

                if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                    write_heartbeat()
                    last_heartbeat = now

                line = file.readline()

                if line:
                    process_event(line)
                else:
                    check_recovery()
                    time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            print("\nMonitoring stopped.")

if __name__ == "__main__":
    monitor_logs()

