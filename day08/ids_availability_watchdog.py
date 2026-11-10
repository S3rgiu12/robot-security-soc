
from pathlib import Path
from datetime import datetime
import sys
import time

BASE_DIR = Path(__file__).resolve().parent
DAY07_DIR = BASE_DIR.parent / "day07"

sys.path.insert(0, str(DAY07_DIR))

from heartbeat_reader import get_heartbeat_status

LOG_FILE = BASE_DIR / "logs" / "ids_availability.log"
CHECK_INTERVAL = 2


def write_event(level, message):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"{timestamp} | {level} | {message}"

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(entry + "\n")

    print(entry, flush=True)


def monitor_availability():
    print("=== ROBOT IDS AVAILABILITY WATCHDOG ===")
    print("Monitoring service: robot_ids_v3")
    print(f"Check interval: {CHECK_INTERVAL} seconds")
    print("Press Ctrl+C to stop.\n")

    previous_status = None

    try:
        while True:
            result = get_heartbeat_status()
            current_status = result["status"]
            reason = result["reason"]

            if previous_status is None:
                print(
                    f"Initial state: {current_status} ({reason})",
                    flush=True
                )

            elif previous_status == "ONLINE" and current_status == "OFFLINE":
                write_event(
                    "OFFLINE",
                    f"IDS v3 unavailable: {reason}"
                )

            elif previous_status == "OFFLINE" and current_status == "ONLINE":
                write_event(
                    "RECOVERY",
                    "IDS v3 heartbeat restored"
                )

            previous_status = current_status
            time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        print("\nAvailability watchdog stopped.")


if __name__ == "__main__":
    monitor_availability()
