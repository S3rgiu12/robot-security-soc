
from pathlib import Path
from datetime import datetime, timezone
import json
import time

BASE_DIR = Path(__file__).resolve().parent
HEARTBEAT_FILE = BASE_DIR / "logs" / "ids_heartbeat.json"

INTERVAL_SECONDS = 5


def write_heartbeat():
    timestamp = datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )

    heartbeat = {
        "service": "robot_ids_v3_simulator",
        "timestamp": timestamp
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

    print(f"[HEARTBEAT] {timestamp}")


def main():
    print("=== ROBOT IDS HEARTBEAT SIMULATOR ===")
    print(f"Interval: {INTERVAL_SECONDS} seconds")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            write_heartbeat()
            time.sleep(INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("\nHeartbeat simulator stopped.")


if __name__ == "__main__":
    main()
