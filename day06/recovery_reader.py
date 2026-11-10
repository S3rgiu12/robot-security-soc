
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

DAY11_DIR = Path.home() / "cybersecurity/day11"
STATE_FILE = DAY11_DIR / "data/recovery_state.json"
RECOVERY_LOG = DAY11_DIR / "logs/recovery.log"
SUPERVISOR_LOG = DAY11_DIR / "logs/recovery_supervisor.log"
PROCESS_STATUS_FILE = DAY11_DIR / "data/ids_process_status.json"

# Day 13: IDS process status freshness
if str(DAY11_DIR) not in sys.path:
    sys.path.insert(0, str(DAY11_DIR))

from ids_status_freshness import get_ids_status_freshness

MAX_ATTEMPTS = 3
WINDOW_MINUTES = 10


def read_json(path, default):
    try:
        with path.open(encoding="utf-8") as file:
            return json.load(file)
    except (OSError, ValueError):
        return default


def get_recovery_summary():
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=WINDOW_MINUTES)

    state = read_json(STATE_FILE, {"attempts": []})
    attempts = []

    for value in state.get("attempts", []):
        try:
            timestamp = datetime.fromisoformat(value)
            if timestamp.tzinfo is None:
                continue
            if timestamp >= cutoff:
                attempts.append(timestamp)
        except (TypeError, ValueError):
            continue

    process = read_json(PROCESS_STATUS_FILE, {})

    freshness = get_ids_status_freshness()

    last_recovery = None

    if RECOVERY_LOG.exists():
        for line in RECOVERY_LOG.read_text(
            encoding="utf-8"
        ).splitlines():
            if " | RECOVERED | " in line:
                last_recovery = {
                    "timestamp": line.split(" | ", 1)[0],
                    "result": "SUCCESS",
                    "message": line
                }
            elif " | FAILED | " in line:
                last_recovery = {
                    "timestamp": line.split(" | ", 1)[0],
                    "result": "FAILED",
                    "message": line
                }

    supervisor_last_check = None

    if SUPERVISOR_LOG.exists():
        for line in SUPERVISOR_LOG.read_text(
            encoding="utf-8"
        ).splitlines():
            if " | CHECK | " in line:
                supervisor_last_check = line.split(" | ", 1)[0]

    return {
        "service": "robot_ids_v3",
        "process_state": process.get("state", "UNKNOWN"),
        "status_freshness": freshness["freshness"],
        "status_age_seconds": freshness["age_seconds"],
        "status_reason": freshness["reason"],
        "attempts_used": len(attempts),
        "attempts_limit": MAX_ATTEMPTS,
        "window_minutes": WINDOW_MINUTES,
        "restart_blocked": len(attempts) >= MAX_ATTEMPTS,
        "last_recovery": last_recovery,
        "supervisor_last_check": supervisor_last_check,
        "generated_at_utc": now.isoformat()
    }


if __name__ == "__main__":
    print(json.dumps(
        get_recovery_summary(),
        indent=4
    ))
