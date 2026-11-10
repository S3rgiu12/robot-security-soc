
import json
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
import fcntl
from ids_process_monitor import monitor_ids

BASE_DIR = Path(__file__).resolve().parent
IDS_DIR = BASE_DIR.parent / "day05"
IDS_SCRIPT = IDS_DIR / "robot_ids_detector_v3.py"

LOG_FILE = BASE_DIR / "logs/recovery.log"
STATE_FILE = BASE_DIR / "data/recovery_state.json"
CONTROLLER_LOCK_FILE = (
    BASE_DIR / "data/recovery_controller.lock"
)
PROCESS_LOG = BASE_DIR / "logs/recovered_ids.log"

MAX_ATTEMPTS = 3
WINDOW_MINUTES = 10
HEALTH_TIMEOUT = 25


def utc_now():
    return datetime.now(timezone.utc)


def log_event(message):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    line = f"{utc_now().isoformat()} | {message}"

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(line + "\n")

    print(line)


def load_attempts():
    if not STATE_FILE.exists():
        return []

    with STATE_FILE.open(encoding="utf-8") as file:
        data = json.load(file)

    cutoff = utc_now() - timedelta(minutes=WINDOW_MINUTES)

    attempts = []

    for value in data.get("attempts", []):
        timestamp = datetime.fromisoformat(value)

        if timestamp >= cutoff:
            attempts.append(timestamp)

    return attempts


def save_attempts(attempts):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

    with STATE_FILE.open("w", encoding="utf-8") as file:
        json.dump({
            "attempts": [item.isoformat() for item in attempts]
        }, file, indent=4)


def recover_ids():
    CONTROLLER_LOCK_FILE.parent.mkdir(
        parents=True, exist_ok=True
    )

    with CONTROLLER_LOCK_FILE.open("a+") as lock:
        try:
            fcntl.flock(
                lock.fileno(),
                fcntl.LOCK_EX | fcntl.LOCK_NB
            )
        except BlockingIOError:
            log_event(
                "BLOCKED | Another recovery is already running"
            )
            return False

        return _recover_ids_unlocked()


def _recover_ids_unlocked():
    print("=== ROBOT IDS AUTOMATIC RECOVERY CONTROLLER V1 ===")

    status = monitor_ids()
    print("Initial state:", status["state"])

    if status["process_running"]:
        log_event(
            "SKIPPED | IDS process already running; "
            "no automatic restart"
        )
        return status["state"] == "HEALTHY"

    # Allow restart only when the process is absent.
    if status["state"] not in ("OFFLINE", "INCONSISTENT"):
        log_event("SKIPPED | Unexpected monitor state")
        return False

    if not IDS_SCRIPT.is_file():
        log_event("FAILED | IDS script not found")
        return False

    attempts = load_attempts()

    if len(attempts) >= MAX_ATTEMPTS:
        log_event("BLOCKED | Recovery attempt limit reached")
        return False

    attempts.append(utc_now())
    save_attempts(attempts)

    log_event(
        f"STARTING | Recovery attempt "
        f"{len(attempts)}/{MAX_ATTEMPTS}"
    )

    PROCESS_LOG.parent.mkdir(parents=True, exist_ok=True)

    with PROCESS_LOG.open("a", encoding="utf-8") as output:
        process = subprocess.Popen(
            [sys.executable, "-u", str(IDS_SCRIPT)],
            cwd=str(IDS_DIR),
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True
        )

    log_event(f"STARTED | IDS PID={process.pid}")

    deadline = time.monotonic() + HEALTH_TIMEOUT

    while time.monotonic() < deadline:
        time.sleep(2)

        status = monitor_ids()

        if status["state"] == "HEALTHY":
            log_event(
                f"RECOVERED | IDS HEALTHY | PID={process.pid}"
            )
            return True

        if process.poll() is not None:
            log_event(
                f"FAILED | IDS exited with code "
                f"{process.returncode}"
            )
            return False

    log_event(
        f"FAILED | IDS did not become HEALTHY "
        f"within {HEALTH_TIMEOUT} seconds"
    )
    return False

if __name__ == "__main__":
    try:
        success = recover_ids()

        print(
            "Recovery result:",
            "SUCCESS" if success else "FAILED"
        )

        sys.exit(0 if success else 1)

    except Exception as error:
        log_event(
            f"ERROR | {type(error).__name__}: {error}"
        )
        sys.exit(1)
