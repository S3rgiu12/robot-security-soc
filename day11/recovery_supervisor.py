
import fcntl
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from ids_process_monitor import monitor_ids
from ids_recovery_controller import recover_ids

BASE_DIR = Path(__file__).resolve().parent
LOCK_FILE = BASE_DIR / "data/recovery_supervisor.lock"
LOG_FILE = BASE_DIR / "logs/recovery_supervisor.log"

CHECK_INTERVAL = 10


def log(message):
    timestamp = datetime.now(timezone.utc).isoformat()
    line = f"{timestamp} | {message}"

    print(line, flush=True)

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(line + "\n")


def main():
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    with LOCK_FILE.open("a+") as lock:
        try:
            fcntl.flock(
                lock.fileno(),
                fcntl.LOCK_EX | fcntl.LOCK_NB
            )
        except BlockingIOError:
            print(
                "Another recovery supervisor is already running."
            )
            return 1

        log("SUPERVISOR_STARTED | Monitoring robot_ids_v3")

        try:
            while True:
                status = monitor_ids()
                state = status["state"]

                log(f"CHECK | IDS state={state}")

                if state == "HEALTHY":
                    pass

                elif state in ("OFFLINE", "INCONSISTENT"):
                    log("RECOVERY_REQUESTED | IDS process absent")

                    success = recover_ids()

                    if success:
                        log("RECOVERY_SUCCESS")
                    else:
                        log("RECOVERY_FAILED_OR_BLOCKED")

                elif state == "DEGRADED":
                    log(
                        "WARNING | IDS process running "
                        "but heartbeat unavailable"
                    )

                time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            log("SUPERVISOR_STOPPED | Manual shutdown")

    return 0


if __name__ == "__main__":
    sys.exit(main())
