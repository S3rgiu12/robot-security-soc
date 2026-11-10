
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from sys import path as python_path

PROJECT_DIR = Path.home() / "cybersecurity"
DAY07_DIR = PROJECT_DIR / "day07"

python_path.insert(0, str(DAY07_DIR))

from heartbeat_reader import get_heartbeat_status

IDS_SCRIPT = (
    PROJECT_DIR / "day05/robot_ids_detector_v3.py"
).resolve()

OUTPUT_FILE = (
    PROJECT_DIR / "day11/data/ids_process_status.json"
)


def find_ids_processes():
    processes = []

    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue

        pid = int(entry.name)

        try:
            raw = (entry / "cmdline").read_bytes()
            arguments = [
                arg.decode("utf-8", errors="replace")
                for arg in raw.split(b"\0")
                if arg
            ]

            if not arguments:
                continue

            # Only inspect Python processes.
            executable = Path(arguments[0]).name.lower()

            if "python" not in executable:
                continue

            for arg in arguments[1:]:
                if Path(arg).name != IDS_SCRIPT.name:
                    continue

                candidate = Path(arg)

                if not candidate.is_absolute():
                    cwd = (entry / "cwd").resolve()
                    candidate = cwd / candidate

                if candidate.resolve() == IDS_SCRIPT:
                    processes.append(pid)
                    break

        except (OSError, PermissionError):
            continue

    return sorted(processes)


def monitor_ids():
    pids = find_ids_processes()
    heartbeat = get_heartbeat_status()

    process_running = len(pids) > 0
    heartbeat_online = heartbeat["status"] == "ONLINE"

    if process_running and heartbeat_online:
        state = "HEALTHY"
    elif process_running and not heartbeat_online:
        state = "DEGRADED"
    elif not process_running and heartbeat_online:
        state = "INCONSISTENT"
    else:
        state = "OFFLINE"

    result = {
        "checked_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "service": "robot_ids_v3",
        "state": state,
        "process_running": process_running,
        "process_pids": pids,
        "heartbeat_status": heartbeat["status"],
        "heartbeat_reason": heartbeat["reason"],
        "heartbeat_age_seconds": heartbeat.get(
            "age_seconds"
        )
    }

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    temporary_file = OUTPUT_FILE.with_suffix(".tmp")

    with temporary_file.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=4)

    os.replace(temporary_file, OUTPUT_FILE)

    return result


if __name__ == "__main__":
    status = monitor_ids()

    print("=== ROBOT IDS PROCESS MONITOR V1 ===")
    print("Service:", status["service"])
    print("State:", status["state"])
    print("Process running:", status["process_running"])
    print("Process PIDs:", status["process_pids"])
    print("Heartbeat:", status["heartbeat_status"])
    print("Reason:", status["heartbeat_reason"])
