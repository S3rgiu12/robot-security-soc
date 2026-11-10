from datetime import datetime
from pathlib import Path
import hashlib
import re


ROOT = Path(__file__).resolve().parents[1]

SYNTHETIC_LOG = (
    ROOT / "day21/data/simulated_security_events.log"
)

REAL_IDS_LOG = (
    ROOT / "day05/logs/robot_security.log"
)

VALID_LEVELS = {
    "DEBUG",
    "INFO",
    "WARNING",
    "ERROR",
    "CRITICAL",
}

TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S",
)


def parse_timestamp(value):
    value = value.strip()

    for timestamp_format in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(
                value,
                timestamp_format
            )
        except ValueError:
            continue

    return None


def create_event_id(source, line_number, raw_line):
    payload = (
        f"{source}|{line_number}|{raw_line}"
    )

    digest = hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()[:16].upper()

    return f"EVT-{digest}"


def parse_security_event(
    line,
    line_number,
    source
):
    raw_line = line.rstrip("\r\n")

    if not raw_line.strip():
        return None

    parts = raw_line.split(" | ", 2)

    timestamp = None
    level = "UNKNOWN"
    message = raw_line.strip()

    if len(parts) == 3:
        timestamp = parse_timestamp(parts[0])

        candidate_level = parts[1].strip().upper()

        if candidate_level in VALID_LEVELS:
            level = candidate_level

        message = parts[2].strip()

    event_id = create_event_id(
        source,
        line_number,
        raw_line
    )

    return {
        "event_id": event_id,
        "source": source,
        "line_number": line_number,
        "timestamp": (
            timestamp.isoformat(
                timespec="milliseconds"
            )
            if timestamp else None
        ),
        "timestamp_available": timestamp is not None,
        "level": level,
        "message": message,
        "evidence": raw_line,
        "classification": (
            "POTENTIAL_SECURITY_EVENT"
            if level in {
                "WARNING",
                "ERROR",
                "CRITICAL"
            }
            else "OBSERVATION"
        ),
    }


def analyze_log(log_path):
    path = Path(log_path).resolve()

    if not path.is_file():
        raise FileNotFoundError(
            f"Log file not found: {path}"
        )

    events = []

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace"
    ) as file:
        for line_number, line in enumerate(
            file,
            start=1
        ):
            event = parse_security_event(
                line,
                line_number,
                str(path)
            )

            if event is not None:
                events.append(event)

    events.sort(
        key=lambda event: (
            event["timestamp"] is None,
            event["timestamp"] or "",
            event["line_number"]
        )
    )

    return {
        "status": "OK",
        "source": str(path),
        "total_events": len(events),
        "potential_security_events": sum(
            event["classification"]
            == "POTENTIAL_SECURITY_EVENT"
            for event in events
        ),
        "unknown_timestamps": sum(
            not event["timestamp_available"]
            for event in events
        ),
        "timeline": events,
    }


if __name__ == "__main__":
    for name, log in (
        ("SYNTHETIC", SYNTHETIC_LOG),
        ("REAL_IDS", REAL_IDS_LOG),
    ):
        result = analyze_log(log)

        print(f"\n=== {name} THREAT HUNTING ===")
        print("Events:", result["total_events"])
        print(
            "Potential security events:",
            result["potential_security_events"]
        )
        print(
            "Unknown timestamps:",
            result["unknown_timestamps"]
        )

        for event in result["timeline"][:5]:
            print(
                event["timestamp"],
                event["level"],
                event["message"]
            )
