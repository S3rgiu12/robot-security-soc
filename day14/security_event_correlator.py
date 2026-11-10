import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INPUT = ROOT / "day14/data/normalized_events.json"
OUTPUT = ROOT / "day14/data/correlated_incidents.json"

RECOVERY_WINDOW_SECONDS = 60

def parse_time(event):
    return datetime.fromisoformat(
        event["timestamp_utc"].replace("Z", "+00:00")
    )

def incident_id(kind, events):
    ids = sorted(e["event_id"] for e in events)
    raw = kind + "|" + "|".join(ids)
    return hashlib.sha256(raw.encode()).hexdigest()[:20]

def build_incident(kind, events, status, severity):
    events = sorted(events, key=parse_time)
    start = parse_time(events[0])
    end = parse_time(events[-1])

    return {
        "incident_id": incident_id(kind, events),
        "incident_type": kind,
        "service": events[0]["service"],
        "status": status,
        "severity": severity,
        "started_at_utc": start.isoformat(),
        "ended_at_utc": end.isoformat(),
        "duration_seconds": round(
            (end - start).total_seconds(), 3
        ),
        "simulated": any(
            e.get("simulated", False) for e in events
        ),
        "event_ids": [e["event_id"] for e in events],
        "evidence": [
            {
                "event_id": e["event_id"],
                "timestamp_utc": e["timestamp_utc"],
                "event_type": e["event_type"],
                "source": e["source"],
                "source_file": e["source_file"],
                "source_line": e.get("source_line"),
                "source_record_id": e.get("source_record_id")
            }
            for e in events
        ]
    }

def correlate_availability(events):
    incidents = []
    pending = {}

    relevant = [
        e for e in events
        if e["source"] == "IDS_AVAILABILITY"
        and e["event_type"] in ("IDS_OFFLINE", "IDS_ONLINE")
    ]

    for event in sorted(relevant, key=parse_time):
        service = event["service"]
        kind = event["event_type"]

        if kind == "IDS_OFFLINE":
            if service in pending:
                incidents.append(build_incident(
                    "IDS_AVAILABILITY_INCIDENT",
                    [pending[service]],
                    "UNRESOLVED",
                    "WARNING"
                ))
            pending[service] = event

        elif kind == "IDS_ONLINE":
            if service not in pending:
                continue

            offline = pending.pop(service)

            if offline.get("simulated") != event.get("simulated"):
                incidents.append(build_incident(
                    "IDS_AVAILABILITY_INCIDENT",
                    [offline],
                    "UNRESOLVED",
                    "WARNING"
                ))
                continue

            duration = (
                parse_time(event) - parse_time(offline)
            ).total_seconds()

            severity = (
                "CRITICAL" if duration >= 3600
                else "WARNING"
            )

            incidents.append(build_incident(
                "IDS_AVAILABILITY_INCIDENT",
                [offline, event],
                "RESTORED",
                severity
            ))

    for offline in pending.values():
        incidents.append(build_incident(
            "IDS_AVAILABILITY_INCIDENT",
            [offline],
            "UNRESOLVED",
            "WARNING"
        ))

    return incidents

def correlate_recovery(events):
    incidents = []
    pending = {}

    recovery_types = {
        "STARTING", "STARTED", "RECOVERED"
    }

    relevant = [
        e for e in events
        if e["source"] == "RECOVERY_CONTROLLER"
        and e["event_type"] in recovery_types
        and e["source_file"] == "day11/logs/recovery.log"
    ]

    for event in sorted(relevant, key=parse_time):
        service = event["service"]
        kind = event["event_type"]

        if kind == "STARTING":
            if service in pending:
                incidents.append(build_incident(
                    "IDS_RECOVERY_INCIDENT",
                    pending[service]["events"],
                    "INCOMPLETE",
                    "WARNING"
                ))

            pending[service] = {
                "events": [event],
                "stage": "STARTING"
            }
            continue

        attempt = pending.get(service)

        if not attempt:
            continue

        first = attempt["events"][0]

        elapsed = (
            parse_time(event) - parse_time(first)
        ).total_seconds()

        if (
            elapsed < 0
            or elapsed > RECOVERY_WINDOW_SECONDS
            or event.get("simulated") != first.get("simulated")
        ):
            incidents.append(build_incident(
                "IDS_RECOVERY_INCIDENT",
                attempt["events"],
                "INCOMPLETE",
                "WARNING"
            ))
            pending.pop(service, None)
            continue

        if kind == "STARTED" and attempt["stage"] == "STARTING":
            attempt["events"].append(event)
            attempt["stage"] = "STARTED"

        elif kind == "RECOVERED" and attempt["stage"] == "STARTED":
            attempt["events"].append(event)

            incidents.append(build_incident(
                "IDS_RECOVERY_INCIDENT",
                attempt["events"],
                "RECOVERED",
                "INFO"
            ))

            pending.pop(service, None)

    for attempt in pending.values():
        incidents.append(build_incident(
            "IDS_RECOVERY_INCIDENT",
            attempt["events"],
            "INCOMPLETE",
            "WARNING"
        ))

    return incidents

def correlate_blocked(events):
    incidents = []

    blocked = [
        e for e in events
        if e["event_type"] == "BLOCKED"
        and e["source_file"] == "day11/logs/recovery.log"
    ]

    for event in blocked:
        incidents.append(build_incident(
            "IDS_RECOVERY_BLOCKED",
            [event],
            "BLOCKED",
            "CRITICAL"
        ))

    return incidents

def main():
    events = json.loads(INPUT.read_text(encoding="utf-8"))

    ids = [e["event_id"] for e in events]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate normalized event IDs")

    incidents = (
        correlate_availability(events)
        + correlate_recovery(events)
        + correlate_blocked(events)
    )

    incidents.sort(
        key=lambda i: (
            i["started_at_utc"],
            i["incident_id"]
        )
    )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(incidents, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("=== DAY 14 SECURITY EVENT CORRELATOR ===")
    print("Input events:", len(events))
    print("Correlated incidents:", len(incidents))

    for kind in sorted(set(
        i["incident_type"] for i in incidents
    )):
        count = sum(
            i["incident_type"] == kind for i in incidents
        )
        print(f"{kind}: {count}")

    print("Simulated incidents:", sum(
        i["simulated"] for i in incidents
    ))
    print("Output:", OUTPUT)

if __name__ == "__main__":
    main()
