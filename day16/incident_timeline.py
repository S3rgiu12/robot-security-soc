import json
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

VERIFICATION_FILE = (
    BASE_DIR / "data/evidence_verification.json"
)

TIMELINE_FILE = (
    BASE_DIR / "data/incident_timelines.json"
)

SOURCE_PREFIX = "IDS_AVAILABILITY|"


def parse_verified_event(evidence):
    if evidence.get("status") != "VERIFIED":
        return None

    key = evidence.get("event_key")

    if not isinstance(key, str):
        return None

    if not key.startswith(SOURCE_PREFIX):
        return None

    raw = key[len(SOURCE_PREFIX):]
    parts = raw.split(" | ", 2)

    if len(parts) != 3:
        return None

    timestamp, event_type, message = parts

    try:
        event_time = datetime.strptime(
            timestamp, "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        return None

    if event_type not in ("OFFLINE", "RECOVERY"):
        return None

    return {
        "timestamp": timestamp,
        "datetime": event_time,
        "event_type": event_type,
        "message": message
    }


def reconstruct_timeline(incident):
    events = []

    for evidence in incident.get("evidence", []):
        event = parse_verified_event(evidence)

        if event is not None:
            events.append(event)

    events.sort(
        key=lambda item: (
            item["datetime"],
            0 if item["event_type"] == "OFFLINE" else 1
        )
    )

    findings = []

    if incident.get("verification_status") != "VERIFIED":
        findings.append(
            "Evidence verification is incomplete."
        )

    offline_events = [
        event for event in events
        if event["event_type"] == "OFFLINE"
    ]

    recovery_events = [
        event for event in events
        if event["event_type"] == "RECOVERY"
    ]

    duration_seconds = None
    timeline_status = "INCOMPLETE"

    if (
        incident.get("verification_status") == "VERIFIED"
        and len(events) == 2
        and len(offline_events) == 1
        and len(recovery_events) == 1
    ):
        offline = offline_events[0]
        recovery = recovery_events[0]

        if recovery["datetime"] >= offline["datetime"]:
            duration_seconds = int(
                (
                    recovery["datetime"]
                    - offline["datetime"]
                ).total_seconds()
            )
            timeline_status = "RECONSTRUCTED"
        else:
            findings.append(
                "Recovery precedes offline event."
            )
    elif events:
        findings.append(
            "Expected one OFFLINE and one RECOVERY event."
        )
    else:
        findings.append(
            "No verified events available."
        )

    clean_events = [
        {
            "timestamp": event["timestamp"],
            "event_type": event["event_type"],
            "message": event["message"]
        }
        for event in events
    ]

    return {
        "incident_id": incident.get("incident_id"),
        "operational_status": incident.get("operational_status"),
        "verification_status": incident.get(
            "verification_status"
        ),
        "timeline_status": timeline_status,
        "duration_seconds": duration_seconds,
        "events": clean_events,
        "findings": findings
    }


def build_timeline_report(verification_report):
    incidents = [
        reconstruct_timeline(incident)
        for incident in verification_report.get("incidents", [])
    ]

    return {
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "source_verification_report": str(
            VERIFICATION_FILE
        ),
        "summary": {
            "total_incidents": len(incidents),
            "reconstructed": sum(
                item["timeline_status"] == "RECONSTRUCTED"
                for item in incidents
            ),
            "incomplete": sum(
                item["timeline_status"] == "INCOMPLETE"
                for item in incidents
            )
        },
        "incidents": incidents
    }


def main():
    verification_report = json.loads(
        VERIFICATION_FILE.read_text(encoding="utf-8")
    )

    report = build_timeline_report(
        verification_report
    )

    TIMELINE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    TIMELINE_FILE.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    print("=== DAY 16 INCIDENT TIMELINES ===")
    print("Total incidents:",
          report["summary"]["total_incidents"])
    print("Reconstructed:",
          report["summary"]["reconstructed"])
    print("Incomplete:",
          report["summary"]["incomplete"])

    print()
    print("=== INCIDENT DURATIONS ===")

    for incident in report["incidents"]:
        print(
            incident["incident_id"],
            "|",
            incident["timeline_status"],
            "|",
            incident["duration_seconds"],
            "seconds"
            if incident["duration_seconds"] is not None
            else ""
        )

    print()
    print("Report:", TIMELINE_FILE)


if __name__ == "__main__":
    main()
