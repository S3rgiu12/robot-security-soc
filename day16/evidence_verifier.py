import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

INCIDENTS_FILE = PROJECT_DIR / "day09/data/incidents.json"
AVAILABILITY_LOG = PROJECT_DIR / "day08/logs/ids_availability.log"
REPORT_FILE = BASE_DIR / "data/evidence_verification.json"

SOURCE_PREFIX = "IDS_AVAILABILITY|"


def load_log_evidence(path):
    evidence = Counter()

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            content = line.rstrip("\r\n")

            if content:
                evidence[SOURCE_PREFIX + content] += 1

    return evidence


def verify_incident(incident, log_evidence):
    incident_id = incident.get("incident_id")
    event_keys = incident.get("event_keys", [])

    results = []
    findings = []

    if not isinstance(event_keys, list):
        event_keys = []
        findings.append("Invalid event_keys structure.")

    if not event_keys:
        findings.append("No event evidence linked.")

    seen = set()
    verified_events = []

    for key in event_keys:
        result = {
            "event_key": key,
            "status": "UNVERIFIABLE",
            "reason": None
        }

        if not isinstance(key, str):
            result["reason"] = "Evidence key is not a string."

        elif not key.startswith(SOURCE_PREFIX):
            result["reason"] = "Unsupported evidence source."

        elif key in seen:
            result["status"] = "MISMATCH"
            result["reason"] = "Duplicate evidence reference."

        elif log_evidence.get(key, 0) == 0:
            result["status"] = "MISSING"
            result["reason"] = "Evidence not found in source log."

        else:
            raw_line = key[len(SOURCE_PREFIX):]
            parts = raw_line.split(" | ", 2)

            if len(parts) != 3:
                result["status"] = "MISMATCH"
                result["reason"] = "Invalid log event format."

            else:
                timestamp, level, message = parts

                try:
                    event_time = datetime.strptime(
                        timestamp, "%Y-%m-%d %H:%M:%S"
                    )

                    if level not in ("OFFLINE", "RECOVERY"):
                        raise ValueError("Unsupported event type")

                    result["status"] = "VERIFIED"
                    result["reason"] = "Exact source log match."

                    verified_events.append({
                        "timestamp": event_time,
                        "level": level,
                        "message": message
                    })

                except ValueError:
                    result["status"] = "MISMATCH"
                    result["reason"] = "Invalid timestamp or event type."

        if isinstance(key, str):
            seen.add(key)

        results.append(result)

    if (
        len(verified_events) == 2
        and len(results) == 2
        and all(item["status"] == "VERIFIED" for item in results)
    ):
        first, second = verified_events

        if first["level"] != "OFFLINE":
            findings.append("First event is not OFFLINE.")

        if second["level"] != "RECOVERY":
            findings.append("Second event is not RECOVERY.")

        if second["timestamp"] < first["timestamp"]:
            findings.append("Recovery timestamp precedes outage.")

    if not results:
        verification_status = "UNVERIFIABLE"

    elif findings or any(
        item["status"] != "VERIFIED" for item in results
    ):
        verification_status = "REVIEW_REQUIRED"

    else:
        verification_status = "VERIFIED"

    return {
        "incident_id": incident_id,
        "operational_status": incident.get("status"),
        "verification_status": verification_status,
        "evidence_count": len(results),
        "verified_count": sum(
            item["status"] == "VERIFIED" for item in results
        ),
        "findings": findings,
        "evidence": results
    }


def build_report(incidents, log_evidence):
    results = [
        verify_incident(incident, log_evidence)
        for incident in incidents
    ]

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_log": str(
            AVAILABILITY_LOG.relative_to(PROJECT_DIR)
        ),
        "summary": {
            "total_incidents": len(results),
            "by_verification_status": dict(Counter(
                item["verification_status"]
                for item in results
            )),
            "total_evidence": sum(
                item["evidence_count"] for item in results
            ),
            "verified_evidence": sum(
                item["verified_count"] for item in results
            )
        },
        "incidents": results
    }


def main():
    incidents = json.loads(
        INCIDENTS_FILE.read_text(encoding="utf-8")
    )

    if not isinstance(incidents, list):
        raise SystemExit("Incident registry must be a JSON list.")

    log_evidence = load_log_evidence(AVAILABILITY_LOG)
    report = build_report(incidents, log_evidence)

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    REPORT_FILE.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("=== DAY 16 EVIDENCE VERIFICATION ===")
    print("Total incidents:",
          report["summary"]["total_incidents"])
    print("Evidence references:",
          report["summary"]["total_evidence"])
    print("Verified references:",
          report["summary"]["verified_evidence"])
    print("Incident verification:",
          report["summary"]["by_verification_status"])
    print("Report:", REPORT_FILE)

    for incident in report["incidents"]:
        if incident["verification_status"] != "VERIFIED":
            print(
                "[REVIEW]",
                incident["incident_id"],
                "|",
                incident["verification_status"],
                "|",
                incident["findings"]
            )


if __name__ == "__main__":
    main()
