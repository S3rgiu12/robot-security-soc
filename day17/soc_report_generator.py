import json
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "day17" / "data"

SOURCES = {
    "registry": BASE_DIR / "day09/data/incidents.json",
    "investigation": BASE_DIR / "day15/data/incident_investigation.json",
    "verification": BASE_DIR / "day16/data/evidence_verification.json",
    "timeline": BASE_DIR / "day16/data/incident_timelines.json",
}


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def index_records(records):
    result = {}

    for record in records:
        incident_id = record.get("incident_id")

        if not incident_id:
            raise ValueError("Record without incident_id")

        if incident_id in result:
            raise ValueError(
                f"Duplicate incident ID: {incident_id}"
            )

        result[incident_id] = record

    return result


def build_soc_reports():
    registry = load_json(SOURCES["registry"])
    investigation = load_json(SOURCES["investigation"])
    verification = load_json(SOURCES["verification"])
    timeline = load_json(SOURCES["timeline"])

    if not isinstance(registry, list):
        raise ValueError("Invalid incident registry format")

    investigations = index_records(
        investigation["investigations"]
    )

    verifications = index_records(
        verification["incidents"]
    )

    timelines = index_records(
        timeline["incidents"]
    )

    registry_index = index_records(registry)

    registry_ids = set(registry_index)

    for name, records in [
        ("investigation", investigations),
        ("verification", verifications),
        ("timeline", timelines),
    ]:
        missing = registry_ids - set(records)
        extra = set(records) - registry_ids

        if missing or extra:
            raise ValueError(
                f"{name} mismatch: "
                f"missing={sorted(missing)}, "
                f"extra={sorted(extra)}"
            )

    reports = []

    for incident in registry:
        incident_id = incident["incident_id"]

        inv = investigations[incident_id]
        ver = verifications[incident_id]
        tl = timelines[incident_id]

        findings = list(dict.fromkeys(
            inv.get("findings", [])
            + ver.get("findings", [])
            + tl.get("findings", [])
        ))

        verification_status = ver.get(
            "verification_status", "UNKNOWN"
        )

        timeline_status = tl.get(
            "timeline_status", "UNKNOWN"
        )

        review_required = (
            inv.get("investigation_status")
            == "REVIEW_REQUIRED"
            or verification_status != "VERIFIED"
            or timeline_status != "RECONSTRUCTED"
        )

        report = {
            "incident_id": incident_id,
            "source": incident.get("source"),
            "incident_type": incident.get("type"),
            "severity": incident.get("severity"),
            "operational_status": incident.get("status"),
            "description": incident.get("description"),
            "created_at": incident.get("created_at"),
            "resolved_at": incident.get("resolved_at"),

            "investigation": {
                "priority": inv.get(
                    "investigation_priority"
                ),
                "status": inv.get(
                    "investigation_status"
                ),
                "evidence_status": inv.get(
                    "evidence_status"
                ),
            },

            "forensics": {
                "verification_status": verification_status,
                "evidence_count": ver.get(
                    "evidence_count", 0
                ),
                "verified_count": ver.get(
                    "verified_count", 0
                ),
                "evidence": ver.get("evidence", []),
                "timeline_status": timeline_status,
                "duration_seconds": tl.get(
                    "duration_seconds"
                ),
                "events": tl.get("events", []),
            },

            "analyst_findings": findings,
            "review_required": review_required,
            "report_type": "HISTORICAL_SNAPSHOT",
        }

        reports.append(report)

    return {
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "report_type": "SOC_INCIDENT_REPORTS",
        "source_snapshots": {
            "investigation": investigation.get(
                "generated_at_utc"
            ),
            "verification": verification.get(
                "generated_at_utc"
            ),
            "timeline": timeline.get(
                "generated_at_utc"
            ),
        },
        "summary": {
            "total_reports": len(reports),
            "review_required": sum(
                report["review_required"]
                for report in reports
            ),
            "verified_incidents": sum(
                report["forensics"]["verification_status"]
                == "VERIFIED"
                for report in reports
            ),
        },
        "reports": reports,
    }


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    result = build_soc_reports()

    output = OUTPUT_DIR / "soc_incident_reports.json"

    output.write_text(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8",
    )

    print("=== DAY 17 SOC REPORT GENERATOR ===")
    print("Total reports:",
          result["summary"]["total_reports"])
    print("Verified incidents:",
          result["summary"]["verified_incidents"])
    print("Review required:",
          result["summary"]["review_required"])
    print("Output:", output)


if __name__ == "__main__":
    main()
