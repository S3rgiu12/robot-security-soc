import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

SOURCE_FILE = PROJECT_DIR / "day09/data/incidents.json"
REPORT_FILE = BASE_DIR / "data/incident_investigation.json"


def investigate_incident(incident):
    incident_id = incident.get("incident_id")
    status = incident.get("status", "UNKNOWN")
    evidence = incident.get("event_keys", [])

    if not isinstance(evidence, list):
        evidence = []

    findings = []

    if not evidence:
        evidence_status = "MISSING"
        findings.append("No linked event evidence.")
    elif len(evidence) == 1:
        evidence_status = "PARTIAL"
        findings.append("Only one linked event.")
    else:
        evidence_status = "AVAILABLE"

    if status == "OPEN":
        findings.append("Incident remains open.")

    if status == "RESOLVED" and not incident.get("resolved_at"):
        findings.append("Resolved incident lacks resolution timestamp.")

    if status == "OPEN" and not evidence:
        investigation_priority = "HIGH"
        investigation_status = "REVIEW_REQUIRED"
    elif findings:
        investigation_priority = "MEDIUM"
        investigation_status = "REVIEW_REQUIRED"
    else:
        investigation_priority = "LOW"
        investigation_status = "EVIDENCE_LINKED"

    return {
        "incident_id": incident_id,
        "source": incident.get("source"),
        "incident_type": incident.get("type"),
        "severity": incident.get("severity"),
        "operational_status": status,
        "created_at": incident.get("created_at"),
        "resolved_at": incident.get("resolved_at"),
        "evidence_status": evidence_status,
        "evidence_count": len(evidence),
        "investigation_priority": investigation_priority,
        "investigation_status": investigation_status,
        "findings": findings
    }


def build_report(incidents):
    investigations = [
        investigate_incident(item)
        for item in incidents
    ]

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": str(SOURCE_FILE.relative_to(PROJECT_DIR)),
        "summary": {
            "total": len(investigations),
            "by_evidence_status": dict(Counter(
                item["evidence_status"] for item in investigations
            )),
            "by_investigation_status": dict(Counter(
                item["investigation_status"] for item in investigations
            )),
            "by_priority": dict(Counter(
                item["investigation_priority"] for item in investigations
            ))
        },
        "investigations": investigations
    }


def main():
    if not SOURCE_FILE.exists():
        raise SystemExit(f"Source file missing: {SOURCE_FILE}")

    incidents = json.loads(SOURCE_FILE.read_text(encoding="utf-8"))

    if not isinstance(incidents, list):
        raise SystemExit("Expected a list of incidents.")

    report = build_report(incidents)

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("=== DAY 15 INCIDENT INVESTIGATOR ===")
    print("Total:", report["summary"]["total"])
    print("Evidence:", report["summary"]["by_evidence_status"])
    print("Investigation:", report["summary"]["by_investigation_status"])
    print("Priority:", report["summary"]["by_priority"])
    print("Report:", REPORT_FILE)

    for item in report["investigations"]:
        if item["investigation_status"] == "REVIEW_REQUIRED":
            print(
                f"[REVIEW] {item['incident_id']} | "
                f"{item['investigation_priority']} | "
                f"{', '.join(item['findings'])}"
            )


if __name__ == "__main__":
    main()
