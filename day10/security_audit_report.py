
import json
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SOURCE = BASE_DIR / "reports/incident_response_report.json"
OUTPUT = BASE_DIR / "reports/security_audit_report.json"


def generate_audit_report():
    with SOURCE.open(encoding="utf-8") as file:
        incident_report = json.load(file)

    stats = incident_report["statistics"]
    longest = incident_report["longest_incidents"]

    findings = []

    if stats["maximum_recovery_seconds"] is not None:
        if stats["maximum_recovery_seconds"] > 3600:
            findings.append({
                "id": "AUD-001",
                "title": "Extended IDS unavailability",
                "risk": "MEDIUM",
                "evidence": [
                    item["incident_id"] for item in longest
                ],
                "recommendation":
                    "Investigate prolonged service interruptions "
                    "and implement process supervision."
            })

    findings.extend([
        {
            "id": "AUD-002",
            "title": "Heartbeat monitoring dependency",
            "risk": "MEDIUM",
            "evidence": ["Heartbeat monitoring architecture"],
            "recommendation":
                "Add independent process health monitoring."
        },
        {
            "id": "AUD-003",
            "title": "Local evidence storage",
            "risk": "MEDIUM",
            "evidence": ["Local evidence collection directory"],
            "recommendation":
                "Implement restricted access, backups and "
                "tamper-evident evidence storage."
        },
        {
            "id": "AUD-004",
            "title": "Timestamp consistency",
            "risk": "LOW",
            "evidence": ["Incident registry timestamp formats"],
            "recommendation":
                "Standardize event timestamps to UTC ISO 8601."
        },
        {
            "id": "AUD-005",
            "title": "Demonstration incident in registry",
            "risk": "LOW",
            "evidence": ["INC-0001"],
            "recommendation":
                "Separate demonstration data from operational records."
        }
    ])

    report = {
        "title": "Robot Security Audit Report v1",
        "generated_at_utc":
            datetime.now(timezone.utc).isoformat(),
        "scope": "Educational Robot IDS Security Laboratory",
        "assessment_type": "Preliminary technical review",
        "summary": {
            "incidents_analyzed": stats["analyzed_incidents"],
            "mttr_minutes": stats["mttr_minutes"],
            "median_recovery_seconds":
                stats["median_recovery_seconds"],
            "total_findings": len(findings)
        },
        "findings": findings,
        "limitations": [
            "Findings are based on educational laboratory evidence.",
            "Risk ratings are preliminary and require validation.",
            "No production infrastructure was assessed."
        ]
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    return report


if __name__ == "__main__":
    report = generate_audit_report()

    print("=== ROBOT SECURITY AUDIT REPORT V1 ===")
    print("Incidents analyzed:",
          report["summary"]["incidents_analyzed"])
    print("MTTR (minutes):",
          report["summary"]["mttr_minutes"])
    print("Total findings:",
          report["summary"]["total_findings"])

    for finding in report["findings"]:
        print(
            f"[{finding['risk']}] "
            f"{finding['id']} - {finding['title']}"
        )

    print("Saved to:", OUTPUT)
