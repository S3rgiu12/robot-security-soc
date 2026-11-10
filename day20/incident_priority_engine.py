import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INCIDENTS_FILE = ROOT / "day09/data/incidents.json"

SEVERITY_SCORES = {
    "CRITICAL": 60,
    "HIGH": 40,
    "MEDIUM": 20,
    "LOW": 5
}


def calculate_priority(incident):
    severity = str(
        incident.get("severity") or ""
    ).upper()

    status = str(
        incident.get("status") or ""
    ).upper()

    incident_type = str(
        incident.get("type") or ""
    ).upper()

    score = SEVERITY_SCORES.get(severity, 0)
    reasons = []

    if severity in SEVERITY_SCORES:
        reasons.append(
            f"Severity {severity}: +{score}"
        )

    if status == "OPEN":
        score += 20
        reasons.append("Open incident: +20")

    if "TLS" in incident_type:
        score += 15
        reasons.append("TLS-related incident: +15")

    if "SERVICE_UNAVAILABLE" in incident_type:
        score += 10
        reasons.append("Service unavailable: +10")

    score = min(score, 100)

    if score >= 80:
        priority = "CRITICAL"
    elif score >= 60:
        priority = "HIGH"
    elif score >= 30:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return {
        "incident_id": incident.get("incident_id"),
        "severity": severity,
        "status": status,
        "type": incident_type,
        "risk_score": score,
        "priority": priority,
        "reasons": reasons
    }


def prioritize_incidents(
    incidents_file=INCIDENTS_FILE
):
    incidents = json.loads(
        Path(incidents_file).read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(incidents, list):
        raise ValueError(
            "Incident registry must be a list"
        )

    results = [
        calculate_priority(incident)
        for incident in incidents
    ]

    return sorted(
        results,
        key=lambda item: (
            -item["risk_score"],
            str(item["incident_id"])
        )
    )


if __name__ == "__main__":
    results = prioritize_incidents()

    print("=== DAY 20 INCIDENT PRIORITIZATION ===")
    print("Total incidents:", len(results))

    for item in results:
        print(
            item["incident_id"],
            "| Score:", item["risk_score"],
            "| Priority:", item["priority"],
            "| Type:", item["type"]
        )
