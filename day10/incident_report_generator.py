
import json
from pathlib import Path
from datetime import datetime, timezone
from statistics import median
from hashlib import sha256

from incident_response_analyzer import analyze_incidents

BASE_DIR = Path(__file__).resolve().parent
REGISTRY = BASE_DIR.parent / "day09/data/incidents.json"
REPORT_FILE = BASE_DIR / "reports/incident_response_report.json"


def calculate_sha256(path):
    digest = sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def generate_report():
    analysis = analyze_incidents()

    durations = [
        incident["duration_seconds"]
        for incident in analysis["incidents"]
    ]

    longest = sorted(
        analysis["incidents"],
        key=lambda item: item["duration_seconds"],
        reverse=True
    )[:3]

    report = {
        "report_title": "Robot IDS Incident Response Report",
        "report_version": "1.0",
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "scope": "Educational Robot IDS Availability Monitoring",
        "source_evidence": {
            "file": str(REGISTRY),
            "sha256": calculate_sha256(REGISTRY)
        },
        "statistics": {
            "total_registry_incidents":
                analysis["total_registry_incidents"],
            "analyzed_incidents":
                analysis["analyzed_incidents"],
            "skipped_incidents":
                analysis["skipped_incidents"],
            "mttr_seconds":
                analysis["mttr_seconds"],
            "mttr_minutes":
                analysis["mttr_minutes"],
            "median_recovery_seconds":
                round(median(durations), 2) if durations else None,
            "maximum_recovery_seconds":
                max(durations) if durations else None,
            "minimum_recovery_seconds":
                min(durations) if durations else None
        },
        "longest_incidents": longest,
        "incidents": analysis["incidents"],
        "limitations": [
            "Events originate from a controlled educational environment.",
            "Recovery does not prove root cause remediation.",
            "Watchdog detection may lag actual service failure.",
            "Source event timestamps lack explicit timezone offsets."
        ]
    }

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with REPORT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    return report


if __name__ == "__main__":
    report = generate_report()
    stats = report["statistics"]

    print("=== ROBOT INCIDENT RESPONSE REPORT ===")
    print("Report generated: YES")
    print("Analyzed incidents:", stats["analyzed_incidents"])
    print("MTTR (minutes):", stats["mttr_minutes"])
    print("Median (seconds):", stats["median_recovery_seconds"])
    print("Maximum (seconds):", stats["maximum_recovery_seconds"])
    print("SHA256:", report["source_evidence"]["sha256"])
    print("Saved to:", REPORT_FILE)
