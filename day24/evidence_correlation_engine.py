import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

for folder in ("day21", "day22", "day24"):
    location = str(ROOT / folder)
    if location not in sys.path:
        sys.path.insert(0, location)

from threat_hunting_engine import analyze_log
from threat_alert_engine import generate_alerts


def correlate_evidence(log_path):
    path = Path(log_path).resolve()

    hunting = analyze_log(path)
    alert_result = generate_alerts(log_path=str(path))

    if alert_result.get("status") != "OK":
        raise ValueError("Threat alert generation failed")

    events = hunting["timeline"]
    alerts = alert_result["alerts"]

    event_index = {
        (event["line_number"], event["evidence"]): event
        for event in events
    }

    correlated = []
    unmatched = []

    for alert in alerts:
        key = (
            alert["line_number"],
            alert["evidence"]
        )

        event = event_index.get(key)

        if event is None:
            unmatched.append(alert["alert_id"])
            continue

        correlated.append({
            "alert_id": alert["alert_id"],
            "event_id": event["event_id"],
            "timestamp": event["timestamp"],
            "timestamp_available": event["timestamp_available"],
            "line_number": event["line_number"],
            "level": event["level"],
            "classification": event["classification"],
            "ioc_id": alert["ioc_id"],
            "ioc_type": alert["ioc_type"],
            "ioc_value": alert["ioc_value"],
            "severity": alert["severity"],
            "priority": alert["priority"],
            "confidence": alert["confidence"],
            "threat_type": alert["threat_type"],
            "evidence": event["evidence"],
            "source": str(path),
        })

    correlated.sort(
        key=lambda item: (
            item["timestamp"] is None,
            item["timestamp"] or "",
            item["line_number"],
            item["alert_id"]
        )
    )

    return {
        "status": "OK",
        "source": str(path),
        "total_events": len(events),
        "total_alerts": len(alerts),
        "correlated_alerts": len(correlated),
        "unmatched_alerts": unmatched,
        "timeline": correlated,
    }


if __name__ == "__main__":
    for name, path in (
        (
            "SYNTHETIC",
            ROOT / "day21/data/simulated_security_events.log"
        ),
        (
            "REAL_IDS",
            ROOT / "day05/logs/robot_security.log"
        ),
    ):
        result = correlate_evidence(path)

        print(f"\n=== {name} EVIDENCE CORRELATION ===")
        print("Events:", result["total_events"])
        print("Alerts:", result["total_alerts"])
        print(
            "Correlated alerts:",
            result["correlated_alerts"]
        )
        print(
            "Unmatched alerts:",
            len(result["unmatched_alerts"])
        )

        for item in result["timeline"]:
            print(
                item["timestamp"],
                item["severity"],
                item["alert_id"],
                item["ioc_value"]
            )
