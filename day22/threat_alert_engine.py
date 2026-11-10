import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DAY21_DIR = ROOT / "day21"

if str(DAY21_DIR) not in sys.path:
    sys.path.insert(0, str(DAY21_DIR))

from ioc_correlation_engine import correlate_log


VALID_SEVERITIES = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW"
}


def create_alert_id(match):
    """
    Generate a deterministic ID for one IOC match.
    """

    identity = {
        "ioc_id": match["ioc_id"],
        "ioc_value": match["ioc_value"],
        "line_number": match["line_number"],
        "evidence": match["evidence"]
    }

    encoded = json.dumps(
        identity,
        sort_keys=True
    ).encode("utf-8")

    digest = hashlib.sha256(encoded).hexdigest()[:16]

    return f"ALT-{digest.upper()}"


def enrich_match(match):
    """
    Convert an IOC match into a structured SOC alert.
    """

    severity = str(match["severity"]).upper()

    if severity not in VALID_SEVERITIES:
        raise ValueError("Unsupported IOC severity")

    confidence = match["confidence"]

    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0 <= confidence <= 100
    ):
        raise ValueError("Invalid IOC confidence")

    evidence = str(match["evidence"]).strip()

    if not evidence:
        raise ValueError("Missing alert evidence")

    priority = severity

    explanation = (
        f"IOC {match['ioc_id']} matched a security "
        f"log event. Severity: {severity}. "
        f"Confidence: {confidence}%."
    )

    return {
        "alert_id": create_alert_id(match),
        "ioc_id": match["ioc_id"],
        "ioc_type": match["ioc_type"],
        "ioc_value": match["ioc_value"],
        "severity": severity,
        "priority": priority,
        "confidence": confidence,
        "threat_type": match["threat_type"],
        "line_number": match["line_number"],
        "evidence": evidence,
        "explanation": explanation,
        "investigation_status": "UNREVIEWED",
        "source": "IOC_CORRELATION"
    }


def enrich_matches(matches):
    """
    Enrich and deduplicate IOC matches.
    """

    alerts = []
    seen_ids = set()

    for match in matches:
        alert = enrich_match(match)

        if alert["alert_id"] in seen_ids:
            continue

        seen_ids.add(alert["alert_id"])
        alerts.append(alert)

    priority_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3
    }

    alerts.sort(
        key=lambda alert: (
            priority_order[alert["priority"]],
            -alert["confidence"],
            alert["alert_id"]
        )
    )

    return alerts


def generate_alerts(log_path=None):
    """
    Run Day 21 correlation and enrich its matches.
    """

    if log_path is None:
        results = correlate_log()
    else:
        results = correlate_log(log_path=log_path)

    alerts = enrich_matches(results["matches"])

    return {
        "status": "OK",
        "total_events": results["total_lines"],
        "total_ioc_matches": results["total_matches"],
        "total_alerts": len(alerts),
        "alerts": alerts
    }


if __name__ == "__main__":

    test_log = (
        ROOT / "day21/data/simulated_security_events.log"
    )

    results = generate_alerts(log_path=test_log)

    print("=== DAY 22 THREAT ALERT ENRICHMENT ===")
    print("Events:", results["total_events"])
    print("IOC matches:", results["total_ioc_matches"])
    print("Generated alerts:", results["total_alerts"])

    for alert in results["alerts"]:
        print()
        print("Alert ID:", alert["alert_id"])
        print("Priority:", alert["priority"])
        print("IOC:", alert["ioc_value"])
        print("Confidence:", alert["confidence"])
        print("Status:", alert["investigation_status"])
        print("Explanation:", alert["explanation"])
