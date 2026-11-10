import sys
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "day22"))

from threat_alert_engine import (
    create_alert_id,
    enrich_match,
    enrich_matches,
    generate_alerts
)


SAMPLE_MATCH = {
    "line_number": 1,
    "ioc_id": "IOC-0001",
    "ioc_type": "ipv4",
    "ioc_value": "192.0.2.10",
    "severity": "HIGH",
    "confidence": 90,
    "threat_type": "SIMULATED_SUSPICIOUS_CONNECTION",
    "evidence": "Robot connection from 192.0.2.10"
}


class TestThreatAlertEngine(unittest.TestCase):

    def test_alert_creation(self):
        alert = enrich_match(SAMPLE_MATCH)

        self.assertEqual(alert["priority"], "HIGH")
        self.assertEqual(alert["confidence"], 90)
        self.assertEqual(
            alert["investigation_status"],
            "UNREVIEWED"
        )

    def test_stable_alert_id(self):
        first = create_alert_id(SAMPLE_MATCH)
        second = create_alert_id(SAMPLE_MATCH)

        self.assertEqual(first, second)
        self.assertTrue(first.startswith("ALT-"))

    def test_duplicate_matches(self):
        matches = [
            deepcopy(SAMPLE_MATCH),
            deepcopy(SAMPLE_MATCH)
        ]

        alerts = enrich_matches(matches)

        self.assertEqual(len(alerts), 1)

    def test_different_events_not_deduplicated(self):
        first = deepcopy(SAMPLE_MATCH)
        second = deepcopy(SAMPLE_MATCH)

        second["line_number"] = 2
        second["evidence"] = (
            "Second robot connection from 192.0.2.10"
        )

        alerts = enrich_matches([first, second])

        self.assertEqual(len(alerts), 2)

    def test_priority_order(self):
        high = deepcopy(SAMPLE_MATCH)

        critical = deepcopy(SAMPLE_MATCH)
        critical["ioc_id"] = "IOC-0002"
        critical["ioc_value"] = "robot-control-test.example"
        critical["severity"] = "CRITICAL"

        medium = deepcopy(SAMPLE_MATCH)
        medium["ioc_id"] = "IOC-0003"
        medium["ioc_value"] = "198.51.100.25"
        medium["severity"] = "MEDIUM"

        alerts = enrich_matches([
            medium,
            high,
            critical
        ])

        priorities = [
            alert["priority"]
            for alert in alerts
        ]

        self.assertEqual(
            priorities,
            ["CRITICAL", "HIGH", "MEDIUM"]
        )

    def test_invalid_severity(self):
        match = deepcopy(SAMPLE_MATCH)
        match["severity"] = "UNKNOWN"

        with self.assertRaises(ValueError):
            enrich_match(match)

    def test_invalid_confidence(self):
        match = deepcopy(SAMPLE_MATCH)
        match["confidence"] = 150

        with self.assertRaises(ValueError):
            enrich_match(match)

    def test_missing_evidence(self):
        match = deepcopy(SAMPLE_MATCH)
        match["evidence"] = ""

        with self.assertRaises(ValueError):
            enrich_match(match)

    def test_synthetic_log(self):
        log_path = (
            ROOT / "day21/data/simulated_security_events.log"
        )

        results = generate_alerts(log_path=log_path)

        self.assertEqual(results["total_events"], 4)
        self.assertEqual(results["total_ioc_matches"], 3)
        self.assertEqual(results["total_alerts"], 3)

        self.assertEqual(
            [alert["priority"] for alert in results["alerts"]],
            ["CRITICAL", "HIGH", "MEDIUM"]
        )


if __name__ == "__main__":
    unittest.main()
