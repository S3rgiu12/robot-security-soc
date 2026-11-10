import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from incident_priority_engine import calculate_priority


class TestIncidentPriorityEngine(unittest.TestCase):

    def test_critical_open_tls(self):
        incident = {
            "incident_id": "TEST-001",
            "severity": "CRITICAL",
            "status": "OPEN",
            "type": "TLS_ATTACK"
        }

        result = calculate_priority(incident)

        self.assertEqual(result["risk_score"], 95)
        self.assertEqual(result["priority"], "CRITICAL")

    def test_high_open_service_unavailable(self):
        incident = {
            "incident_id": "TEST-002",
            "severity": "HIGH",
            "status": "OPEN",
            "type": "SERVICE_UNAVAILABLE"
        }

        result = calculate_priority(incident)

        self.assertEqual(result["risk_score"], 70)
        self.assertEqual(result["priority"], "HIGH")

    def test_medium_open_service_unavailable(self):
        incident = {
            "incident_id": "TEST-003",
            "severity": "MEDIUM",
            "status": "OPEN",
            "type": "SERVICE_UNAVAILABLE"
        }

        result = calculate_priority(incident)

        self.assertEqual(result["risk_score"], 50)
        self.assertEqual(result["priority"], "MEDIUM")

    def test_low_resolved_incident(self):
        incident = {
            "incident_id": "TEST-004",
            "severity": "LOW",
            "status": "RESOLVED",
            "type": "INFORMATIONAL"
        }

        result = calculate_priority(incident)

        self.assertEqual(result["risk_score"], 5)
        self.assertEqual(result["priority"], "LOW")

    def test_score_is_capped_at_100(self):
        incident = {
            "incident_id": "TEST-005",
            "severity": "CRITICAL",
            "status": "OPEN",
            "type": "TLS_SERVICE_UNAVAILABLE"
        }

        result = calculate_priority(incident)

        self.assertEqual(result["risk_score"], 100)
        self.assertEqual(result["priority"], "CRITICAL")

    def test_unknown_severity(self):
        incident = {
            "incident_id": "TEST-006",
            "severity": "UNKNOWN",
            "status": "OPEN",
            "type": "UNKNOWN"
        }

        result = calculate_priority(incident)

        self.assertEqual(result["risk_score"], 20)
        self.assertEqual(result["priority"], "LOW")


if __name__ == "__main__":
    unittest.main()
